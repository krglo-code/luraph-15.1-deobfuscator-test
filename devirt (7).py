#!/usr/bin/env python3
"""
devirt.py — SuperFlow + VM Devirtualizer for Luraph v15.1.

Builds on the original SuperFlowDevirt (bsdata0 extraction, lazy constant
resolution) and adds:

  VMProtoWalker
    Extracts the VM's proto table from the obfuscated source, walks each
    proto's instruction stream using the classified opcode map, and emits
    a reconstructed Luau IR for each function proto.

  V151Devirt
    Combines SuperFlowDevirt + VMProtoWalker + symexec constant recovery
    into one object.  Called by driver.py as the v15.1 pipeline entry.

  Opcode reconstruction map
    Maps each canonical opcode name to an IR emitter function.  Each
    emitter produces one or more IRStmt / Node objects that the lifter's
    codegen pass turns into final Luau text.

Architecture
────────────
  Source
    ↓ vmmap.build_opcode_map()        → OpcodeMap  (id → canonical)
    ↓ _extract_proto_table()          → list[ProtoRaw]
    ↓ VMProtoWalker.walk_proto()       → list[IRNode]  (per proto)
    ↓ _emit_proto_luau()              → Luau text (per proto)
    ↓ symexec.recover_and_apply()     → constant substitution
    ↓ lifter.lift()                   → SSA + CFF + fold + dead-elim
    ↓ finish_text()                   → clean output
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import re
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any

# ── re-export original helpers unchanged ─────────────────────────────────────

_BSDATA_RE  = re.compile(r"_bsdata0\s*=\s*['\"]([^'\"]+)['\"]", re.DOTALL)
_ENCSTR2_RE = re.compile(r"LPH_ENCSTR2\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE)
_ENCFUNC2_RE= re.compile(r"LPH_ENCFUNC2\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE)


def extract_bsdata0(source: str) -> Optional[str]:
    m = _BSDATA_RE.search(source)
    return m.group(1) if m else None


def extract_bsdata0_from_file(path: Path) -> Optional[str]:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    return extract_bsdata0(text)


def _decode_bsdata0(blob: str) -> dict:
    result = {"raw": blob, "decoded": None, "tables": {}, "constants": []}
    try:
        raw = base64.b64decode(blob)
    except Exception:
        raw = blob.encode("utf-8", errors="replace")
    try:
        raw = gzip.decompress(raw)
    except Exception:
        pass
    try:
        raw = zlib.decompress(raw)
    except Exception:
        pass
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        result["decoded"] = data
        if isinstance(data, dict):
            result["tables"]    = data.get("tables", {})
            result["constants"] = data.get("constants", [])
    except Exception:
        result["decoded"]   = raw
        result["constants"] = [raw]
    return result


def seed_sandbox(bsdata0: str, sandbox_path: Path) -> Path:
    decoded = _decode_bsdata0(bsdata0)
    seed = {
        "_bsdata0":  bsdata0,
        "decoded":   decoded["decoded"],
        "tables":    decoded["tables"],
        "constants": decoded["constants"],
    }
    seed_path = sandbox_path.with_suffix(".bsdata.seed.json")
    seed_path.write_text(json.dumps(seed), encoding="utf-8")
    return seed_path


def finish_text(text: str) -> str:
    if text is None:
        return text
    text = re.sub(
        r"-- \[\[ SuperFlow seed injected by luraph_v15\.1 driver \]\]\n"
        r"_G\.__BSDATA0__\s*=\s*['\"][^'\"]+['\"]\n",
        "", text
    )
    return text


# ── SuperFlowDevirt (original, unchanged) ────────────────────────────────────

class SuperFlowDevirt:
    def __init__(self, source_path):
        self.source_path        = Path(source_path) if not isinstance(source_path, Path) else source_path
        self.bsdata0            = None
        self.decoded_constants  = {}
        self.operand_cache      = {}
        self.fetch_count        = 0
        self.miss_count         = 0

    def seed_from_source(self, source: str) -> Optional[str]:
        self.bsdata0 = extract_bsdata0(source)
        if self.bsdata0:
            decoded = _decode_bsdata0(self.bsdata0)
            self.decoded_constants = decoded
            print(f"[*] SuperFlowDevirt: seeded "
                  f"{len(self.decoded_constants.get('constants', []))} constants",
                  file=sys.stderr)
        return self.bsdata0

    def resolve_lazy(self, token: str) -> Optional[str]:
        if not self.decoded_constants:
            self.miss_count += 1
            return None
        for c in self.decoded_constants.get("constants", []):
            if isinstance(c, str) and c == token:
                return c
            if isinstance(c, dict) and c.get("token") == token:
                return c.get("value")
        self.miss_count += 1
        return None

    def operand_dedup(self, decoder_id: str, operand: str, value) -> bool:
        key = (decoder_id, operand)
        if key in self.operand_cache:
            return True
        self.operand_cache[key] = value
        return False

    def stats(self) -> dict:
        return {
            "bsdata0_seeded":       self.bsdata0 is not None,
            "decoded_constants":    len(self.decoded_constants.get("constants", [])),
            "operand_cache_entries":len(self.operand_cache),
            "fetch_count":          self.fetch_count,
            "miss_count":           self.miss_count,
        }


# ── VM proto extraction ───────────────────────────────────────────────────────

@dataclass
class ProtoRaw:
    """Raw extracted VM function prototype."""
    proto_id:    int
    source_text: str          # Luau source of this proto's handler
    upvalue_count: int = 0
    param_count:   int = 0
    is_vararg:     bool = False
    constants:     list[Any] = field(default_factory=list)
    nested_protos: list[int] = field(default_factory=list)


# Pattern: Luraph v15 stores protos as closures inside an array literal or
# as sequentially-defined local functions with a numeric key.
_PROTO_ARRAY_RE = re.compile(
    r"(?:local\s+)?([A-Za-z_]\w*)\s*=\s*\{(.*?)\}\s*$",
    re.DOTALL | re.MULTILINE,
)
_PROTO_FUNC_RE = re.compile(
    r"(?:local\s+function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)|"
    r"([A-Za-z_]\w*)\s*=\s*function\s*\(([^)]*)\))"
    r"(.*?)"
    r"\n\s*end(?:\s|$)",
    re.DOTALL,
)
_CONST_TABLE_RE = re.compile(
    r"local\s+([A-Za-z_]\w*)\s*=\s*\{([^}]{0,8000})\}",
    re.DOTALL,
)


def _extract_proto_table(source: str) -> list[ProtoRaw]:
    """
    Extract VM function protos from the obfuscated source.

    Luraph v15.1 stores protos in one of:
      1. A flat table of closures: {function() ... end, function() ... end, ...}
      2. Sequentially-indexed local functions in the VM body.

    We try both. The proto with the most sub-functions is the VM proto table.
    """
    protos: list[ProtoRaw] = []

    # Strategy 1: find the largest closure-array literal
    best_match = None
    best_count = 0
    for m in _PROTO_ARRAY_RE.finditer(source):
        body = m.group(2)
        count = body.count("function")
        if count > best_count:
            best_count = count
            best_match = m

    if best_match and best_count >= 4:
        body = best_match.group(2)
        # Split on top-level function...end boundaries
        depth = 0
        start = None
        func_bodies: list[str] = []
        i = 0
        tokens = re.split(r'(\bfunction\b|\bend\b)', body)
        cur: list[str] = []
        for tok in tokens:
            if tok == "function":
                if depth == 0:
                    cur = ["function"]
                else:
                    cur.append(tok)
                depth += 1
            elif tok == "end":
                depth -= 1
                cur.append(tok)
                if depth == 0 and cur:
                    func_bodies.append("".join(cur))
                    cur = []
            else:
                cur.append(tok)

        for idx, fb in enumerate(func_bodies):
            protos.append(ProtoRaw(
                proto_id=idx,
                source_text=fb,
            ))
        if protos:
            return protos

    # Strategy 2: collect all local function definitions in order
    for idx, m in enumerate(_PROTO_FUNC_RE.finditer(source)):
        name = m.group(1) or m.group(3) or f"proto_{idx}"
        params_raw = m.group(2) or m.group(4) or ""
        params = [p.strip() for p in params_raw.split(",") if p.strip()]
        body = m.group(5)
        protos.append(ProtoRaw(
            proto_id=idx,
            source_text=body,
            param_count=len(params),
            is_vararg="..." in params_raw,
        ))

    return protos


# ── VM instruction walker ─────────────────────────────────────────────────────

@dataclass
class VMInstr:
    """One decoded VM instruction."""
    pc:       int
    opcode:   int
    canonical: str           # from OpcodeMap, e.g. "MOVE"
    A:        int = 0
    B:        int = 0
    C:        int = 0
    D:        int = 0
    raw_line: str = ""


@dataclass
class VMFunc:
    """One lifted VM function (from one proto)."""
    proto_id: int
    instrs:   list[VMInstr] = field(default_factory=list)
    constants: list[Any]    = field(default_factory=list)
    upvalues:  list[str]    = field(default_factory=list)
    params:    int = 0
    is_vararg: bool = False


# Operand extraction: Luraph decodes A/B/C/D from instruction integers via
# bit ops.  We look for the characteristic patterns in each handler body.
_OP_FIELD_RE = re.compile(
    r"(?:local\s+)?([A-D])\s*=\s*((?:bit32\.[a-z]+\s*\([^)]+\)|[^;\n]+))",
    re.MULTILINE,
)
_NUM_LITERAL_RE = re.compile(r"\b(\d+)\b")


def _parse_operand_fields(handler_body: str) -> dict[str, int]:
    """Extract A/B/C/D operand values from a handler body's bit-op lines."""
    fields: dict[str, int] = {}
    for m in _OP_FIELD_RE.finditer(handler_body):
        field_name = m.group(1)
        expr = m.group(2)
        nums = _NUM_LITERAL_RE.findall(expr)
        if nums:
            try:
                fields[field_name] = int(nums[-1])
            except ValueError:
                pass
    return fields


def _instr_from_handler(pc: int, opcode_id: int, canonical: str,
                        handler_body: str) -> VMInstr:
    fields = _parse_operand_fields(handler_body)
    return VMInstr(
        pc=pc,
        opcode=opcode_id,
        canonical=canonical,
        A=fields.get("A", 0),
        B=fields.get("B", 0),
        C=fields.get("C", 0),
        D=fields.get("D", 0),
        raw_line=handler_body[:120].replace("\n", " "),
    )


# ── IR emission: opcode → Luau statement ─────────────────────────────────────

def _reg(n: int) -> str:
    return f"r{n}"


def _emit_instr(instr: VMInstr, constants: list[Any]) -> list[str]:
    """
    Emit Luau statement(s) for one VM instruction.
    Returns a list of source lines.
    """
    A, B, C, D = instr.A, instr.B, instr.C, instr.D
    op = instr.canonical

    def K(idx: int) -> str:
        if 0 <= idx < len(constants):
            v = constants[idx]
            if isinstance(v, str):
                safe = v.replace("\\", "\\\\").replace('"', '\\"')
                return f'"{safe}"'
            if v is None:
                return "nil"
            if isinstance(v, bool):
                return "true" if v else "false"
            return str(v)
        return f"K[{idx}]"

    # ── moves / loads ─────────────────────────────────────────────────────
    if op == "MOVE":
        return [f"local {_reg(A)} = {_reg(B)}"]
    if op == "LOADK":
        return [f"local {_reg(A)} = {K(B)}"]
    if op == "LOADN":
        return [f"local {_reg(A)} = {D}"]
    if op == "LOADBOOL":
        val = "true" if B else "false"
        return [f"local {_reg(A)} = {val}"]
    if op == "LOADNIL":
        return [f"{_reg(A)} = nil"] if A == B else \
               [f"for __i = {A}, {B} do r__i = nil end  -- LOADNIL range"]
    # ── upvalues ──────────────────────────────────────────────────────────
    if op == "GETUPVAL":
        return [f"local {_reg(A)} = upvals[{B}]"]
    if op == "SETUPVAL":
        return [f"upvals[{B}] = {_reg(A)}"]
    # ── globals ───────────────────────────────────────────────────────────
    if op == "GETGLOBAL":
        return [f"local {_reg(A)} = _ENV[{K(D)}]"]
    if op == "SETGLOBAL":
        return [f"_ENV[{K(D)}] = {_reg(A)}"]
    if op == "GETIMPORT":
        # multi-level import: K[D>>18], K[(D>>9)&0x1ff], K[D&0x1ff]
        k0 = K(D >> 18)
        k1 = K((D >> 9) & 0x1ff)
        k2 = K(D & 0x1ff)
        if C == 1:
            return [f"local {_reg(A)} = _ENV[{k0}]"]
        elif C == 2:
            return [f"local {_reg(A)} = _ENV[{k0}][{k1}]"]
        else:
            return [f"local {_reg(A)} = _ENV[{k0}][{k1}][{k2}]"]
    # ── table ops ─────────────────────────────────────────────────────────
    if op == "GETTABLE":
        return [f"local {_reg(A)} = {_reg(B)}[{_reg(C)}]"]
    if op == "SETTABLE":
        return [f"{_reg(A)}[{_reg(B)}] = {_reg(C)}"]
    if op == "GETFIELD":
        return [f"local {_reg(A)} = {_reg(B)}[{K(C)}]"]
    if op == "SETFIELD":
        return [f"{_reg(A)}[{K(B)}] = {_reg(C)}"]
    if op == "GETTABLEKS":
        return [f"local {_reg(A)} = {_reg(B)}[{K(C)}]"]
    if op == "SETTABLEKS":
        return [f"{_reg(A)}[{K(B)}] = {_reg(C)}"]
    if op == "NEWTABLE":
        return [f"local {_reg(A)} = {{}}"]
    if op == "SELF":
        return [
            f"local {_reg(A+1)} = {_reg(B)}",
            f"local {_reg(A)} = {_reg(B)}[{K(C)}]",
        ]
    if op == "NAMECALL":
        return [
            f"local {_reg(A+1)} = {_reg(B)}",
            f"local {_reg(A)} = {_reg(B)}[{K(C)}]",
        ]
    if op == "SETLIST":
        # tbl[start..start+C-1] = r[A+1..A+C]
        lines = []
        for i in range(C):
            lines.append(f"{_reg(A)}[{B + i}] = {_reg(A + 1 + i)}")
        return lines if lines else [f"-- SETLIST r{A}[{B}..] = ..."]
    # ── arithmetic ────────────────────────────────────────────────────────
    _ARITH_OPS = {
        "ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/",
        "MOD": "%", "POW": "^", "IDIV": "//",
    }
    if op in _ARITH_OPS:
        return [f"local {_reg(A)} = {_reg(B)} {_ARITH_OPS[op]} {_reg(C)}"]
    _BIT_OPS = {
        "BAND": "bit32.band", "BOR": "bit32.bor", "BXOR": "bit32.bxor",
        "SHL": "bit32.lshift", "SHR": "bit32.rshift",
    }
    if op in _BIT_OPS:
        return [f"local {_reg(A)} = {_BIT_OPS[op]}({_reg(B)}, {_reg(C)})"]
    if op == "BNOT":
        return [f"local {_reg(A)} = bit32.bnot({_reg(B)})"]
    if op == "UNM":
        return [f"local {_reg(A)} = -{_reg(B)}"]
    if op == "NOT":
        return [f"local {_reg(A)} = not {_reg(B)}"]
    if op == "LEN":
        return [f"local {_reg(A)} = #{_reg(B)}"]
    if op == "CONCAT":
        parts = " .. ".join(_reg(B + i) for i in range(C - B + 1))
        return [f"local {_reg(A)} = {parts}"]
    # ── comparisons / conditional jumps ──────────────────────────────────
    _CMP_OPS = {"EQ": "==", "LT": "<", "LE": "<=",
                "JUMPIFEQ": "==", "JUMPIFLT": "<", "JUMPIFLE": "<=",
                "JUMPIFNOTEQ": "~=", "JUMPIFNOTLT": ">=", "JUMPIFNOTLE": ">"}
    if op in _CMP_OPS:
        sense = "not " if (A == 0 and op in ("EQ", "LT", "LE")) else ""
        return [f"if {sense}({_reg(B)} {_CMP_OPS[op]} {_reg(C)}) then  -- {op} pc+={D}"]
    if op == "TEST":
        return [f"if {'not ' if C == 0 else ''}{_reg(A)} then  -- TEST"]
    if op == "TESTSET":
        return [f"if {'not ' if C == 0 else ''}{_reg(B)} then {_reg(A)} = {_reg(B)} end  -- TESTSET"]
    if op in ("JUMPIF", "JUMPIFNOT"):
        sense = "not " if op == "JUMPIFNOT" else ""
        return [f"if {sense}{_reg(A)} then  -- {op} pc+={D}"]
    # ── unconditional jumps ───────────────────────────────────────────────
    if op in ("JMP", "JUMP", "JUMPBACK"):
        return [f"-- {op} offset={D}"]
    # ── calls / returns ───────────────────────────────────────────────────
    if op == "CALL":
        args = ", ".join(_reg(A + 1 + i) for i in range(B - 1)) if B > 1 else "..."
        rets = ", ".join(_reg(A + i) for i in range(C - 1)) if C > 1 else "_"
        if C == 1:
            return [f"{_reg(A)}({args})"]
        return [f"local {rets} = {_reg(A)}({args})"]
    if op == "TAILCALL":
        args = ", ".join(_reg(A + 1 + i) for i in range(B - 1)) if B > 1 else "..."
        return [f"return {_reg(A)}({args})"]
    if op == "RETURN":
        if B == 1:
            return ["return"]
        if B == 2:
            return [f"return {_reg(A)}"]
        rets = ", ".join(_reg(A + i) for i in range(B - 1))
        return [f"return {rets}"]
    # ── for loops ─────────────────────────────────────────────────────────
    if op == "FORPREP":
        return [f"-- FORPREP r{A} (limit=r{A+1}, step=r{A+2}) pc+={D}"]
    if op == "FORLOOP":
        return [
            f"{_reg(A)} = {_reg(A)} + {_reg(A+2)}",
            f"if {_reg(A)} <= {_reg(A+1)} then {_reg(A+3)} = {_reg(A)} end  -- FORLOOP",
        ]
    if op == "TFORLOOP":
        rets = ", ".join(_reg(A + 3 + i) for i in range(C))
        return [f"local {rets} = {_reg(A)}({_reg(A+1)}, {_reg(A+2)})  -- TFORLOOP"]
    # ── closures ──────────────────────────────────────────────────────────
    if op in ("CLOSURE", "NEWCLOSURE", "DUPCLOSURE"):
        return [f"local {_reg(A)} = protos[{D}]  -- {op}"]
    if op == "CAPTURE":
        return [f"-- CAPTURE type={A} reg/up={B}"]
    if op == "CLOSE":
        return [f"-- CLOSE upvals through r{A}"]
    # ── vararg ────────────────────────────────────────────────────────────
    if op in ("VARARG", "GETVARARGS"):
        if B == 0:
            return [f"local {_reg(A)}, ... = ...  -- {op}"]
        rets = ", ".join(_reg(A + i) for i in range(B))
        return [f"local {rets} = ...  -- {op}"]
    if op == "PREPVARARGS":
        return [f"-- PREPVARARGS {A}"]
    # ── fastcalls (treat as call hints) ──────────────────────────────────
    if op.startswith("FASTCALL"):
        return [f"-- {op} A={A} B={B} C={C}"]
    # ── fallback ──────────────────────────────────────────────────────────
    return [f"-- {op} A={A} B={B} C={C} D={D}  (unhandled)"]


# ── Proto emitter ─────────────────────────────────────────────────────────────

def _emit_proto_luau(func: VMFunc, proto_id: int) -> str:
    """Emit a reconstructed Luau function from a VMFunc."""
    params = ", ".join(f"r{i}" for i in range(func.params))
    if func.is_vararg:
        params = (params + ", ..." if params else "...").strip(", ")

    lines: list[str] = [
        f"-- [[ proto {proto_id}: {len(func.instrs)} instrs, "
        f"{len(func.constants)} consts, {func.params} params ]]",
        f"local function proto_{proto_id}({params})",
    ]

    for instr in func.instrs:
        emitted = _emit_instr(instr, func.constants)
        for line in emitted:
            lines.append("  " + line)

    lines.append("end")
    lines.append("")
    return "\n".join(lines)


# ── Full VM Walker ────────────────────────────────────────────────────────────

class VMProtoWalker:
    """
    Walks every proto in the obfuscated VM, decodes instructions using the
    classified opcode map, and emits reconstructed Luau IR.
    """

    def __init__(self, opcode_map, constants: list[Any] = None):
        self.opcode_map = opcode_map
        self.global_constants: list[Any] = constants or []

    def walk_source(self, source: str) -> list[VMFunc]:
        """Extract and walk all protos in source. Returns list of VMFunc."""
        protos = _extract_proto_table(source)
        if not protos:
            return []
        funcs: list[VMFunc] = []
        for pr in protos:
            f = self._walk_proto(pr)
            funcs.append(f)
        return funcs

    def _walk_proto(self, proto: ProtoRaw) -> VMFunc:
        """Walk one proto and decode its instruction stream."""
        func = VMFunc(
            proto_id=proto.proto_id,
            constants=proto.constants or self.global_constants,
            params=proto.param_count,
            is_vararg=proto.is_vararg,
        )

        # Scan the handler body text for opcode dispatch branches.
        # Each branch is: if op == N then ... end
        branch_re = re.compile(
            r"(?:^|\n)[ \t]*(?:else)?if\s+\w+\s*==\s*(\d+)\s+then[ \t]*(?:\n|$)"
            r"(.*?)(?=\n[ \t]*(?:else)?if\s+\w+\s*==|\n[ \t]*end\s*(?:$|\n))",
            re.DOTALL | re.MULTILINE,
        )

        pc = 0
        for bm in branch_re.finditer(proto.source_text):
            try:
                opcode_id = int(bm.group(1))
            except ValueError:
                continue
            handler_body = bm.group(2)
            canonical = self.opcode_map.get(opcode_id)
            instr = _instr_from_handler(pc, opcode_id, canonical, handler_body)
            func.instrs.append(instr)
            pc += 1

        return func

    def emit_all(self, funcs: list[VMFunc]) -> str:
        """Emit all VMFuncs as a single Luau source string."""
        parts: list[str] = [
            "-- [[ Luraph v15.1 — VM devirtualized output ]]",
            "-- [[ Generated by LuraphDeobSuite opcode classifier ]]",
            "",
        ]
        for f in funcs:
            parts.append(_emit_proto_luau(f, f.proto_id))
        return "\n".join(parts)


# ── V151Devirt: full pipeline object ─────────────────────────────────────────

class V151Devirt:
    """
    Full v15.1 devirtualization pipeline.

    1. Extract _bsdata0 + classify opcode map.
    2. Run symexec constant recovery (multi-pass sandbox).
    3. Walk VM protos and emit reconstructed IR.
    4. Apply constant map to IR output.
    5. Hand off to lifter for SSA + CFF + fold + dead-elim.
    """

    def __init__(self, source: str, source_path: Optional[Path] = None,
                 *, luau_bin: Optional[str] = None,
                 sandbox_path: Optional[Path] = None,
                 verbose: bool = True):
        self.source = source
        self.source_path = source_path
        self.luau_bin = luau_bin
        self.sandbox_path = sandbox_path
        self.verbose = verbose

        self._sf = SuperFlowDevirt(source_path or Path("."))
        self._sf.seed_from_source(source)
        self._omap = None
        self._cmap = None

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"  [v151devirt] {msg}", file=sys.stderr)

    def build_opcode_map(self, use_cache: bool = True):
        """Run heuristic opcode classification on the source."""
        from .vmmap import OpcodeMap
        self._log("classifying opcodes...")
        if use_cache and self.source_path:
            cache_dir = Path(self.source_path).parent / ".luraph_cache"
            self._omap = OpcodeMap.from_cache_or_source(self.source, cache_dir)
        else:
            self._omap = OpcodeMap.from_source(self.source)

        rec = self._omap.classified
        tot = self._omap.total_handlers
        self._log(f"opcode map: {rec}/{tot} handlers classified "
                  f"({self._omap.coverage()*100:.1f}% coverage)")
        return self._omap

    def recover_constants(self, timeout: int = 60, extra_rounds: int = 2):
        """Run multi-pass symexec constant recovery."""
        if not self.luau_bin or not self.sandbox_path:
            self._log("no luau_bin/sandbox_path — skipping symexec")
            return None

        from .symexec import recover_and_apply
        self._log("running symexec constant recovery...")
        patched, cmap = recover_and_apply(
            self.source,
            self.luau_bin,
            self.sandbox_path,
            bsdata0=self._sf.bsdata0,
            timeout=timeout,
            extra_rounds=extra_rounds,
            verbose=self.verbose,
        )
        self._cmap = cmap
        rec, tot = cmap.coverage()
        self._log(f"constants: {rec}/{tot} recovered")
        # Update source with decrypted constants
        self.source = patched
        return cmap

    def devirtualize(self) -> str:
        """
        Walk VM protos, emit reconstructed Luau IR.
        Returns the emitted source string.
        """
        if self._omap is None:
            self.build_opcode_map()

        self._log("walking VM protos...")
        walker = VMProtoWalker(self._omap)
        funcs = walker.walk_source(self.source)

        if not funcs:
            self._log("no VM protos found — returning constant-substituted source")
            return self.source

        self._log(f"emitting {len(funcs)} reconstructed proto(s)...")
        emitted = walker.emit_all(funcs)

        # Apply constant map to emitted IR if we have one
        if self._cmap:
            emitted = self._cmap.apply(emitted)

        return emitted

    def full_pipeline(self, timeout: int = 60) -> str:
        """
        Run the complete pipeline: classify → recover constants → devirt.
        Returns the best available output.
        """
        self.build_opcode_map()
        self.recover_constants(timeout=timeout)
        return self.devirtualize()
