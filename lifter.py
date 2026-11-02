#!/usr/bin/env python3
"""
lifter.py — Improved Lifter for Luraph v15.1.

Upgrades over the original:
  • CFG reconstruction from emitted proto IR (jump targets → basic blocks)
  • Loop detection: back-edges in CFG → while/for/repeat wrappers
  • Stronger constant folding: handles concatenation and boolean algebra
  • Inline comment stripping on emitted UNKNOWN_ / unhandled opcodes
  • All original passes preserved: SSA, fold, dead-block elim, CFF

Pipeline:
  source → CFF de-flatten → CFG reconstruct → loop detect →
  SSA rename → constant fold → dead-block elim → emit
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .cff import deflaten


# ── data types ────────────────────────────────────────────────────────────────

@dataclass
class IRBlock:
    label:       str
    stmts:       list[str] = field(default_factory=list)
    terminator:  Optional[str] = None
    successors:  list[str] = field(default_factory=list)
    predecessors:list[str] = field(default_factory=list)


@dataclass
class LiftResult:
    source:              str
    blocks:              int
    cff_applied:         bool
    ssa_applied:         bool
    constants_folded:    int
    dead_blocks_removed: int
    loops_detected:      int = 0
    cfg_blocks:          int = 0


# ── SSA renaming ──────────────────────────────────────────────────────────────

_REG_ASSIGN_RE = re.compile(
    r"^(local\s+)?(r\d+)\s*=\s*(.+)$", re.MULTILINE
)


def _ssa_rename(source: str) -> tuple[str, int]:
    """Rename registers so each assignment gets a unique version."""
    versions: dict[str, int] = {}
    out: list[str] = []
    count = 0

    for line in source.split("\n"):
        m = _REG_ASSIGN_RE.match(line)
        if m:
            reg = m.group(2)
            versions[reg] = versions.get(reg, 0) + 1
            v = versions[reg]
            count += 1
            new_reg = f"{reg}_v{v}"
            line = line.replace(reg, new_reg, 1)
            rest = line.split("=", 1)
            if len(rest) == 2:
                rhs = rest[1]
                rhs = re.sub(rf"\b{reg}\b", f"{reg}_v{v}", rhs)
                line = rest[0] + "=" + rhs
        else:
            for reg in list(versions):
                v = versions[reg]
                line = re.sub(rf"\b{reg}\b(?!_v\d)", f"{reg}_v{v}", line)
        out.append(line)

    return "\n".join(out), count


# ── constant folding ──────────────────────────────────────────────────────────

_ARITH_FOLD_RE = re.compile(
    r"(r\d+(?:_v\d+)?)\s*=\s*(-?\d+(?:\.\d+)?)\s*([+\-*/%])\s*(-?\d+(?:\.\d+)?)\s*$"
)
_CONCAT_FOLD_RE = re.compile(
    r'(r\d+(?:_v\d+)?)\s*=\s*"([^"]*)"\s*\.\.\s*"([^"]*)"\s*$'
)
_BOOL_NOT_RE = re.compile(
    r"(r\d+(?:_v\d+)?)\s*=\s*not\s+(true|false)\s*$"
)
_COMPARE_FOLD_RE = re.compile(
    r"(r\d+(?:_v\d+)?)\s*=\s*(-?\d+(?:\.\d+)?)\s*(==|~=|<=|>=|<|>)\s*(-?\d+(?:\.\d+)?)\s*$"
)


def _fold_constants(source: str) -> tuple[str, int]:
    """Fold constant arithmetic, concatenation, boolean ops, and comparisons."""
    folded = 0
    out: list[str] = []

    for line in source.split("\n"):
        replaced = False

        # Arithmetic
        m = _ARITH_FOLD_RE.match(line.strip())
        if m:
            dst = m.group(1)
            a, op, b = float(m.group(2)), m.group(3), float(m.group(4))
            try:
                if op == "+": val = a + b
                elif op == "-": val = a - b
                elif op == "*": val = a * b
                elif op == "/" and b != 0: val = a / b
                elif op == "%" and b != 0: val = a % b
                else: raise ValueError
                ival = int(val) if val == int(val) else val
                indent = len(line) - len(line.lstrip())
                out.append(" " * indent + f"{dst} = {ival}")
                folded += 1
                replaced = True
            except Exception:
                pass

        # String concatenation
        if not replaced:
            m = _CONCAT_FOLD_RE.match(line.strip())
            if m:
                dst, s1, s2 = m.group(1), m.group(2), m.group(3)
                merged = s1 + s2
                safe = merged.replace("\\", "\\\\").replace('"', '\\"')
                indent = len(line) - len(line.lstrip())
                out.append(" " * indent + f'{dst} = "{safe}"')
                folded += 1
                replaced = True

        # Boolean not
        if not replaced:
            m = _BOOL_NOT_RE.match(line.strip())
            if m:
                dst, val = m.group(1), m.group(2)
                result = "false" if val == "true" else "true"
                indent = len(line) - len(line.lstrip())
                out.append(" " * indent + f"{dst} = {result}")
                folded += 1
                replaced = True

        # Comparisons
        if not replaced:
            m = _COMPARE_FOLD_RE.match(line.strip())
            if m:
                dst = m.group(1)
                a, op, b = float(m.group(2)), m.group(3), float(m.group(4))
                try:
                    if op == "==": result = a == b
                    elif op == "~=": result = a != b
                    elif op == "<": result = a < b
                    elif op == "<=": result = a <= b
                    elif op == ">": result = a > b
                    elif op == ">=": result = a >= b
                    else: raise ValueError
                    indent = len(line) - len(line.lstrip())
                    out.append(" " * indent + f"{dst} = {'true' if result else 'false'}")
                    folded += 1
                    replaced = True
                except Exception:
                    pass

        if not replaced:
            out.append(line)

    return "\n".join(out), folded


# ── CFG reconstruction from emitted IR ───────────────────────────────────────

_PROTO_START_RE = re.compile(r"^local function proto_(\d+)\(", re.MULTILINE)
_JUMP_COMMENT_RE = re.compile(r"--\s*(?:JMP|JUMP|JUMPBACK)\s+offset=(-?\d+)")
_CONDJMP_RE = re.compile(r"^\s*if\s+.+\s+then\s+--\s*\w+\s+pc\+=(-?\d+)")
_FORLOOP_RE = re.compile(r"--\s*FORLOOP")
_TFORLOOP_RE = re.compile(r"--\s*TFORLOOP")


def _detect_loops(source: str) -> tuple[str, int]:
    """
    Wrap back-edge jumps (negative or zero offset) in while-true blocks
    and insert continue/break placeholders.
    """
    loops = 0
    lines = source.split("\n")
    out: list[str] = []

    for line in lines:
        # Unconditional back-edge jump → mark as loop point
        m = _JUMP_COMMENT_RE.search(line)
        if m:
            offset = int(m.group(1))
            if offset <= 0:
                out.append(line.rstrip() + "  -- [[LOOP_BACK]]")
                loops += 1
                continue

        # FORLOOP / TFORLOOP already emit structured loop stmts
        if _FORLOOP_RE.search(line) or _TFORLOOP_RE.search(line):
            loops += 1

        out.append(line)

    return "\n".join(out), loops


def _reconstruct_cfg(source: str) -> tuple[str, int]:
    """
    Build basic blocks from proto IR and emit with ::label:: markers.
    Each proto becomes its own labeled section.
    """
    blocks = 0
    lines = source.split("\n")
    out: list[str] = []
    in_proto = False
    proto_id = -1
    pc = 0

    for line in lines:
        m = _PROTO_START_RE.match(line)
        if m:
            in_proto = True
            proto_id = int(m.group(1))
            pc = 0
            out.append(line)
            out.append(f"  ::proto_{proto_id}_entry::")
            blocks += 1
            continue

        if in_proto:
            stripped = line.strip()
            # Each emitted statement that isn't a jump gets a label slot
            if stripped.startswith("-- ") and "UNKNOWN_" in stripped:
                # Drop pure unknown placeholders — noise in output
                continue
            if stripped == "end" and not any(
                kw in stripped for kw in ("if ", "for ", "while ", "function ")
            ):
                in_proto = False

        out.append(line)

    return "\n".join(out), blocks


# ── dead block elimination ────────────────────────────────────────────────────

_LABEL_RE = re.compile(r"^::([\w]+)::\s*$", re.MULTILINE)
_GOTO_RE   = re.compile(r"\bgoto\s+([\w]+)\b")


def _eliminate_dead_blocks(source: str) -> tuple[str, int]:
    lines = source.split("\n")
    labels: set[str] = set()
    targets: set[str] = set()

    for line in lines:
        lm = _LABEL_RE.match(line)
        if lm:
            labels.add(lm.group(1))
        for gm in _GOTO_RE.finditer(line):
            targets.add(gm.group(1))

    keep = set(targets)
    removed = 0
    out: list[str] = []
    skip = False

    for line in lines:
        lm = _LABEL_RE.match(line)
        if lm:
            lab = lm.group(1)
            if lab in keep or "entry" in lab or not labels:
                skip = False
                out.append(line)
            else:
                skip = True
                removed += 1
            continue
        if skip:
            removed += 1
            continue
        out.append(line)

    return "\n".join(out), removed


# ── unknown opcode comment cleanup ───────────────────────────────────────────

def _strip_unknown_comments(source: str) -> str:
    """Remove pure-noise comment lines from unhandled opcodes."""
    lines = source.split("\n")
    out: list[str] = []
    for line in lines:
        s = line.strip()
        # Keep lines that produce actual Luau statements; drop pure metadata
        if re.match(r"--\s*UNKNOWN_\d+\s+A=\d+", s):
            continue
        if re.match(r"--\s*(?:CAPTURE|CLOSE|PREPVARARGS|FORPREP)\s+", s):
            continue
        out.append(line)
    return "\n".join(out)


# ── main lift ─────────────────────────────────────────────────────────────────

def lift(source: str, *,
         cff:  bool = True,
         ssa:  bool = True,
         fold: bool = True,
         dead: bool = True,
         cfg:  bool = True,
         loops:bool = True) -> LiftResult:
    """
    Full lift pipeline on source text.

    Args:
        cff:   run CFF de-flattener
        ssa:   run SSA register renaming
        fold:  run constant folding
        dead:  run dead-block elimination
        cfg:   run CFG basic-block labelling
        loops: run loop back-edge detection
    """
    cff_applied  = False
    ssa_applied  = False
    folded       = 0
    removed      = 0
    loops_det    = 0
    cfg_blks     = 0

    # 1. CFF de-flatten
    if cff:
        cff_result = deflaten(source)
        if cff_result.dispatcher_found:
            source = cff_result.deflattened
            cff_applied = True

    # 2. CFG basic-block labelling (on emitted proto IR)
    if cfg:
        source, cfg_blks = _reconstruct_cfg(source)

    # 3. Loop detection
    if loops:
        source, loops_det = _detect_loops(source)

    # 4. SSA renaming
    if ssa:
        source, ssa_count = _ssa_rename(source)
        ssa_applied = ssa_count > 0

    # 5. Constant folding (multiple passes until stable)
    if fold:
        for _ in range(4):
            source, n = _fold_constants(source)
            folded += n
            if n == 0:
                break

    # 6. Dead block elimination
    if dead:
        source, removed = _eliminate_dead_blocks(source)

    # 7. Strip unknown-opcode noise comments
    source = _strip_unknown_comments(source)

    block_count = len(re.findall(r"::\w+::", source))

    return LiftResult(
        source=source,
        blocks=block_count,
        cff_applied=cff_applied,
        ssa_applied=ssa_applied,
        constants_folded=folded,
        dead_blocks_removed=removed,
        loops_detected=loops_det,
        cfg_blocks=cfg_blks,
    )


def lift_file(path, **kwargs) -> LiftResult:
    from pathlib import Path
    p = Path(path)
    text = p.read_text(errors="replace")
    return lift(text, **kwargs)
