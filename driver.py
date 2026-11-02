#!/usr/bin/env python3
"""
driver.py — Luraph v15.1 / SuperFlow driver.

Full pipeline (in order):
  1.  Extract _bsdata0 SuperFlow seed from source.
  2.  Run heuristic opcode classifier → OpcodeMap.
  3.  Run multi-pass symexec constant recovery → ConstantMap.
  4.  Walk VM protos with classified opcodes → emitted IR.
  5.  Run CFF de-flatten + CFG + loop detection + SSA + fold + dead-elim.
  6.  Strip SuperFlow seed scaffolding via finish_text().

Falls back to v15 trace-only when the proto walker finds nothing
(script isn't a VM chunk, just a wrapped module).

Fixes from prior revisions retained:
  Bug 1 — devirtualize public alias.
  Bug 3 — finish_text() called before write.
  BUG-E  — saved original v15 devirt before patching; no infinite recursion.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]   # deobfuscator-luraph-v15.1/
CORE = ROOT / "core"
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from obfuscators.luraph_v15 import driver as v15_driver
from .cff    import deflaten
from .lifter import lift
from .devirt import SuperFlowDevirt, extract_bsdata0, seed_sandbox, finish_text, V151Devirt
from .vmmap  import build_opcode_map

_BSDATA_RE  = re.compile(r"_bsdata0\s*=\s*['\"]([^'\"]+)['\"]", re.DOTALL)
_ENCSTR2_RE = re.compile(r"LPH_ENCSTR2",  re.IGNORECASE)
_ENCFUNC2_RE= re.compile(r"LPH_ENCFUNC2", re.IGNORECASE)

_saved_v15_devirt = [None]


def detect_v151(source: str) -> bool:
    return bool(_ENCSTR2_RE.search(source) or _ENCFUNC2_RE.search(source)
                or _BSDATA_RE.search(source))


def _extract_bsdata0(source: str):
    m = _BSDATA_RE.search(source)
    return m.group(1) if m else None


def run(job) -> str:
    args   = job.args
    source = job.source

    # ── 1. Extract _bsdata0 ──────────────────────────────────────────────
    bsdata0 = _extract_bsdata0(source)
    if bsdata0 and not getattr(args, "bsdata", None):
        args.bsdata = bsdata0
        print(f"[*] auto-extracted _bsdata0 ({len(bsdata0)} chars)", file=sys.stderr)

    if not detect_v151(source):
        print("[*] no v15.1/SuperFlow markers — delegating to luraph_v15", file=sys.stderr)
        return v15_driver.run(job)

    print("[*] v15.1/SuperFlow detected", file=sys.stderr)

    # Inject seed so the sandbox runtime can decrypt constants
    if bsdata0:
        seed_code = (
            "\n-- [[ SuperFlow seed injected by luraph_v15.1 driver ]]\n"
            f"_G.__BSDATA0__ = '{bsdata0}'\n"
        )
        source     = seed_code + source
        job.source = source

    # ── 2+3+4. V151Devirt: classify opcodes + recover constants + walk protos
    # Find the luau binary and sandbox path from the harness
    luau_bin     = None
    sandbox_path = None
    try:
        import harness as _h
        luau_bin = _h.luau_bin()
    except Exception:
        pass
    try:
        sandbox_path = ROOT / "runtime" / "envlog.luau"
        if not sandbox_path.is_file():
            sandbox_path = None
    except Exception:
        pass

    timeout = getattr(args, "budget", 30) * getattr(args, "max_runs", 4)

    devirt = V151Devirt(
        source, source_path=getattr(job, "source_path", None),
        luau_bin=luau_bin,
        sandbox_path=sandbox_path,
        verbose=True,
    )

    emitted = devirt.full_pipeline(timeout=timeout)

    # ── 5. If emitted looks like reconstructed IR, lift it directly ──────
    out_path = job.path(".deobf.luau") if hasattr(job, "path") else str(
        Path(getattr(job, "input", "out.lua")).with_suffix(".deobf.luau")
    )

    if emitted and emitted != source:
        # Run through the full lifter on the emitted IR
        result = lift(
            emitted,
            cff=not getattr(args, "no_cff",  False),
            ssa=not getattr(args, "no_ssa",  False),
            fold=not getattr(args, "no_fold", False),
            dead=not getattr(args, "no_dead", False),
        )
        improved = finish_text(result.source)
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(improved, encoding="utf-8")
        print(
            f"[*] v151 lift: blocks={result.blocks} cff={result.cff_applied} "
            f"ssa={result.ssa_applied} folded={result.constants_folded} "
            f"dead={result.dead_blocks_removed} loops={result.loops_detected}",
            file=sys.stderr,
        )
        return out_path

    # ── Fallback: delegate to v15 trace engine ───────────────────────────
    print("[*] proto walk produced no IR — falling back to v15 trace", file=sys.stderr)

    try:
        from obfuscators.luraph_v15 import devirt as _v15d  # noqa
        sf = SuperFlowDevirt(getattr(job, "source_path", "."))
        cfg = getattr(args, "__dict__", {})
        cfg["sf_devirt"] = sf
        cfg["bsdata0"]   = getattr(args, "bsdata", None)
        _saved_v15_devirt[0] = v15_driver.devirtualize
        v15_driver.devirtualize = lambda *a, **kw: _devirtualize_v151(*a, **kw)
    except ImportError:
        pass

    out_path = v15_driver.run(job)

    if out_path and Path(out_path).is_file():
        lifted  = Path(out_path).read_text(errors="replace")
        result  = lift(
            lifted,
            cff=not getattr(args, "no_cff",  False),
            ssa=not getattr(args, "no_ssa",  False),
            fold=not getattr(args, "no_fold", False),
            dead=not getattr(args, "no_dead", False),
        )
        improved = finish_text(result.source)
        Path(out_path).write_text(improved, encoding="utf-8")
        print(f"[*] fallback lift: blocks={result.blocks}", file=sys.stderr)

    return out_path


def _devirtualize_v151(job, ppath, dpath, cfg, rerun, chunk_paths=(), live=None):
    sf = SuperFlowDevirt(getattr(job, "source_path", "."))
    cfg["sf_devirt"] = sf
    cfg["bsdata0"]   = getattr(getattr(job, "args", object()), "bsdata", None)
    impl = _saved_v15_devirt[0] or v15_driver.devirtualize
    impl(job, ppath, dpath, cfg, rerun, chunk_paths, live)


# Bug 1: public alias so __init__.py import resolves
devirtualize = _devirtualize_v151
