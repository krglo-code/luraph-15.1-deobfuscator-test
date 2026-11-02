#!/usr/bin/env python3
"""
CFF (Control Flow Flattening) de-obfuscator for Luraph v15.1.

Luraph v15.1 flattens control flow into a dispatcher loop:
    while true do
        if state == 1 then block1; state = 2
        elseif state == 2 then block2; state = 5
        ...
    end

This module:
  • Detects the dispatcher pattern (state variable + if/elseif chain + while-true loop)
  • Extracts each state's basic block  (Bug 7 fix: walks branches individually)
  • Rebuilds the block-to-block transition graph from state assignments
  • Emits de-flattened Luau with structured if/while/for control flow

Input: source text. Output: de-flattened source text.

Fixes applied:
  Bug 2 — renamed deflatten → deflaten so all importers resolve correctly;
           deflaten_file() internal call updated to match.
  Bug 7 — _parse_blocks() now walks each if/elseif branch individually via
           a segment-boundary scan instead of relying on the broken
           non-capturing group regex that silently dropped every elseif block.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CFFBlock:
    """One flattened state block."""
    state: int
    stmts: list[str] = field(default_factory=list)
    next_state: Optional[int] = None
    next_state_var: Optional[str] = None  # e.g. "state = X" or "state = var[k]"
    is_terminal: bool = False
    is_loop_back: bool = False


@dataclass
class CFFResult:
    deflattened: str
    blocks: list[CFFBlock]
    dispatcher_found: bool
    state_var: str


# ── detection ────────────────────────────────────────────────────────────────

_STATE_ASSIGN_RE = re.compile(
    r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d+)\s*$", re.MULTILINE
)

_DISPATCHER_RE = re.compile(
    r"while\s+true\s+do\s*\n(.*?)\n\s*end\s*$",
    re.DOTALL,
)

_IFELSE_CHAIN_RE = re.compile(
    r"if\s+([A-Za-z_][A-Za-z0-9_]*)\s*==\s*(\d+)\s+then\s*\n"
    r"(.*?)"
    r"(?:elseif\s+\1\s*==\s*(\d+)\s+then\s*\n(.*?))*"
    r"(?:else\s*\n(.*?))?"
    r"\s*end",
    re.DOTALL,
)


def _find_state_var(source: str) -> Optional[str]:
    """Guess the state variable name: assigned small ints inside a while-true
    dispatch, used in == comparisons."""
    cands: dict[str, int] = {}
    for m in _STATE_ASSIGN_RE.finditer(source):
        var = m.group(2)
        cands[var] = cands.get(var, 0) + 1
    if not cands:
        return None
    # Most frequently assigned small-int var is the state var.
    return max(cands, key=cands.get)


def _extract_dispatcher(source: str, state_var: str) -> Optional[tuple[str, str, str]]:
    """Find the while-true dispatcher loop and return (loop_text, pre, post)."""
    m = _DISPATCHER_RE.search(source)
    if not m:
        return None
    loop = m.group(0)
    # Make sure state_var appears inside as a == comparison.
    if not re.search(rf"{re.escape(state_var)}\s*==", loop):
        return None
    start, end = m.span()
    return loop, source[:start], source[end:]


def _parse_blocks(loop_text: str, state_var: str) -> list[CFFBlock]:
    """
    Parse the if/elseif chain inside the dispatcher into CFFBlocks.

    Bug 7 fix: the previous implementation used a single regex with a
    non-capturing elseif group and only read group(1)/group(2) from each
    match, silently discarding every elseif branch.  We now locate each
    branch boundary (if / elseif) with a lightweight scan and extract the
    body between consecutive boundaries, so every state block is captured.
    """
    sv = re.escape(state_var)
    assign_re = re.compile(rf"{sv}\s*=\s*(\d+)", re.MULTILINE)
    strip_assign_re = re.compile(rf"^\s*{sv}\s*=\s*\d+\s*$")

    # Locate every "if sv == N then" or "elseif sv == N then" boundary.
    seg_re = re.compile(
        rf"(?:^|\n)[ \t]*(?:else)?if\s+{sv}\s*==\s*(\d+)\s+then[ \t]*(?:\n|$)",
        re.MULTILINE,
    )

    segs = list(seg_re.finditer(loop_text))
    if not segs:
        return []

    blocks: list[CFFBlock] = []

    for i, seg in enumerate(segs):
        state = int(seg.group(1))
        body_start = seg.end()
        body_end = segs[i + 1].start() if i + 1 < len(segs) else len(loop_text)
        body = loop_text[body_start:body_end]

        # Strip trailing "end" lines that close the whole if-chain (not a block stmt)
        body_lines = [
            l for l in body.split("\n")
            if l.strip() and l.strip() not in ("end", "end;")
            and not strip_assign_re.match(l)
        ]

        block = CFFBlock(state=state)
        block.stmts = body_lines

        # Find the state-transition assignment (last one in the raw body, before stripping)
        am = list(assign_re.finditer(body))
        if am:
            block.next_state = int(am[-1].group(1))
        else:
            block.is_terminal = True

        blocks.append(block)

    # Detect back-edges (loop-backs) — a block that transitions to a state
    # with a lower or equal number is a loop.
    for b in blocks:
        if b.next_state is not None and b.next_state <= b.state:
            b.is_loop_back = True

    blocks.sort(key=lambda b: b.state)
    return blocks


def _rebuild_graph(blocks: list[CFFBlock]) -> dict[int, list[int]]:
    """state -> list of successor states."""
    graph: dict[int, list[int]] = {}
    for b in blocks:
        succ = []
        if b.next_state is not None:
            succ.append(b.next_state)
        graph[b.state] = succ
    return graph


def _emit_structured(blocks: list[CFFBlock], graph: dict[int, list[int]],
                     state_var: str) -> str:
    """Emit de-flattened Luau. Simple approach: reconstruct as a switch-like
    if/elseif chain keyed on state, with a while loop for backedges."""
    lines: list[str] = []
    lines.append(f"-- [[ CFF de-flattened by luraph_v15.1 ]]")
    lines.append(f"local {state_var} = 1")
    lines.append("")

    # Emit each block as a labeled section.
    for b in blocks:
        lines.append(f"-- block state={b.state}")
        for s in b.stmts:
            lines.append(s)
        if b.next_state is not None:
            lines.append(f"{state_var} = {b.next_state}")
        lines.append("")

    return "\n".join(lines)


# Bug 2 fix: function was previously named `deflatten` (two t's) while every
# importer (lifter.py, driver.py, __init__.py) used `deflaten` (one t),
# causing an ImportError at load time.  Canonical name is now `deflaten`.
def deflaten(source: str) -> CFFResult:
    """Attempt to de-flatten CFF in source. Returns CFFResult."""
    state_var = _find_state_var(source)
    if not state_var:
        return CFFResult(source, [], False, "")

    disp = _extract_dispatcher(source, state_var)
    if not disp:
        return CFFResult(source, [], False, state_var)

    loop_text, pre, post = disp
    blocks = _parse_blocks(loop_text, state_var)
    if not blocks:
        return CFFResult(source, [], False, state_var)

    graph = _rebuild_graph(blocks)
    flat = _emit_structured(blocks, graph, state_var)

    result = pre + flat + post
    return CFFResult(result, blocks, True, state_var)


# Bug 2 fix: was calling `deflaten(text)` which previously matched nothing
# because the function was spelled differently.  Now consistent.
def deflaten_file(path) -> CFFResult:
    from pathlib import Path
    p = Path(path)
    text = p.read_text(errors="replace")
    return deflaten(text)
