# lang: Python 3.10+
# file: core/opcode_recover.py
# runtime: standalone — no external deps beyond stdlib + re
#
# Usage:
#   from core.opcode_recover import OpcodeTable, recover_opcodes
#
#   tbl = recover_opcodes(source_text)   # str of obfuscated .lua/.luau
#   print(tbl.summary())                 # handler_N -> OP_NAME confidence%
#   print(tbl.to_json())
#   tbl.assert_coverage(min_pct=70)      # raises if < 70% mapped
#
# Plugs into deob.py engine_luraph_v151() by passing tbl into _Args so
# the harness can feed it to the lifter's constant walker.
#
# Signature format — each OpSig:
#   patterns   list[re.Pattern]  all must hit somewhere in the handler body
#   anti       list[re.Pattern]  any hit -> reject (disambiguates near-twins)
#   score      int               confidence weight (additive when multiple sigs match)
#   canonical  str               Luau opcode name from luaP_opnames[]
#
# Handler body extraction:
#   The VM loop in v15.1 is a while-true dispatch on a shuffled integer
#   array.  Each handler is an if/elseif branch.  We extract the raw Lua
#   source of each branch, strip the leading "if op == N then" guard, and
#   run the signature battery against the stripped body.

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Luau opcode names (luaP_opnames order, 0-indexed) ───────────────────────
# Source: luau/VM/src/lopnames.h  — the canonical 83-entry list for Luau 0.6+
LUAU_OPCODES: list[str] = [
    "OP_NOP",           # 0
    "OP_BREAK",         # 1
    "OP_LOADNIL",       # 2
    "OP_LOADB",         # 3
    "OP_LOADN",         # 4
    "OP_LOADK",         # 5
    "OP_MOVE",          # 6
    "OP_GETGLOBAL",     # 7
    "OP_SETGLOBAL",     # 8
    "OP_GETUPVAL",      # 9
    "OP_SETUPVAL",      # 10
    "OP_CLOSEUPVALS",   # 11
    "OP_GETIMPORT",     # 12
    "OP_GETTABLE",      # 13
    "OP_SETTABLE",      # 14
    "OP_GETTABLEKS",    # 15
    "OP_SETTABLEKS",    # 16
    "OP_GETTABLEN",     # 17
    "OP_SETTABLEN",     # 18
    "OP_NEWCLOSURE",    # 19
    "OP_NAMECALL",      # 20
    "OP_CALL",          # 21
    "OP_RETURN",        # 22
    "OP_JUMP",          # 23
    "OP_JUMPBACK",      # 24
    "OP_JUMPIF",        # 25
    "OP_JUMPIFNOT",     # 26
    "OP_JUMPIFEQ",      # 27
    "OP_JUMPIFLE",      # 28
    "OP_JUMPIFLT",      # 29
    "OP_JUMPIFNOTEQ",   # 30
    "OP_JUMPIFNOTLE",   # 31
    "OP_JUMPIFNOTLT",   # 32
    "OP_ADD",           # 33
    "OP_SUB",           # 34
    "OP_MUL",           # 35
    "OP_DIV",           # 36
    "OP_MOD",           # 37
    "OP_POW",           # 38
    "OP_ADDK",          # 39
    "OP_SUBK",          # 40
    "OP_MULK",          # 41
    "OP_DIVK",          # 42
    "OP_MODK",          # 43
    "OP_POWK",          # 44
    "OP_AND",           # 45
    "OP_OR",            # 46
    "OP_ANDK",          # 47
    "OP_ORK",           # 48
    "OP_CONCAT",        # 49
    "OP_NOT",           # 50
    "OP_MINUS",         # 51
    "OP_LENGTH",        # 52
    "OP_NEWTABLE",      # 53
    "OP_DUPTABLE",      # 54
    "OP_SETLIST",       # 55
    "OP_FORNPREP",      # 56
    "OP_FORNLOOP",      # 57
    "OP_FORGLOOP",      # 58
    "OP_FORGPREP_INEXT",# 59
    "OP_DEP_FORGLOOP_INEXT", # 60
    "OP_FORGPREP_NEXT", # 61
    "OP_DEP_FORGLOOP_NEXT",  # 62
    "OP_GETVARARGS",    # 63
    "OP_DUPCLOSURE",    # 64
    "OP_PREPVARARGS",   # 65
    "OP_LOADKX",        # 66
    "OP_JUMPX",         # 67
    "OP_FASTCALL",      # 68
    "OP_COVERAGE",      # 69
    "OP_CAPTURE",       # 70
    "OP_SUBRK",         # 71
    "OP_DIVRK",         # 72
    "OP_FASTCALL1",     # 73
    "OP_FASTCALL2",     # 74
    "OP_FASTCALL2K",    # 75
    "OP_FORGPREP",      # 76
    "OP_JUMPXEQKNIL",   # 77
    "OP_JUMPXEQKB",     # 78
    "OP_JUMPXEQKN",     # 79
    "OP_JUMPXEQKS",     # 80
    "OP_IDIV",          # 81
    "OP_IDIVK",         # 82
]


# ── Signature dataclass ──────────────────────────────────────────────────────

@dataclass
class OpSig:
    canonical: str
    patterns:  list[re.Pattern]
    anti:      list[re.Pattern] = field(default_factory=list)
    score:     int = 10


def _p(s: str) -> re.Pattern:
    return re.compile(s, re.IGNORECASE)


# ── Signature library ────────────────────────────────────────────────────────
SIGNATURES: list[OpSig] = [

    OpSig("OP_NOP",
        patterns=[_p(r"(?:^|\s)(?:--\s*nop|do\s+end)(?:\s|$)")],
        score=5,
    ),

    OpSig("OP_BREAK",
        patterns=[_p(r"LPH_CRASH\s*\(|error\s*\(\s*[\"']break[\"']\s*\)")],
        score=12,
    ),

    OpSig("OP_LOADNIL",
        patterns=[_p(r"\w+\s*\[\s*\w+\s*\]\s*=\s*nil")],
        anti=[_p(r"(?:\w+\s*\[\s*\w+\s*\]\s*=\s*nil.*){2}")],
        score=8,
    ),

    OpSig("OP_LOADB",
        patterns=[
            _p(r"\w+\s*\[\s*\w+\s*\]\s*=\s*\(?(?:true|false|\w+\s*~=\s*0|\w+\s*==\s*\w+)\)?"),
            _p(r"pc\s*=\s*pc\s*[+\-]\s*1"),
        ],
        score=14,
    ),

    OpSig("OP_LOADN",
        patterns=[_p(r"\w+\s*\[\s*\w+\s*\]\s*=\s*-?\s*\w+")],
        anti=[_p(r"\w+\s*\[\s*\w+\s*\]\s*\["), _p(r"kst\s*\[")],
        score=6,
    ),

    OpSig("OP_LOADK",
        patterns=[_p(r"\w+\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]")],
        anti=[_p(r"\w+\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\]")],
        score=7,
    ),

    OpSig("OP_MOVE",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]")],
        score=12,
    ),

    OpSig("OP_GETGLOBAL",
        patterns=[_p(r"\w+\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\[\s*\w+\s*\]\s*\]")],
        score=11,
    ),

    OpSig("OP_SETGLOBAL",
        patterns=[_p(r"\w+\s*\[\s*\w+\s*\[\s*\w+\s*\]\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]")],
        score=11,
    ),

    OpSig("OP_GETUPVAL",
        patterns=[_p(r"\w+\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]\s*\[\s*1\s*\]")],
        score=13,
    ),

    OpSig("OP_SETUPVAL",
        patterns=[_p(r"\w+\s*\[\s*\w+\s*\]\s*\[\s*1\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]")],
        score=13,
    ),

    OpSig("OP_CLOSEUPVALS",
        patterns=[
            _p(r"for\s+\w+\s*=\s*\w+\s*,\s*\w+\s+do"),
            _p(r"\[\s*1\s*\]\s*="),
        ],
        score=12,
    ),

    OpSig("OP_GETIMPORT",
        patterns=[
            _p(r"if\s+\w+\s*\[\s*\w+\s*\]\s*==\s*nil\s+then"),
            _p(r"\w+\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\[\s*\w+\s*\]\s*\]"),
        ],
        score=15,
    ),

    OpSig("OP_GETTABLE",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\[\s*\1\s*\[\s*\w+\s*\]\s*\]")],
        score=14,
    ),

    OpSig("OP_SETTABLE",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*\[\s*\1\s*\[\s*\w+\s*\]\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]")],
        score=14,
    ),

    OpSig("OP_GETTABLEKS",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\[\s*(?:kst|\w+)\s*\[\s*\w+\s*\]\s*\]")],
        anti=[_p(r"\w+\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\[")],
        score=13,
    ),

    OpSig("OP_SETTABLEKS",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*\[\s*(?:kst|\w+)\s*\[\s*\w+\s*\]\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]")],
        score=13,
    ),

    OpSig("OP_GETTABLEN",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\+\s*1\s*\]")],
        score=13,
    ),

    OpSig("OP_SETTABLEN",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\+\s*1\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]")],
        score=13,
    ),

    OpSig("OP_NEWCLOSURE",
        patterns=[_p(r"setmetatable\s*\("), _p(r"upv\s*\[\s*|upvalue")],
        score=10,
    ),

    OpSig("OP_DUPCLOSURE",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]")],
        anti=[_p(r"setmetatable\s*\("), _p(r"upv\s*\[")],
        score=8,
    ),

    OpSig("OP_NAMECALL",
        patterns=[
            _p(r"(\w+)\s*\[\s*\w+\s*\+\s*1\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]"),
            _p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\["),
        ],
        score=15,
    ),

    OpSig("OP_CALL",
        patterns=[
            _p(r"(\w+)\s*\[\s*\w+\s*\]\s*\("),
            _p(r"top\s*=|top\b.*="),
        ],
        anti=[_p(r"return\b")],
        score=12,
    ),

    OpSig("OP_RETURN",
        patterns=[_p(r"\breturn\b"), _p(r"\bbreak\b|\bgoto\s+\w+")],
        score=10,
    ),

    OpSig("OP_JUMP",
        patterns=[_p(r"pc\s*=\s*pc\s*\+\s*\w+")],
        anti=[_p(r"pc\s*=\s*pc\s*-"), _p(r"if\b")],
        score=11,
    ),

    OpSig("OP_JUMPBACK",
        patterns=[_p(r"pc\s*=\s*pc\s*-\s*\w+")],
        anti=[_p(r"if\b")],
        score=11,
    ),

    OpSig("OP_JUMPIF",
        patterns=[_p(r"if\s+\w+\s*\[\s*\w+\s*\]\s+then\s+pc\s*=")],
        anti=[_p(r"not\b"), _p(r"==|~=|<=|>=|<(?!=)|>(?!=)")],
        score=12,
    ),

    OpSig("OP_JUMPIFNOT",
        patterns=[_p(r"if\s+not\s+\w+\s*\[\s*\w+\s*\]\s+then\s+pc\s*=")],
        score=12,
    ),

    OpSig("OP_JUMPIFEQ",
        patterns=[_p(r"if\s+\w+\s*\[\s*\w+\s*\]\s*==\s*\w+\s*\[\s*\w+\s*\]\s+then\s+pc\s*=")],
        score=14,
    ),

    OpSig("OP_JUMPIFNOTEQ",
        patterns=[_p(r"if\s+\w+\s*\[\s*\w+\s*\]\s*~=\s*\w+\s*\[\s*\w+\s*\]\s+then\s+pc\s*=")],
        score=14,
    ),

    OpSig("OP_JUMPIFLE",
        patterns=[_p(r"if\s+\w+\s*\[\s*\w+\s*\]\s*<=\s*\w+\s*\[\s*\w+\s*\]\s+then\s+pc\s*=")],
        score=14,
    ),

    OpSig("OP_JUMPIFNOTLE",
        patterns=[_p(r"if\s+not\s*\(?.*<=.*\)?\s+then\s+pc\s*=|if\s+\w+\[.*\]\s*>\s*\w+\[.*\]\s+then\s+pc\s*=")],
        score=13,
    ),

    OpSig("OP_JUMPIFLT",
        patterns=[_p(r"if\s+\w+\s*\[\s*\w+\s*\]\s*<\s*\w+\s*\[\s*\w+\s*\]\s+then\s+pc\s*=")],
        anti=[_p(r"<=")],
        score=14,
    ),

    OpSig("OP_JUMPIFNOTLT",
        patterns=[_p(r"if\s+not\s*\(?.*<.*\)?\s+then\s+pc\s*=|if\s+\w+\[.*\]\s*>=\s*\w+\[.*\]\s+then\s+pc\s*=")],
        score=13,
    ),

    OpSig("OP_ADD",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\+\s*\1\s*\[\s*\w+\s*\]")],
        score=12,
    ),
    OpSig("OP_SUB",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*-\s*\1\s*\[\s*\w+\s*\]")],
        score=12,
    ),
    OpSig("OP_MUL",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\*\s*\1\s*\[\s*\w+\s*\]")],
        score=12,
    ),
    OpSig("OP_DIV",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*/\s*\1\s*\[\s*\w+\s*\]")],
        score=12,
    ),
    OpSig("OP_MOD",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*%\s*\1\s*\[\s*\w+\s*\]")],
        score=12,
    ),
    OpSig("OP_POW",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\^\s*\1\s*\[\s*\w+\s*\]")],
        score=12,
    ),
    OpSig("OP_IDIV",
        patterns=[_p(r"math\.floor\s*\(\s*(\w+)\s*\[\s*\w+\s*\]\s*/\s*\1\s*\[\s*\w+\s*\]\s*\)")],
        score=14,
    ),

    OpSig("OP_ADDK",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\+\s*\w+\s*\[\s*\w+\s*\]")],
        anti=[_p(r"\+\s*\w+\[\w+\]\s*\+")],
        score=11,
    ),
    OpSig("OP_SUBK",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*-\s*\w+\s*\[\s*\w+\s*\]")],
        score=11,
    ),
    OpSig("OP_MULK",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\*\s*\w+\s*\[\s*\w+\s*\]")],
        score=11,
    ),
    OpSig("OP_DIVK",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*/\s*\w+\s*\[\s*\w+\s*\]")],
        score=11,
    ),
    OpSig("OP_MODK",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*%\s*\w+\s*\[\s*\w+\s*\]")],
        score=11,
    ),
    OpSig("OP_POWK",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\^\s*\w+\s*\[\s*\w+\s*\]")],
        score=11,
    ),
    OpSig("OP_IDIVK",
        patterns=[_p(r"math\.floor\s*\(\s*(\w+)\s*\[\s*\w+\s*\]\s*/\s*\w+\s*\[\s*\w+\s*\]\s*\)")],
        score=13,
    ),

    OpSig("OP_SUBRK",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]\s*-\s*\1\s*\[\s*\w+\s*\]")],
        score=14,
    ),
    OpSig("OP_DIVRK",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]\s*/\s*\1\s*\[\s*\w+\s*\]")],
        score=14,
    ),

    OpSig("OP_AND",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s+and\s+\1\s*\[\s*\w+\s*\]")],
        score=13,
    ),
    OpSig("OP_OR",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s+or\s+\1\s*\[\s*\w+\s*\]")],
        score=13,
    ),
    OpSig("OP_ANDK",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s+and\s+\w+\s*\[\s*\w+\s*\]")],
        score=12,
    ),
    OpSig("OP_ORK",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s+or\s+\w+\s*\[\s*\w+\s*\]")],
        score=12,
    ),

    OpSig("OP_CONCAT",
        patterns=[_p(r"table\.concat\s*\(|\.\.\s*\w+\s*\[")],
        score=12,
    ),

    OpSig("OP_NOT",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*not\s+\1\s*\[\s*\w+\s*\]")],
        score=13,
    ),

    OpSig("OP_MINUS",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*-\s*\1\s*\[\s*\w+\s*\]")],
        score=13,
    ),

    OpSig("OP_LENGTH",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*#\s*\1\s*\[\s*\w+\s*\]")],
        score=14,
    ),

    OpSig("OP_NEWTABLE",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\{")],
        anti=[_p(r"setmetatable\s*\(")],
        score=11,
    ),

    OpSig("OP_DUPTABLE",
        patterns=[
            _p(r"for\s+\w+\s*,\s*\w+\s+in\s+pairs\s*\("),
            _p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\{"),
        ],
        score=13,
    ),

    OpSig("OP_SETLIST",
        patterns=[_p(r"table\.move\s*\(")],
        score=14,
    ),

    OpSig("OP_FORNPREP",
        patterns=[
            _p(r"\w+\s*\[\s*\w+\s*\+\s*2\s*\]"),
            _p(r"type\s*\(|tonumber\s*\("),
        ],
        score=12,
    ),

    OpSig("OP_FORNLOOP",
        patterns=[
            _p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\+\s*\1\s*\[\s*\w+\s*\+\s*2\s*\]"),
            _p(r"pc\s*=\s*pc\s*-"),
        ],
        score=15,
    ),

    OpSig("OP_FORGLOOP",
        patterns=[
            _p(r"(\w+)\s*\[\s*\w+\s*\+\s*4\s*\]"),
            _p(r"\w+\s*\[\s*\w+\s*\]\s*\(\s*\w+\s*\[\s*\w+\s*\+\s*1\s*\]"),
        ],
        score=14,
    ),

    OpSig("OP_FORGPREP",
        patterns=[_p(r"(\w+)\s*\[\s*\w+\s*\+\s*3\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]")],
        score=11,
    ),
    OpSig("OP_FORGPREP_INEXT",
        patterns=[_p(r"ipairs|inext|__inext")],
        score=13,
    ),
    OpSig("OP_FORGPREP_NEXT",
        patterns=[_p(r"(?:next\b|pairs\b)"), _p(r"(\w+)\s*\[\s*\w+\s*\+\s*3\s*\]")],
        score=13,
    ),

    OpSig("OP_GETVARARGS",
        patterns=[_p(r"select\s*\(\s*['\"]#['\"]|\.\.\.|vararg|varg")],
        score=12,
    ),

    OpSig("OP_PREPVARARGS",
        patterns=[_p(r"table\.pack\s*\(\s*\.\.\.\s*\)|local\s+\w+\s*=\s*\{\s*\.\.\.\s*\}")],
        score=12,
    ),

    OpSig("OP_LOADKX",
        patterns=[
            _p(r"(\w+)\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]"),
            _p(r"pc\s*=\s*pc\s*\+\s*1"),
        ],
        score=14,
    ),

    OpSig("OP_JUMPX",
        patterns=[
            _p(r"pc\s*=\s*pc\s*\+\s*\w+"),
            _p(r"pc\s*=\s*pc\s*\+\s*1"),
        ],
        anti=[_p(r"if\b")],
        score=13,
    ),

    OpSig("OP_FASTCALL",
        patterns=[_p(r"fastcall|__builtins|builtin\s*\[\s*\w+\s*\]")],
        score=11,
    ),
    OpSig("OP_FASTCALL1",
        patterns=[_p(r"fastcall|builtin"), _p(r"\[\s*\w+\s*\+\s*1\s*\]")],
        score=12,
    ),
    OpSig("OP_FASTCALL2",
        patterns=[_p(r"fastcall|builtin"), _p(r"\[\s*\w+\s*\+\s*1\s*\].*\[\s*\w+\s*\+\s*2\s*\]")],
        score=13,
    ),
    OpSig("OP_FASTCALL2K",
        patterns=[
            _p(r"fastcall|builtin"),
            _p(r"\w+\s*\[\s*\w+\s*\]"),
            _p(r"kst\s*\[|\w+\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\]"),
        ],
        score=13,
    ),

    OpSig("OP_COVERAGE",
        patterns=[_p(r"coverage|cov\s*=\s*cov\s*\+\s*1|__cov")],
        score=10,
    ),

    OpSig("OP_CAPTURE",
        patterns=[_p(r"capture|upvalue\s*=\s*\{|upv\s*\[\s*\w+\s*\]\s*=\s*\{")],
        score=11,
    ),

    OpSig("OP_JUMPXEQKNIL",
        patterns=[_p(r"==\s*nil|~=\s*nil"), _p(r"pc\s*=\s*pc\s*\+\s*\w+")],
        score=13,
    ),
    OpSig("OP_JUMPXEQKB",
        patterns=[_p(r"==\s*(?:true|false)|~=\s*(?:true|false)"), _p(r"pc\s*=\s*pc\s*\+\s*\w+")],
        score=13,
    ),
    OpSig("OP_JUMPXEQKN",
        patterns=[_p(r"==\s*\d+|~=\s*\d+"), _p(r"pc\s*=\s*pc\s*\+\s*\w+")],
        score=13,
    ),
    OpSig("OP_JUMPXEQKS",
        patterns=[_p(r"==\s*[\"']|~=\s*[\"']"), _p(r"pc\s*=\s*pc\s*\+\s*\w+")],
        score=13,
    ),
]

_SIG_BY_CANONICAL: dict[str, list[OpSig]] = {}
for _s in SIGNATURES:
    _SIG_BY_CANONICAL.setdefault(_s.canonical, []).append(_s)


# ── Handler extraction ────────────────────────────────────────────────────────

_DISPATCH_VAR_RE = re.compile(
    r"while\s+true\s+do\s+(?:local\s+)?(\w+)(?:\s*,|\s*=)",
    re.DOTALL,
)

def _collapse(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _find_loop_end(source: str, start: int, max_scan: int = 400_000) -> int:
    depth = 0
    end = min(len(source), start + max_scan)
    tok_re = re.compile(
        r"\b(while|for|do|if|function|repeat|end|until|then|else|elseif)\b"
    )
    for m in tok_re.finditer(source, start, end):
        kw = m.group(1)
        if kw in ("while", "for", "do", "function", "repeat", "if"):
            depth += 1
        elif kw in ("then", "else", "elseif"):
            pass
        elif kw == "until":
            depth -= 1
        elif kw == "end":
            depth -= 1
            if depth == 0:
                return m.end()
    return end


def extract_handlers(source: str) -> dict[int, str]:
    """
    Extract handler bodies from the VM dispatch loop(s).
    Returns {slot_number: collapsed_body_text}.
    Handles both single-dispatch and chunked-dispatch VM shapes.
    """
    handlers: dict[int, str] = {}

    loop_starts = [m.start() for m in re.finditer(r"while\s+true\s+do", source)]
    if not loop_starts:
        return handlers

    for ls in loop_starts:
        dm = _DISPATCH_VAR_RE.search(source, ls, ls + 512)
        if not dm:
            continue
        op_var = dm.group(1)

        loop_body_end = _find_loop_end(source, ls)
        loop_src = source[ls:loop_body_end]

        bound_re = re.compile(
            rf"(?:^|(?<=\n))\s*(?:else)?if\s+{re.escape(op_var)}\s*==\s*(\d+)\s+then\b",
            re.MULTILINE,
        )
        segs = list(bound_re.finditer(loop_src))

        for i, seg in enumerate(segs):
            slot = int(seg.group(1))
            body_start = seg.end()
            body_end   = segs[i + 1].start() if i + 1 < len(segs) else len(loop_src)
            raw_body   = loop_src[body_start:body_end]
            raw_body   = re.sub(r"\s*(end\s*)+$", "", raw_body.rstrip())
            handlers[slot] = _collapse(raw_body)

    return handlers


# ── Scoring engine ────────────────────────────────────────────────────────────

def _score_handler(body: str, sig: OpSig) -> int:
    for pat in sig.patterns:
        if not pat.search(body):
            return 0
    for anti in sig.anti:
        if anti.search(body):
            return 0
    return sig.score


def _match_handler(body: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    seen: set[str] = set()
    for sig in SIGNATURES:
        s = _score_handler(body, sig)
        if s > 0 and sig.canonical not in seen:
            hits.append((s, sig.canonical))
            seen.add(sig.canonical)
    hits.sort(key=lambda t: (
        -t[0],
        LUAU_OPCODES.index(t[1]) if t[1] in LUAU_OPCODES else 999,
    ))
    return hits


# ── OpcodeTable ───────────────────────────────────────────────────────────────

@dataclass
class MappedOp:
    slot:         int
    canonical:    str
    confidence:   int
    alternatives: list[str]
    body_preview: str


class OpcodeTable:
    def __init__(
        self,
        slot_to_op:   dict[int, MappedOp],
        raw_handlers: dict[int, str],
        source_hash:  str,
    ) -> None:
        self.slot_to_op   = slot_to_op
        self.raw_handlers = raw_handlers
        self.source_hash  = source_hash
        self.op_to_slot: dict[str, int] = {
            m.canonical: m.slot for m in slot_to_op.values()
        }

    def coverage(self) -> float:
        if not self.raw_handlers:
            return 0.0
        return len(self.slot_to_op) / len(self.raw_handlers)

    def canonical_coverage(self) -> float:
        return len(self.op_to_slot) / len(LUAU_OPCODES)

    def missing_slots(self) -> list[int]:
        return sorted(set(self.raw_handlers) - set(self.slot_to_op))

    def missing_ops(self) -> list[str]:
        return [op for op in LUAU_OPCODES if op not in self.op_to_slot]

    def get_slot(self, canonical: str) -> Optional[int]:
        return self.op_to_slot.get(canonical)

    def get_op(self, slot: int) -> Optional[str]:
        m = self.slot_to_op.get(slot)
        return m.canonical if m else None

    def summary(self) -> str:
        lines = [
            f"OpcodeTable  hash={self.source_hash[:12]}",
            f"  handlers : {len(self.raw_handlers)}",
            f"  mapped   : {len(self.slot_to_op)} "
              f"({self.coverage()*100:.0f}% of handlers, "
              f"{self.canonical_coverage()*100:.0f}% of Luau opcodes)",
        ]
        for slot in sorted(self.slot_to_op):
            m = self.slot_to_op[slot]
            alts = f"  alt=[{', '.join(m.alternatives[:2])}]" if m.alternatives else ""
            lines.append(f"  [{slot:3d}] {m.canonical:<22} conf={m.confidence}{alts}")
        if self.missing_slots():
            lines.append(f"  unmatched slots: {self.missing_slots()}")
        if self.missing_ops():
            lines.append(f"  not found ops  : {self.missing_ops()}")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps({
            "source_hash":   self.source_hash,
            "handlers":      len(self.raw_handlers),
            "mapped":        len(self.slot_to_op),
            "coverage_pct":  round(self.coverage() * 100, 1),
            "table": {
                str(slot): {
                    "op":           m.canonical,
                    "confidence":   m.confidence,
                    "alternatives": m.alternatives,
                }
                for slot, m in sorted(self.slot_to_op.items())
            },
            "missing_slots": self.missing_slots(),
            "missing_ops":   self.missing_ops(),
        }, indent=2)

    def assert_coverage(self, min_pct: float = 60.0) -> None:
        pct = self.coverage() * 100
        if pct < min_pct:
            raise RuntimeError(
                f"OpcodeTable coverage {pct:.1f}% < required {min_pct:.1f}%"
            )


# ── Public API ────────────────────────────────────────────────────────────────

def recover_opcodes(source: str) -> OpcodeTable:
    """
    Top-level entry point.
    Pass the raw obfuscated Luau source as a string.
    Returns an OpcodeTable with the recovered slot->opcode mapping.
    Per-script: call once per obfuscated file.
    """
    import hashlib
    h = hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()

    handlers = extract_handlers(source)
    if not handlers:
        return OpcodeTable({}, {}, h)

    slot_to_op: dict[int, MappedOp] = {}
    for slot, body in handlers.items():
        hits = _match_handler(body)
        if not hits:
            continue
        top_score, top_name = hits[0]
        alts = [name for _, name in hits[1:]]
        slot_to_op[slot] = MappedOp(
            slot         = slot,
            canonical    = top_name,
            confidence   = top_score,
            alternatives = alts,
            body_preview = body[:120],
        )

    return OpcodeTable(slot_to_op, handlers, h)


def recover_from_file(path: str | Path) -> OpcodeTable:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return recover_opcodes(text)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Luraph v15.1 opcode table recovery — static pattern matcher"
    )
    ap.add_argument("input",              help="obfuscated .lua/.luau file")
    ap.add_argument("-o", "--output",     help="write JSON table to this path")
    ap.add_argument("--min-coverage",     type=float, default=0.0,
                    help="fail if mapped%% < this (0=off)")
    ap.add_argument("--show-bodies",      action="store_true",
                    help="print handler body previews in summary")
    args = ap.parse_args()

    tbl = recover_from_file(args.input)
    print(tbl.summary())

    if args.show_bodies:
        print("\n--- handler body previews ---")
        for slot in sorted(tbl.raw_handlers):
            op = tbl.get_op(slot) or "UNKNOWN"
            print(f"[{slot:3d}] {op}")
            print(f"      {tbl.raw_handlers[slot][:200]}")

    if args.output:
        Path(args.output).write_text(tbl.to_json(), encoding="utf-8")
        print(f"\n[+] JSON -> {args.output}")

    if args.min_coverage > 0:
        tbl.assert_coverage(args.min_coverage)

    return 0


if __name__ == "__main__":
    sys.exit(_cli())
