#!/usr/bin/env python3
"""
opclassify.py — Heuristic Opcode Classifier for Luraph v15.1

Every Luraph v15.1-obfuscated script has its VM opcode dispatch table
shuffled at obfuscation time.  The handler bodies are semantically fixed
(MOVE always moves a register, CALL always calls a function) but their
integer IDs change on every pass.

This module walks the AST of the VM dispatcher loop, extracts each handler's
body as a structural fingerprint, and maps it to a canonical Luau opcode name.

Architecture
────────────
  1. HandlerExtractor   — walks the luau-ast JSON, finds every branch of the
                          while-true dispatcher, and emits (opcode_id, body_ast)
                          pairs.

  2. HandlerFingerprint — converts a handler body AST into a compact feature
                          vector: which kinds of table reads/writes occur, what
                          arithmetic ops appear, whether there is a nested call,
                          a return, a branch on a register, etc.

  3. OpcodeClassifier   — matches a fingerprint against the known signature
                          table for all ~80 canonical Luau opcodes and returns
                          the best match + confidence score.

  4. classify_script    — top-level entry: runs luau-ast, feeds into
                          HandlerExtractor + OpcodeClassifier, returns
                          {opcode_id: canonical_name} for the whole script.

Canonical opcode set  (Luau VM — matches the Luraph v15 IR layer)
─────────────────────────────────────────────────────────────────
  MOVE LOADK LOADBOOL LOADNIL
  GETUPVAL SETUPVAL GETGLOBAL SETGLOBAL
  GETTABLE SETTABLE NEWTABLE SELF
  ADD SUB MUL DIV MOD POW UNARY_MINUS NOT LEN CONCAT
  JMP EQ LT LE TEST TESTSET
  CALL TAILCALL RETURN
  FORLOOP FORPREP TFORLOOP
  SETLIST CLOSE CLOSURE VARARG
  GETFIELD SETFIELD GETTABLEKS SETTABLEKS
  FASTCALL FASTCALL1 FASTCALL2 FASTCALL2K
  CAPTURE NAMECALL PREPVARARGS
  LOADN LOADB JUMP JUMPIFEQ JUMPIFLT JUMPIFLE
  JUMPIFNOTEQ JUMPIFNOTLT JUMPIFNOTLE
  JUMPIFNOT JUMPIF JUMPBACK
  GETIMPORT GETVARARGS DUPCLOSURE NEWCLOSURE
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── feature flags (each is a bit in the fingerprint bitvector) ────────────────

_FEATURES = [
    # register file operations
    "REG_READ",          # reads regs[n]
    "REG_WRITE",         # writes regs[n]
    "REG_WRITE_NIL",     # writes nil to a register
    "REG_WRITE_BOOL",    # writes a bool constant
    "REG_WRITE_NUM",     # writes a numeric constant
    "REG_WRITE_CONST",   # writes from constants table
    "REG_COPY",          # regs[A] = regs[B]
    # upvalue operations
    "UPVAL_READ",        # reads upvals[n]
    "UPVAL_WRITE",       # writes upvals[n]
    # global / env operations
    "ENV_READ",          # reads _ENV[key] or getfenv()[key]
    "ENV_WRITE",         # writes _ENV[key]
    # table operations
    "TABLE_GETTABLE",    # t[key] where key is a register value
    "TABLE_SETTABLE",    # t[key] = v where key is a register value
    "TABLE_GETFIELD",    # t.field (string key literal)
    "TABLE_SETFIELD",    # t.field = v
    "TABLE_NEWTABLE",    # {} constructor
    "TABLE_RAWGET",      # rawget(t, k)
    "TABLE_RAWSET",      # rawset(t, k, v)
    "TABLE_SETLIST",     # bulk table fill
    # arithmetic / logic
    "ARITH_ADD",
    "ARITH_SUB",
    "ARITH_MUL",
    "ARITH_DIV",
    "ARITH_MOD",
    "ARITH_POW",
    "ARITH_IDIV",        # integer division
    "ARITH_BAND",        # bitwise and
    "ARITH_BOR",
    "ARITH_BXOR",
    "ARITH_BNOT",
    "ARITH_SHL",
    "ARITH_SHR",
    "ARITH_UNM",         # unary minus
    "ARITH_NOT",         # boolean not
    "ARITH_LEN",         # #t
    "ARITH_CONCAT",      # .. operator
    # comparisons
    "CMP_EQ",
    "CMP_LT",
    "CMP_LE",
    "CMP_NE",
    # control flow
    "CF_JMP",            # unconditional pc change
    "CF_CONDJMP",        # conditional pc change
    "CF_RETURN",         # return statement
    "CF_CALL",           # function call
    "CF_TAILCALL",       # tail call
    "CF_FORPREP",        # numeric for prep
    "CF_FORLOOP",        # numeric for step
    "CF_TFORLOOP",       # generic for step
    # closure / upval capture
    "CL_CLOSURE",        # creates a new closure
    "CL_CAPTURE",        # captures an upvalue into new closure
    "CL_CLOSE",          # closes upvalue range
    # misc
    "MISC_VARARG",       # vararg spread
    "MISC_SELF",         # method call prep (obj, method)
    "MISC_IMPORT",       # multi-level global import chain
    "MISC_LOADN",        # load numeric immediate
    "MISC_PREPVARARG",   # frame vararg setup
    # pc / instruction field reads (A/B/C/D operand decoding)
    "PC_READ_A",
    "PC_READ_B",
    "PC_READ_C",
    "PC_READ_D",
    "PC_READ_E",
    "PC_ADVANCE",        # explicit pc += 1
    "PC_JUMP_OFFSET",    # pc += offset
]

_F_IDX = {f: i for i, f in enumerate(_FEATURES)}
_N_FEATURES = len(_FEATURES)


def _fset(*names: str) -> frozenset[str]:
    return frozenset(names)


# ── canonical opcode signature table ─────────────────────────────────────────
# Each entry: (canonical_name, required_features, forbidden_features, weight)
# Weight reflects how specific the signature is (higher = more confident match).

_SIGNATURES: list[tuple[str, frozenset, frozenset, int]] = [
    # ── register moves / loads ────────────────────────────────────────────────
    ("MOVE",       _fset("REG_COPY", "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "TABLE_NEWTABLE", "ENV_READ"), 9),

    ("LOADK",      _fset("REG_WRITE_CONST", "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "ENV_READ", "REG_COPY"), 9),

    ("LOADN",      _fset("REG_WRITE_NUM", "MISC_LOADN", "PC_READ_A"),
                   _fset("CF_CALL", "ENV_READ", "REG_COPY"), 8),

    ("LOADBOOL",   _fset("REG_WRITE_BOOL", "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "ENV_READ"), 8),

    ("LOADNIL",    _fset("REG_WRITE_NIL", "PC_READ_A"),
                   _fset("CF_CALL", "REG_WRITE_CONST"), 8),

    # ── upvalue ops ───────────────────────────────────────────────────────────
    ("GETUPVAL",   _fset("UPVAL_READ", "REG_WRITE", "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "ENV_READ", "TABLE_GETTABLE"), 9),

    ("SETUPVAL",   _fset("UPVAL_WRITE", "REG_READ", "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "ENV_READ", "TABLE_GETTABLE"), 9),

    # ── global / env ops ─────────────────────────────────────────────────────
    ("GETGLOBAL",  _fset("ENV_READ", "REG_WRITE", "PC_READ_A"),
                   _fset("UPVAL_READ", "CF_CALL", "TABLE_GETTABLE"), 8),

    ("SETGLOBAL",  _fset("ENV_WRITE", "REG_READ", "PC_READ_A"),
                   _fset("UPVAL_WRITE", "CF_CALL"), 8),

    ("GETIMPORT",  _fset("ENV_READ", "MISC_IMPORT", "PC_READ_A"),
                   _fset("ENV_WRITE", "CF_RETURN"), 7),

    # ── table ops ────────────────────────────────────────────────────────────
    ("GETTABLE",   _fset("TABLE_GETTABLE", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("TABLE_SETTABLE", "ENV_READ"), 10),

    ("SETTABLE",   _fset("TABLE_SETTABLE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("TABLE_GETTABLE", "ENV_READ", "REG_WRITE"), 10),

    ("GETFIELD",   _fset("TABLE_GETFIELD", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B"),
                   _fset("TABLE_GETTABLE", "ENV_READ"), 9),

    ("SETFIELD",   _fset("TABLE_SETFIELD", "REG_READ",
                         "PC_READ_A", "PC_READ_B"),
                   _fset("TABLE_GETFIELD", "ENV_READ", "REG_WRITE"), 9),

    ("GETTABLEKS", _fset("TABLE_GETTABLE", "REG_WRITE_CONST", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("TABLE_SETTABLE", "ENV_READ"), 9),

    ("SETTABLEKS", _fset("TABLE_SETTABLE", "REG_WRITE_CONST", "REG_READ",
                         "PC_READ_A", "PC_READ_B"),
                   _fset("TABLE_GETTABLE", "REG_WRITE"), 9),

    ("NEWTABLE",   _fset("TABLE_NEWTABLE", "REG_WRITE", "PC_READ_A"),
                   _fset("CF_CALL", "TABLE_GETTABLE"), 8),

    ("SELF",       _fset("MISC_SELF", "TABLE_GETTABLE", "REG_WRITE",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN"), 9),

    ("SETLIST",    _fset("TABLE_SETLIST", "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "CF_RETURN"), 8),

    ("TABLE_RAWGET", _fset("TABLE_RAWGET", "REG_WRITE", "PC_READ_A"),
                   _fset("CF_CALL", "CF_RETURN"), 7),

    ("TABLE_RAWSET", _fset("TABLE_RAWSET", "REG_READ", "PC_READ_A"),
                   _fset("CF_RETURN"), 7),

    # ── arithmetic ───────────────────────────────────────────────────────────
    ("ADD",        _fset("ARITH_ADD", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN", "TABLE_GETTABLE"), 9),

    ("SUB",        _fset("ARITH_SUB", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN", "TABLE_GETTABLE"), 9),

    ("MUL",        _fset("ARITH_MUL", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN", "TABLE_GETTABLE"), 9),

    ("DIV",        _fset("ARITH_DIV", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN", "TABLE_GETTABLE"), 9),

    ("MOD",        _fset("ARITH_MOD", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN"), 9),

    ("POW",        _fset("ARITH_POW", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN"), 9),

    ("IDIV",       _fset("ARITH_IDIV", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN"), 8),

    ("BAND",       _fset("ARITH_BAND", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN"), 8),

    ("BOR",        _fset("ARITH_BOR", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN"), 8),

    ("BXOR",       _fset("ARITH_BXOR", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN"), 8),

    ("BNOT",       _fset("ARITH_BNOT", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "CF_RETURN"), 8),

    ("SHL",        _fset("ARITH_SHL", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN"), 8),

    ("SHR",        _fset("ARITH_SHR", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN"), 8),

    ("UNM",        _fset("ARITH_UNM", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "CF_RETURN", "CMP_EQ"), 9),

    ("NOT",        _fset("ARITH_NOT", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "CF_RETURN", "CMP_EQ"), 9),

    ("LEN",        _fset("ARITH_LEN", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "CF_RETURN"), 9),

    ("CONCAT",     _fset("ARITH_CONCAT", "REG_WRITE", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_CALL", "CF_RETURN"), 9),

    # ── comparisons / conditional jumps ──────────────────────────────────────
    ("EQ",         _fset("CMP_EQ", "CF_CONDJMP", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_RETURN", "CF_CALL", "REG_WRITE"), 10),

    ("LT",         _fset("CMP_LT", "CF_CONDJMP", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_RETURN", "CF_CALL", "REG_WRITE"), 10),

    ("LE",         _fset("CMP_LE", "CF_CONDJMP", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_RETURN", "CF_CALL", "REG_WRITE"), 10),

    ("JUMPIFEQ",   _fset("CMP_EQ", "CF_JMP", "PC_READ_A", "PC_READ_D"),
                   _fset("CF_CALL", "CF_RETURN", "REG_WRITE"), 9),

    ("JUMPIFLT",   _fset("CMP_LT", "CF_JMP", "PC_READ_A", "PC_READ_D"),
                   _fset("CF_CALL", "CF_RETURN", "REG_WRITE"), 9),

    ("JUMPIFLE",   _fset("CMP_LE", "CF_JMP", "PC_READ_A", "PC_READ_D"),
                   _fset("CF_CALL", "CF_RETURN", "REG_WRITE"), 9),

    ("JUMPIFNOTEQ",_fset("CMP_NE", "CF_JMP", "PC_READ_A", "PC_READ_D"),
                   _fset("CF_CALL", "CF_RETURN", "REG_WRITE"), 9),

    ("TEST",       _fset("CF_CONDJMP", "REG_READ", "PC_READ_A", "PC_READ_C"),
                   _fset("CF_RETURN", "CF_CALL", "CMP_EQ", "REG_WRITE"), 8),

    ("TESTSET",    _fset("CF_CONDJMP", "REG_READ", "REG_WRITE",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_RETURN", "CF_CALL", "CMP_EQ"), 8),

    # ── unconditional jumps ───────────────────────────────────────────────────
    ("JMP",        _fset("CF_JMP", "PC_READ_A", "PC_JUMP_OFFSET"),
                   _fset("CF_CALL", "CF_RETURN", "CMP_EQ", "REG_WRITE",
                         "REG_READ"), 9),

    ("JUMP",       _fset("CF_JMP", "PC_READ_D", "PC_JUMP_OFFSET"),
                   _fset("CF_CALL", "CF_RETURN", "CMP_EQ", "REG_WRITE"), 9),

    ("JUMPBACK",   _fset("CF_JMP", "PC_JUMP_OFFSET"),
                   _fset("CF_CALL", "CF_RETURN", "CMP_EQ", "PC_READ_A"), 7),

    # ── calls / returns ───────────────────────────────────────────────────────
    ("CALL",       _fset("CF_CALL", "REG_READ",
                         "PC_READ_A", "PC_READ_B", "PC_READ_C"),
                   _fset("CF_RETURN", "CF_TAILCALL", "CL_CLOSURE"), 10),

    ("TAILCALL",   _fset("CF_TAILCALL", "REG_READ",
                         "PC_READ_A", "PC_READ_B"),
                   _fset("CF_RETURN", "CL_CLOSURE"), 9),

    ("RETURN",     _fset("CF_RETURN", "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "CF_JMP"), 10),

    ("NAMECALL",   _fset("MISC_SELF", "CF_CALL", "TABLE_GETFIELD",
                         "PC_READ_A", "PC_READ_B"),
                   _fset("CF_RETURN", "CL_CLOSURE"), 9),

    ("FASTCALL",   _fset("CF_CALL", "PC_READ_A", "CF_CONDJMP"),
                   _fset("CF_RETURN", "REG_WRITE"), 7),

    ("FASTCALL1",  _fset("CF_CALL", "PC_READ_A", "PC_READ_B", "CF_CONDJMP"),
                   _fset("CF_RETURN", "REG_WRITE"), 7),

    ("FASTCALL2",  _fset("CF_CALL", "PC_READ_A", "PC_READ_B", "PC_READ_C",
                         "CF_CONDJMP"),
                   _fset("CF_RETURN", "REG_WRITE"), 7),

    # ── for loops ────────────────────────────────────────────────────────────
    ("FORPREP",    _fset("CF_FORPREP", "REG_READ", "PC_READ_A", "PC_READ_D"),
                   _fset("CF_CALL", "CF_RETURN"), 9),

    ("FORLOOP",    _fset("CF_FORLOOP", "ARITH_ADD", "REG_WRITE",
                         "PC_READ_A", "PC_JUMP_OFFSET"),
                   _fset("CF_CALL", "CF_RETURN"), 9),

    ("TFORLOOP",   _fset("CF_TFORLOOP", "CF_CALL", "REG_WRITE",
                         "PC_READ_A", "PC_READ_C"),
                   _fset("CF_RETURN"), 9),

    # ── closures ─────────────────────────────────────────────────────────────
    ("CLOSURE",    _fset("CL_CLOSURE", "REG_WRITE", "PC_READ_A", "PC_READ_D"),
                   _fset("CF_CALL", "CF_RETURN", "TABLE_GETTABLE"), 9),

    ("NEWCLOSURE", _fset("CL_CLOSURE", "REG_WRITE", "PC_READ_A"),
                   _fset("CF_CALL", "CF_RETURN", "TABLE_GETTABLE"), 8),

    ("DUPCLOSURE", _fset("CL_CLOSURE", "REG_WRITE_CONST", "PC_READ_A", "PC_READ_D"),
                   _fset("CF_CALL", "CF_RETURN"), 8),

    ("CAPTURE",    _fset("CL_CAPTURE", "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "CF_RETURN", "REG_WRITE"), 8),

    ("CLOSE",      _fset("CL_CLOSE", "PC_READ_A"),
                   _fset("CF_CALL", "CF_RETURN", "REG_WRITE"), 8),

    # ── vararg ───────────────────────────────────────────────────────────────
    ("VARARG",     _fset("MISC_VARARG", "REG_WRITE", "PC_READ_A", "PC_READ_B"),
                   _fset("CF_CALL", "CF_RETURN"), 9),

    ("GETVARARGS", _fset("MISC_VARARG", "REG_WRITE", "PC_READ_A"),
                   _fset("CF_CALL", "CF_RETURN"), 8),

    ("PREPVARARGS",_fset("MISC_PREPVARARG", "PC_READ_A"),
                   _fset("CF_CALL", "CF_RETURN", "REG_WRITE"), 8),
]


# ── source-text feature extraction ───────────────────────────────────────────

# Patterns matched against the Luau source text of each handler body.
# Each tuple: (feature_name, compiled_regex)
_TEXT_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Register file: variable name patterns like  regs[A]  R[A]  reg[i]
    # (Luraph uses obfuscated single/short names for the register array)
    ("REG_READ",        re.compile(r'\b[A-Za-z_]\w*\[(?:[A-Za-z_]\w*)\](?!\s*=)',  re.M)),
    ("REG_WRITE",       re.compile(r'\b[A-Za-z_]\w*\[(?:[A-Za-z_]\w*)\]\s*=(?!=)', re.M)),
    ("REG_WRITE_NIL",   re.compile(r'\b[A-Za-z_]\w*\[(?:[A-Za-z_]\w*)\]\s*=\s*nil\b', re.M)),
    ("REG_WRITE_BOOL",  re.compile(r'\b[A-Za-z_]\w*\[(?:[A-Za-z_]\w*)\]\s*=\s*(?:true|false)\b', re.M)),
    ("REG_WRITE_NUM",   re.compile(r'\b[A-Za-z_]\w*\[(?:[A-Za-z_]\w*)\]\s*=\s*-?\d+(?:\.\d+)?(?!\s*[+\-*/%])', re.M)),
    # upvalue table (usually accessed as  ups[n]  uv[n])
    ("UPVAL_READ",      re.compile(r'\bup(?:v(?:al(?:s?))?|s?)?\s*\[', re.I)),
    ("UPVAL_WRITE",     re.compile(r'\bup(?:v(?:al(?:s?))?|s?)?\s*\[[^\]]+\]\s*=(?!=)', re.I)),
    # env / globals
    ("ENV_READ",        re.compile(r'\b(?:_ENV|env|getfenv\s*\(\s*\))\s*\[', re.M)),
    ("ENV_WRITE",       re.compile(r'\b(?:_ENV|env|getfenv\s*\(\s*\))\s*\[[^\]]+\]\s*=(?!=)', re.M)),
    # table ops
    ("TABLE_GETTABLE",  re.compile(r'\b\w+\s*\[\s*\w+\s*\](?!\s*=)', re.M)),
    ("TABLE_SETTABLE",  re.compile(r'\b\w+\s*\[\s*\w+\s*\]\s*=(?!=)', re.M)),
    ("TABLE_GETFIELD",  re.compile(r'\b\w+\s*\.\s*[A-Za-z_]\w*(?!\s*=)', re.M)),
    ("TABLE_SETFIELD",  re.compile(r'\b\w+\s*\.\s*[A-Za-z_]\w*\s*=(?!=)', re.M)),
    ("TABLE_NEWTABLE",  re.compile(r'\{[\s,]*\}|\{[^}]{0,40}\}', re.M)),
    ("TABLE_RAWGET",    re.compile(r'\brawget\s*\(', re.M)),
    ("TABLE_RAWSET",    re.compile(r'\brawset\s*\(', re.M)),
    ("TABLE_SETLIST",   re.compile(r'for\s+\w+\s*=\s*\w+\s*,\s*\w+\s*do\s*\w+\[\w+\]\s*=', re.M)),
    # arithmetic
    ("ARITH_ADD",       re.compile(r'(?<![=<>!])(?<!\.)[\+](?![+=])', re.M)),
    ("ARITH_SUB",       re.compile(r'(?<![=<>!])-(?!=)(?!\-)', re.M)),
    ("ARITH_MUL",       re.compile(r'(?<![=<>!])\*(?!=)', re.M)),
    ("ARITH_DIV",       re.compile(r'(?<![=<>!])/(?!=[/])', re.M)),
    ("ARITH_MOD",       re.compile(r'(?<![=<>!])%(?!=)', re.M)),
    ("ARITH_POW",       re.compile(r'\^', re.M)),
    ("ARITH_IDIV",      re.compile(r'//', re.M)),
    ("ARITH_BAND",      re.compile(r'\bbit32\.band\b|\&(?!&)', re.M)),
    ("ARITH_BOR",       re.compile(r'\bbit32\.bor\b|\|(?!\|)', re.M)),
    ("ARITH_BXOR",      re.compile(r'\bbit32\.bxor\b|\^', re.M)),
    ("ARITH_BNOT",      re.compile(r'\bbit32\.bnot\b|~(?!=)', re.M)),
    ("ARITH_SHL",       re.compile(r'\bbit32\.lshift\b|<<', re.M)),
    ("ARITH_SHR",       re.compile(r'\bbit32\.rshift\b|>>', re.M)),
    ("ARITH_UNM",       re.compile(r'=\s*-\s*[A-Za-z_]\w*\s*(?:$|[;\n])', re.M)),
    ("ARITH_NOT",       re.compile(r'\bnot\s+[A-Za-z_]', re.M)),
    ("ARITH_LEN",       re.compile(r'#\s*[A-Za-z_]\w*', re.M)),
    ("ARITH_CONCAT",    re.compile(r'\.\.', re.M)),
    # comparisons
    ("CMP_EQ",          re.compile(r'==', re.M)),
    ("CMP_LT",          re.compile(r'<(?!=)', re.M)),
    ("CMP_LE",          re.compile(r'<=', re.M)),
    ("CMP_NE",          re.compile(r'~=|!=', re.M)),
    # control flow
    ("CF_JMP",          re.compile(r'\b(?:pc|PC|ip|IP)\s*=\s*\w+\s*[+\-]|\bgoto\b', re.M)),
    ("CF_CONDJMP",      re.compile(r'\bif\b', re.M)),
    ("CF_RETURN",       re.compile(r'\breturn\b', re.M)),
    ("CF_CALL",         re.compile(r'[A-Za-z_]\w*\s*\(', re.M)),
    ("CF_TAILCALL",     re.compile(r'\breturn\s+[A-Za-z_]\w*\s*\(', re.M)),
    ("CF_FORPREP",      re.compile(r'\bfor\b.*\bdo\b', re.M)),
    ("CF_FORLOOP",      re.compile(r'\bfor\b.*\bdo\b|\+\s*\bstep\b|\bstep\b\s*\+', re.M)),
    ("CF_TFORLOOP",     re.compile(r'\bfor\b.*\bin\b', re.M)),
    # closure / upval capture
    ("CL_CLOSURE",      re.compile(r'\bfunction\b\s*\(', re.M)),
    ("CL_CAPTURE",      re.compile(r'\bupvalue\b|\bCapture\b|\bcapture\b', re.M)),
    ("CL_CLOSE",        re.compile(r'\bclose\b\s*\(|\bCloseUpv', re.M)),
    # misc
    ("MISC_VARARG",     re.compile(r'\bvararg\b|\.\.\.', re.M)),
    ("MISC_SELF",       re.compile(r'\bself\b|:\s*[A-Za-z_]\w*\s*\(', re.M)),
    ("MISC_IMPORT",     re.compile(r'\[k\d\]\s*\[\s*k\d\s*\]|\bimport\b', re.M)),
    ("MISC_LOADN",      re.compile(r'=\s*-?\d+(?:\.\d+)?\s*(?:$|;)', re.M)),
    ("MISC_PREPVARARG", re.compile(r'\bprepvararg\b|\bPREPVAR', re.M)),
    # operand field reads — Luraph v15.1 typically decodes A/B/C/D from the
    # instruction integer via bit ops; we look for characteristic patterns.
    ("PC_READ_A",       re.compile(r'\bA\b\s*=|\bband\b.*\b0[xX][fF]{1,4}\b|\b&\s*0[xX][fF]{1,4}\b', re.M)),
    ("PC_READ_B",       re.compile(r'\bB\b\s*=|\brshift\b.*\b8\b|>>\s*8\b', re.M)),
    ("PC_READ_C",       re.compile(r'\bC\b\s*=|\brshift\b.*\b16\b|>>\s*16\b', re.M)),
    ("PC_READ_D",       re.compile(r'\bD\b\s*=|\brshift\b.*\b(?:18|16)\b', re.M)),
    ("PC_READ_E",       re.compile(r'\bE\b\s*=|\brshift\b.*\b24\b|>>\s*24\b', re.M)),
    ("PC_ADVANCE",      re.compile(r'\b(?:pc|PC|ip|IP)\s*[+]?=\s*(?:\w+\s*\+)?\s*1\b', re.M)),
    ("PC_JUMP_OFFSET",  re.compile(r'\b(?:pc|PC|ip|IP)\s*[+]?=\s*\w+\s*[+\-]\s*\w+', re.M)),
    ("REG_COPY",        re.compile(r'\b[A-Za-z_]\w*\[[^\]]+\]\s*=\s*[A-Za-z_]\w*\[[^\]]+\]', re.M)),
    ("REG_WRITE_CONST", re.compile(r'\b[A-Za-z_]\w*\[[^\]]+\]\s*=\s*[Kk]\w*\[', re.M)),
]


@dataclass
class HandlerFeatures:
    """Extracted features for one VM handler body."""
    opcode_id: int
    body_text: str
    features: frozenset[str] = field(default_factory=frozenset)
    raw_score: int = 0


@dataclass
class ClassifyResult:
    opcode_id: int
    canonical: str
    confidence: float          # 0.0–1.0
    runner_up: Optional[str]
    runner_up_conf: float
    features: frozenset[str]


def extract_features(handler_body: str) -> frozenset[str]:
    """Run all text patterns against handler_body and return the feature set."""
    found: set[str] = set()
    for feat, rx in _TEXT_PATTERNS:
        if rx.search(handler_body):
            found.add(feat)
    return frozenset(found)


def _score(features: frozenset[str],
           required: frozenset[str],
           forbidden: frozenset[str],
           weight: int) -> float:
    """Score a signature match: penalise missing required and present forbidden."""
    if forbidden & features:
        return 0.0
    hit = len(required & features)
    total = len(required)
    if total == 0:
        return 0.0
    return (hit / total) * weight


def classify_handler(features: frozenset[str]) -> ClassifyResult:
    """Match features against all signatures, return best + runner-up."""
    scores: list[tuple[float, str]] = []
    for canon, req, forb, weight in _SIGNATURES:
        s = _score(features, req, forb, weight)
        if s > 0:
            scores.append((s, canon))

    if not scores:
        return ClassifyResult(-1, "UNKNOWN", 0.0, None, 0.0, features)

    scores.sort(key=lambda x: -x[0])
    best_s, best_n = scores[0]
    max_possible = max(w for _, _, _, w in _SIGNATURES)
    conf = min(best_s / max_possible, 1.0)

    runner = scores[1] if len(scores) > 1 else (0.0, None)
    r_conf = min(runner[0] / max_possible, 1.0)

    return ClassifyResult(-1, best_n, conf, runner[1], r_conf, features)


# ── handler body extractor ───────────────────────────────────────────────────

def _extract_handler_bodies(source: str) -> list[tuple[int, str]]:
    """
    Extract (opcode_id, handler_body_text) pairs from a Luraph v15.1 script.

    Luraph's dispatcher has one of two shapes:
      Shape 1 (v15 classic):
          while true do
              local op = instr[pc]
              if op == 37 then ... elseif op == 12 then ... end
          end

      Shape 2 (v15.1 bool-local):
          while true do
              local op = instr[pc]
              local _b = op == 37
              if _b then ... end
              local _b = op == 12
              if _b then ... end
          end

    We handle both. Returns list of (int opcode_id, str body).
    """
    pairs: list[tuple[int, str]] = []

    # Shape 1: if op == N then ... elseif op == M then ...
    shape1_branch = re.compile(
        r'(?:^|\n)\s*(?:else)?if\s+\w+\s*==\s*(\d+)\s+then\s*\n(.*?)(?=\n\s*(?:else)?if\s+\w+\s*==|\n\s*else\s*\n|\n\s*end\s*(?:$|\n))',
        re.DOTALL | re.MULTILINE,
    )

    # Shape 2: local _b = op == N \n if _b then
    shape2_assign = re.compile(
        r'local\s+\w+\s*=\s*\w+\s*==\s*(\d+)\s*\n\s*if\s+\w+\s+then\s*\n(.*?)(?=\n\s*local\s+\w+\s*=\s*\w+\s*==|\n\s*end\s*(?:$|\n))',
        re.DOTALL | re.MULTILINE,
    )

    for rx in (shape1_branch, shape2_assign):
        for m in rx.finditer(source):
            try:
                oid = int(m.group(1))
                body = m.group(2)
                if body.strip():
                    pairs.append((oid, body))
            except (ValueError, IndexError):
                continue

    # Deduplicate by opcode_id keeping longest body (most complete handler)
    best: dict[int, str] = {}
    for oid, body in pairs:
        if oid not in best or len(body) > len(best[oid]):
            best[oid] = body

    return sorted(best.items())


# ── top-level entry ───────────────────────────────────────────────────────────

def classify_script(source: str,
                    min_confidence: float = 0.35
                    ) -> dict[int, ClassifyResult]:
    """
    Classify all VM handlers in source.
    Returns {opcode_id: ClassifyResult}.
    Only includes results with confidence >= min_confidence.
    """
    handlers = _extract_handler_bodies(source)
    results: dict[int, ClassifyResult] = {}

    for oid, body in handlers:
        feats = extract_features(body)
        result = classify_handler(feats)
        result.opcode_id = oid
        if result.confidence >= min_confidence:
            results[oid] = result

    return results


def build_opcode_map(source: str,
                     min_confidence: float = 0.35
                     ) -> dict[int, str]:
    """
    Convenience: return {opcode_id: canonical_name} for all handlers
    classified above min_confidence.
    """
    classified = classify_script(source, min_confidence)
    return {oid: r.canonical for oid, r in classified.items()}


def print_classification_report(source: str) -> dict[int, ClassifyResult]:
    """Pretty-print the classification table and return the results dict."""
    results = classify_script(source, min_confidence=0.0)
    handlers = _extract_handler_bodies(source)

    print("=" * 72)
    print(f"  Luraph v15.1 — Opcode Classification Report")
    print(f"  {len(handlers)} handlers found, {len(results)} classified")
    print("=" * 72)
    print(f"  {'ID':>5}  {'Canonical':<18}  {'Conf':>6}  {'Runner-up':<18}  {'R-Conf':>6}")
    print("-" * 72)

    for oid, result in sorted(results.items()):
        conf_s = f"{result.confidence:.0%}"
        rconf_s = f"{result.runner_up_conf:.0%}" if result.runner_up else ""
        print(f"  {oid:>5}  {result.canonical:<18}  {conf_s:>6}  "
              f"{(result.runner_up or ''):18}  {rconf_s:>6}")

    # Unclassified handlers
    classified_ids = set(results)
    unclassified = [oid for oid, _ in handlers if oid not in classified_ids]
    if unclassified:
        print(f"\n  Unclassified opcode IDs ({len(unclassified)}): "
              f"{', '.join(str(x) for x in sorted(unclassified))}")
        print("  → Drop a v15.1 script and run again to refine signatures.")

    print()
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python opclassify.py <script.lua>")
        sys.exit(1)
    src = Path(sys.argv[1]).read_text(errors="replace")
    print_classification_report(src)
