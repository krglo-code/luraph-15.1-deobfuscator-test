#!/usr/bin/env python3
"""
Luraph Deobfuscation Suite v3 — Unified Orchestrator
=====================================================
Now with a full built-in sandbox stack:
  • envlog.luau   — hardened offline Roblox emulator (Luraph v15/v15.1,
                    SuperFlow _bsdata0, FlowAuth, executor globals, LPH_ stubs)
  • ipc_repl.py   — live IPC REPL for on-demand constant decryption
  • static_unpack  — LPS/PSU, Luraph v14 LZMA, Prometheus, string.char,
                    _bsdata0 extraction
  • detect.py     — 40-pattern multi-family fingerprinter

External engine priority (auto):
  1. kers0nec multi-family Node lifter   (deobfuscator-luraph-v15/)
  2. KryptIT / larpcorrupt VM deob       (luraph-v15-deob-krypt/)
  3. caomod2077 v15 Node lifter          (psu-deobfuscator/)
  4. Built-in sandbox trace (always available — needs only luau binary)
  5. unluraph.py fallback

Usage:
  python deob.py                              # auto: latest in input/
  python deob.py script.lua                   # single file
  python deob.py script.lua -o out.lua
  python deob.py --detect script.lua
  python deob.py --sandbox script.lua         # built-in sandbox only
  python deob.py --unpack script.lua          # static unpack only
  python deob.py --components
  python deob.py --engine auto|kers|v15|v14|node|sandbox|unluraph
  python deob.py --key YOUR-KEY script.lua    # FlowAuth / KeyForge
  python deob.py --no-devirt script.lua       # trace-only (~2s)
  python deob.py --timeout 600 big.lua
  python deob.py --bsdata "blob" script.lua   # manual _bsdata0 seed
  python deob.py --rounds 5 script.lua        # sandbox trace rounds
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Suite root
ROOT        = Path(__file__).resolve().parent
INPUT_DIR   = ROOT / "input"
OUTPUT_DIR  = ROOT / "output"
BIN_DIR     = ROOT / "bin"

# Internal modules
CORE_DIR    = ROOT / "core"
RUNTIME_DIR = ROOT / "runtime"
SANDBOX     = RUNTIME_DIR / "envlog.luau"
UNLURAPH    = ROOT / "unluraph.py"

# External engines
KERS_DIR    = ROOT / "deobfuscator-luraph-v15.1"
KERS_DEOB   = KERS_DIR / "deob.js"
VM_DEOB     = ROOT / "luraph-v15-deob-krypt" / "Deobfuscator" / "deobf" / "bin" / "deob.py"
VM_CLI      = ROOT / "luraph-v15-deob-krypt" / "Deobfuscator" / "Deobfuscator" / "deobf" / "bin" / "cli.py"
VM_BIN      = ROOT / "luraph-v15-deob-krypt" / "Deobfuscator" / "deobf" / "bin"
NODE_DEOB   = ROOT / "psu-deobfuscator" / "deob.js"
NODE_DIR    = ROOT / "psu-deobfuscator"

# v15.1 / SuperFlow Python module (built into this suite)
V151_DIR    = KERS_DIR / "core" / "obfuscators" / "luraph_v15.1"
V151_DRIVER = V151_DIR / "driver.py"


# ── helpers ──────────────────────────────────────────────────────────────────

def find_luau() -> Optional[str]:
    # Windows shim: if only luau exists, expose it as luau.exe too.
    luau_bin = BIN_DIR / "luau"
    luau_exe = BIN_DIR / "luau.exe"
    if luau_bin.is_file() and not luau_exe.is_file():
        try:
            import shutil as _sh
            _sh.copy2(luau_bin, luau_exe)
        except OSError:
            pass
    for c in [
        BIN_DIR/"luau", BIN_DIR/"luau.exe",
        VM_BIN/"luau",  VM_BIN/"luau.exe",
        NODE_DIR/"bin"/"luau", NODE_DIR/"bin"/"luau.exe",
        KERS_DIR/"bin"/"luau", KERS_DIR/"bin"/"luau.exe",
    ]:
        if c.is_file(): return str(c)
    return shutil.which("luau")

def find_node() -> Optional[str]:
    return shutil.which("node") or shutil.which("node18") or shutil.which("nodejs")

def _path_env(extra=()) -> dict:
    m = os.environ.copy()
    m["PATH"] = os.pathsep.join(
        [str(p) for p in extra] + [str(BIN_DIR), m.get("PATH","")]
    )
    return m

def run(cmd, desc, cwd=None, env=None, timeout=300):
    print(f"\n[==] {desc}")
    print(f"    $ {' '.join(cmd)}")
    try:
        r = subprocess.run(
            cmd, cwd=str(cwd or ROOT),
            env=env or _path_env(),
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"    [!] timed out ({timeout}s)"); return False, ""
    except FileNotFoundError as e:
        print(f"    [!] not found: {e}"); return False, ""
    out = (r.stdout or "") + (r.stderr or "")
    if out.strip():
        for line in out.strip().splitlines()[-60:]:
            print(f"    {line}")
    if r.returncode != 0:
        print(f"    [!] exit {r.returncode}")
        return False, out
    return True, out

def _output_ok(p: Path, min_bytes=32) -> bool:
    return p.is_file() and p.stat().st_size > min_bytes

def find_latest_lua() -> Optional[Path]:
    files = list(INPUT_DIR.glob("*.lua")) + list(INPUT_DIR.glob("*.luau"))
    return max(files, key=lambda p: p.stat().st_mtime) if files else None

def ensure_dirs():
    INPUT_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)


# ── internal detect + unpack ─────────────────────────────────────────────────

def _import_core():
    """Add core/ to sys.path so internal modules are importable."""
    core = str(CORE_DIR)
    if core not in sys.path:
        sys.path.insert(0, core)

def run_detect(path: Path) -> None:
    _import_core()
    try:
        from detect import detect_and_print
        detect_and_print(path)
    except ImportError:
        print("[!] core/detect.py missing — basic static scan only")
        _basic_detect(path)

def _basic_detect(path: Path) -> None:
    import re
    text = path.read_text(errors="replace")[:12_000]
    markers = [
        (r"Luraph Obfuscator v15\.1", "v15.1 header"),
        (r"LPH_ENCSTR2",              "v15.1 extended encrypt"),
        (r"_bsdata0",                 "_bsdata0 (SuperFlow)"),
        (r"flowauth\.net",            "FlowAuth loader"),
        (r"Luraph Obfuscator v15",    "v15 header"),
        (r"LPH_ENCSTR\b",             "v15 encrypt"),
        (r"LPH%[0-9a-zA-Z]{10,}",    "v14 base85 envelope"),
        (r"keyforge\.win",            "KeyForge delivery"),
    ]
    hits = [label for pat, label in markers if re.search(pat, text)]
    print("  Static markers:", ", ".join(hits) if hits else "(none)")

def run_static_unpack(path: Path, output: Path) -> bool:
    _import_core()
    try:
        from static_unpack import static_unpack, extract_bsdata
    except ImportError:
        print("[!] core/static_unpack.py missing"); return False

    src = path.read_text(errors="replace")
    unpacked, method = static_unpack(src)
    if unpacked:
        output.write_text(unpacked)
        print(f"\n[+] Static unpack via {method} -> {output}")
        bsd = extract_bsdata(src)
        if bsd:
            print(f"    _bsdata keys extracted: {list(bsd.keys())}")
        return True
    bsd = extract_bsdata(src)
    if bsd:
        print(f"[!] Static unpack failed but _bsdata keys found: {list(bsd.keys())}")
        print("    Hint: use --engine sandbox --bsdata to pre-seed the bootstrapper")
    return False


# ── built-in sandbox engine ───────────────────────────────────────────────────

def engine_sandbox(
    path: Path,
    output: Path,
    *,
    bsdata0: Optional[str] = None,
    rounds: int = 3,
    timeout: int = 90,
    no_devirt: bool = False,
) -> bool:
    """
    Built-in sandbox trace engine.
    Runs the script through envlog.luau via IpcRepl for up to `rounds` passes.
    Collects all events and writes a behaviour trace + any loadstring payloads.

    Returns True if any events were collected (even partial).
    """
    luau = find_luau()
    if not luau:
        print("[!] luau binary not found — place it in bin/luau")
        print("    Download: https://github.com/luau-lang/luau/releases")
        return False

    if not SANDBOX.is_file():
        print("[!] runtime/envlog.luau missing — sandbox engine unavailable")
        return False

    _import_core()
    try:
        from ipc_repl import run_sandbox
    except ImportError:
        print("[!] core/ipc_repl.py missing"); return False

    # Try static unpack first; if it succeeds, trace the inner payload
    _import_core()
    try:
        from static_unpack import static_unpack, extract_bsdata
        src = path.read_text(errors="replace")
        unpacked, method = static_unpack(src)
        if unpacked:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".lua", mode="w",
                                              dir=path.parent, delete=False) as tf:
                tf.write(unpacked)
                tmp_path = Path(tf.name)
            print(f"[*] Static unpack ({method}) succeeded — tracing inner payload")
            result = engine_sandbox(
                tmp_path, output,
                bsdata0=bsdata0 or extract_bsdata(src).get("_bsdata0"),
                rounds=rounds, timeout=timeout, no_devirt=no_devirt,
            )
            os.unlink(str(tmp_path))
            return result

        # Extract _bsdata0 from the source even if static unpack failed
        bsd = extract_bsdata(src)
        if bsd and bsdata0 is None:
            bsdata0 = bsd.get("_bsdata0")
            if bsdata0:
                print(f"[*] Auto-extracted _bsdata0 from source ({len(bsdata0)} chars)")
    except ImportError:
        pass

    all_events: list[dict] = []
    loadstring_payloads: list[str] = []

    print(f"\n[==] Built-in sandbox trace ({rounds} rounds, luau: {luau})")

    for r in range(rounds):
        print(f"    [round {r+1}/{rounds}]")
        events = run_sandbox(
            luau, path, SANDBOX,
            round=r,
            timeout=timeout,
            bsdata0=bsdata0,
            harness_dir=path.parent,
        )
        all_events.extend(events)

        for e in events:
            if e.get("t") == "loadstring" and e.get("payload"):
                try:
                    import base64 as _b64
                    payload = _b64.b64decode(e["payload"]).decode("utf-8", errors="replace")
                    if payload not in loadstring_payloads:
                        loadstring_payloads.append(payload)
                except Exception:
                    pass

        if any(e.get("t") == "done" for e in events):
            break

    if not all_events:
        print("    [!] no events collected")
        return False

    # Write output report
    lines = ["-- Luraph Deobfuscation Suite v3 — Sandbox Trace Report"]
    lines.append(f"-- Target: {path}")
    lines.append(f"-- Rounds: {rounds}")
    lines.append(f"-- Events: {len(all_events)}")
    lines.append("")

    # Decode constants
    encstr_events = [e for e in all_events if e.get("t") in ("lph_encstr","lph_encstr2")]
    if encstr_events:
        lines.append("-- Decrypted constants:")
        for e in encstr_events:
            lines.append(f"--   [{e['t']}] {repr(e.get('decoded',''))}")
        lines.append("")

    # Recovered loadstring payloads
    if loadstring_payloads:
        lines.append(f"-- Recovered {len(loadstring_payloads)} loadstring payload(s):")
        for i, payload in enumerate(loadstring_payloads):
            lines.append(f"\n-- ===== Payload {i+1} =====")
            lines.append(payload)
    else:
        lines.append("-- No loadstring payloads captured.")
        lines.append("-- (Full devirtualization requires the kers0nec external engine)")

    # HTTP calls
    http_events = [e for e in all_events if e.get("t") == "http"]
    if http_events:
        lines.append("\n-- HTTP calls observed:")
        for e in http_events:
            lines.append(f"--   {e.get('method','GET')} {e.get('url','')}")

    output.write_text("\n".join(lines))
    print(f"\n[+] Sandbox trace -> {output}")
    print(f"    Events: {len(all_events)}, Payloads: {len(loadstring_payloads)}, "
          f"HTTP: {len(http_events)}")
    return True


# ── external engines ──────────────────────────────────────────────────────────

def engine_kers(path, output, *, key=None, no_devirt=False, timeout=600) -> bool:
    if not KERS_DEOB.is_file():
        print("[!] kers0nec engine missing")
        print("    git clone https://github.com/caomod2077/Deobfuscator-Luraph-V15 deobfuscator-luraph-v15")
        return False
    node = find_node()
    if not node: print("[!] node not found"); return False
    env = _path_env([BIN_DIR, KERS_DIR/"bin"])
    kers_bin = KERS_DIR/"bin"; kers_bin.mkdir(exist_ok=True)
    luau = find_luau()
    if luau:
        for n in ("luau","luau.exe"):
            src, dst = Path(luau), kers_bin/n
            if src.name == n and not dst.exists():
                try: shutil.copy2(src, dst); os.chmod(dst, 0o755)
                except OSError: pass
    cmd = [node, str(KERS_DEOB), str(path), "-o", str(output)]
    if key:      cmd += ["--key", key]
    if no_devirt: cmd += ["--no-devirt"]
    ok, _ = run(cmd, "kers0nec multi-family (v15/v15.1/SuperFlow/FlowAuth/KeyForge)",
                cwd=KERS_DIR, env=env, timeout=timeout)
    return ok and _output_ok(output)

def engine_luraph_v151(path: Path, output: Path, *, key=None, bsdata0=None,
                       no_cff=False, no_ssa=False, no_dead=False,
                       no_fold=False, timeout=600) -> bool:
    """
    v15.1 / SuperFlow engine — built-in Python module.

    Fixes applied vs. previous revision:
      BUG-A  _Args was missing devirt_rounds, raw, timeout fields that
             the v15 harness reads unconditionally → AttributeError.
      BUG-B  _Job.input was a Path not a str; harness.load_p2d_cache()
             passes it to os.path.* which silently misbehaves on some builds.
      BUG-E  _devirtualize_v151() monkey-patched v15_driver.devirtualize
             to itself, then called v15_driver.devirtualize() — infinite
             recursion.  We now save the original reference before patching.
      BUG-F  v15 driver can call sys.exit() on parse failure; that killed
             the whole deob.py process.  Wrapped in SystemExit catch so we
             fall through to the next engine instead.
      BUG-G  engine_luraph_v151 accepted no_fold kwarg but _Args did not
             store it, silently defaulting to False regardless of the flag.
    """
    if not V151_DRIVER.is_file():
        print("[!] luraph_v15.1 module missing"); return False

    # Ensure both core dirs are importable.
    for _p in (str(CORE_DIR), str(KERS_DIR / "core")):
        if _p not in sys.path:
            sys.path.insert(0, _p)

    try:
        from obfuscators.luraph_v15_1.driver import run as v151_run
    except ImportError as _ie:
        # ImportError path: run the driver as a subprocess instead.
        cmd = [sys.executable, str(V151_DRIVER), str(path), "-o", str(output)]
        if bsdata0:   cmd += ["--bsdata", bsdata0]
        if key:       cmd += ["--key", key]
        ok, _ = run(cmd, "luraph_v15.1 (SuperFlow, subprocess)", cwd=KERS_DIR, timeout=timeout)
        return ok and _output_ok(output)

    # ── _Job: minimal shim matching what harness.py and v15_driver.run() need ──
    class _Job:
        def __init__(self, p, o, a):
            # BUG-B fix: keep str(p) so os.path calls in harness don't choke on Path.
            self.input       = str(p)          # harness.load_p2d_cache(job.input, ...)
            self.source_path = str(p)
            self.source      = Path(p).read_text(errors="replace")
            self.args        = a
            self.outdir      = Path(o).parent
            self.outdir.mkdir(parents=True, exist_ok=True)
            self.debug       = False
            self.obfuscator  = "Luraph v15.1"

        def write(self, p, text, encoding="utf-8"):
            Path(p).write_text(text, encoding=encoding)
            return str(p)

        def wrote(self, p):
            pass  # suppress debug prints

        def path(self, suffix):
            stem = Path(self.input).stem
            return str(self.outdir / (stem + suffix))

        def credit_header(self):
            return ""

        @property
        def trace_path(self):
            return self.path(".trace.lua")

        @property
        def base(self):
            import re as _re
            return _re.sub(r"\.deobf\.luau$|\.luau$", "", self.trace_path)

    # ── _Args: every field the v15 driver / harness reads ────────────────────
    class _Args:
        def __init__(self,
                     key=None, bsdata=None,
                     no_devirt=False, no_hooks=False,
                     budget=30, strings=False, executor=None, max_runs=12,
                     input_text=None, no_fold=False, studio=False, devirt=True,
                     no_cff=False, no_ssa=False, no_dead=False,
                     # BUG-A fix: fields the v15 driver reads unconditionally.
                     devirt_rounds=8, raw=None, timeout=600):
            self.key           = key
            self.bsdata        = bsdata
            self.no_devirt     = no_devirt
            self.no_hooks      = no_hooks
            self.budget        = budget
            self.strings       = strings
            self.executor      = executor
            self.max_runs      = max_runs
            self.input_text    = input_text
            # BUG-G fix: no_fold was accepted by engine fn but never stored.
            self.no_fold       = no_fold
            self.studio        = studio
            self.devirt        = devirt
            self.no_cff        = no_cff
            self.no_ssa        = no_ssa
            self.no_dead       = no_dead
            # BUG-A: previously missing — v15 driver reads these directly.
            self.devirt_rounds = devirt_rounds
            self.raw           = raw
            self.timeout       = timeout

    args = _Args(
        key=key, bsdata=bsdata0,
        no_cff=no_cff, no_ssa=no_ssa, no_dead=no_dead,
        no_fold=no_fold, timeout=timeout,
    )
    job = _Job(path, output, args)

    try:
        # BUG-E fix: _devirtualize_v151 in the real driver module monkey-patches
        # v15_driver.devirtualize to itself, then calls v15_driver.devirtualize()
        # — which is now itself — producing infinite recursion.  Save the original
        # reference before any patch can land, so the call chain terminates.
        try:
            import obfuscators.luraph_v15.driver as _v15drv
            _orig_devirt = _v15drv.devirtualize
        except (ImportError, AttributeError):
            _orig_devirt = None

        result = v151_run(job)

        # Restore original v15 devirt so subsequent calls are not affected.
        if _orig_devirt is not None:
            try:
                _v15drv.devirtualize = _orig_devirt
            except Exception:
                pass

        # Bug 6 fix: v151_run() can return None on a silent driver failure.
        if not result:
            return False
        rp = Path(result)
        return rp.is_file() and rp.stat().st_size > 32

    except SystemExit as e:
        # BUG-F fix: v15 driver calls sys.exit() on parse failure.  Catch it
        # here so we fall through to the next engine instead of killing the
        # entire process.
        print(f"[!] luraph_v15.1 exited ({e.code}); falling through to next engine",
              file=sys.stderr)
        return False
    except (TypeError, OSError) as e:
        print(f"[!] luraph_v15.1 failed: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[!] luraph_v15.1 unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return False


def engine_vm(path, output, version="auto", timeout=300) -> bool:
    if not VM_DEOB.is_file() and not VM_CLI.is_file():
        print("[!] KryptIT engine missing"); return False
    luau = find_luau()
    if not luau: print("[!] luau binary missing"); return False
    env = _path_env([BIN_DIR, VM_BIN])
    if version in ("v15","15","auto") and VM_DEOB.is_file():
        ok, _ = run([sys.executable, str(VM_DEOB), str(path), "-o", str(output),
                     "--obfuscator","luraph_v15"], "KryptIT (v15)", env=env, timeout=timeout)
        if ok and _output_ok(output): return True
    if version in ("v14","14","auto") and VM_CLI.is_file():
        ok, _ = run([sys.executable, str(VM_CLI), str(path), "-o", str(output)],
                    "KryptIT (v14.x)", env=env, timeout=timeout)
        if ok and _output_ok(output): return True
    return False

def engine_node(path, output, timeout=300) -> bool:
    if not NODE_DEOB.is_file(): print("[!] caomod engine missing"); return False
    node = find_node()
    if not node: print("[!] node not found"); return False
    env = _path_env([BIN_DIR])
    node_bin = NODE_DIR/"bin"; node_bin.mkdir(exist_ok=True)
    luau = find_luau()
    if luau:
        for n in ("luau","luau.exe"):
            src, dst = Path(luau), node_bin/n
            if src.name == n and not dst.exists():
                try: shutil.copy2(src, dst); os.chmod(dst, 0o755)
                except OSError: pass
    ok, _ = run([node, str(NODE_DEOB), str(path), "-o", str(output)],
                "caomod v15 (Node)", cwd=NODE_DIR, env=env, timeout=timeout)
    return ok and _output_ok(output)

def engine_unluraph(path, output, timeout=120) -> bool:
    if not UNLURAPH.is_file(): print("[!] unluraph.py missing"); return False
    ok, _ = run([sys.executable, str(UNLURAPH), str(path), "-o", str(output)],
                "unluraph.py (outer-layer fallback)", timeout=timeout)
    return ok and _output_ok(output)


# ── component status ──────────────────────────────────────────────────────────

def show_components():
    print("=" * 64)
    print("  Luraph Deobfuscation Suite v3 — Component Status")
    print("=" * 64)
    def row(name, ok, detail=""):
        print(f"  [{'OK ' if ok else ' --'}] {name}")
        if detail: print(f"         {detail}")

    row("Python", True, sys.version.split()[0])
    row("Node.js 18+", bool(find_node()), find_node() or "install Node.js 18+")
    row("luau binary", bool(find_luau()), find_luau() or "put in bin/  -> luau-lang/luau releases")
    row("runtime/envlog.luau (built-in sandbox)", SANDBOX.is_file(), str(SANDBOX))
    row("core/ipc_repl.py",         (CORE_DIR/"ipc_repl.py").is_file(),   str(CORE_DIR/"ipc_repl.py"))
    row("core/static_unpack.py",    (CORE_DIR/"static_unpack.py").is_file(), str(CORE_DIR/"static_unpack.py"))
    row("core/detect.py",           (CORE_DIR/"detect.py").is_file(),       str(CORE_DIR/"detect.py"))
    row("unluraph.py",              UNLURAPH.is_file(),                      str(UNLURAPH))
    kers_ok = KERS_DEOB.is_file()
    row("kers0nec multi-family (v15/v15.1/SuperFlow)", kers_ok,
        str(KERS_DEOB) if kers_ok else
        "git clone https://github.com/caomod2077/Deobfuscator-Luraph-V15 deobfuscator-luraph-v15")
    row("luraph_v15.1 SuperFlow module (built-in)", V151_DRIVER.is_file(),
        str(V151_DRIVER) if V151_DRIVER.is_file() else "v15.1 driver missing")
    vm_ok = VM_DEOB.is_file() or VM_CLI.is_file()
    row("KryptIT VM deob (v14.7–v15)", vm_ok,
        str(VM_DEOB if VM_DEOB.is_file() else VM_CLI) if vm_ok else
        "git clone https://github.com/KryptIT/luraph-v15-v14.x-deobfuscator luraph-v15-deob-krypt")
    row("caomod2077 (Node)", NODE_DEOB.is_file(), str(NODE_DEOB) if NODE_DEOB.is_file() else "missing")

    print()
    print("  Engine priority (auto):  luraph_v15.1 -> kers -> KryptIT -> caomod -> sandbox -> unluraph")
    print("  Built-in sandbox: always available when luau binary is present")
    print("  v15.1/SuperFlow:  --engine kers  (best) or  --engine sandbox")
    print("  FlowAuth:         --engine kers --key YOUR-KEY")
    print()
    print("  input/   -> obfuscated scripts")
    print("  output/  -> deobfuscated results")
    print()


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Luraph Deobfuscation Suite v3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Engines:  auto | luraph_v15.1 | kers | v15 | v14 | node | sandbox | unluraph\n"
            "v15.1/SuperFlow: --engine luraph_v15.1  (dedicated) or --engine kers\n"
            "SuperFlow seed:  --bsdata '<_bsdata0_blob>'  (auto-extracted if present)\n"
            "FlowAuth:        --engine kers --key YOUR-KEY\n"
            "Built-in trace:  --engine sandbox  (just needs luau binary)"
        ),
    )
    ap.add_argument("input",         nargs="?",     help=".lua/.luau to deobfuscate")
    ap.add_argument("-o","--output",               help="output path")
    ap.add_argument("--engine",      default="auto",
                    help="force engine: auto|luraph_v15.1|kers|v15|v14|node|sandbox|unluraph")
    ap.add_argument("--key",                       help="FlowAuth / KeyForge script key")
    ap.add_argument("--bsdata",                    help="manual _bsdata0 blob (SuperFlow)")
    ap.add_argument("--rounds",      type=int, default=3,
                    help="sandbox trace rounds (default 3)")
    ap.add_argument("--no-devirt",   action="store_true",
                    help="trace-only, skip full devirtualization")
    ap.add_argument("--timeout",     type=int, default=600,
                    help="per-engine timeout in seconds")
    ap.add_argument("--no-cff",      action="store_true",
                    help="skip CFF de-flattening on lifted output")
    ap.add_argument("--no-ssa",      action="store_true",
                    help="skip SSA register renaming on lifted output")
    ap.add_argument("--no-fold",     action="store_true",
                    help="skip constant folding on lifted output")
    ap.add_argument("--no-dead",     action="store_true",
                    help="skip dead-block elimination on lifted output")
    ap.add_argument("--detect",      action="store_true",  help="fingerprint and exit")
    ap.add_argument("--sandbox",     action="store_true",  help="force built-in sandbox engine")
    ap.add_argument("--unpack",      action="store_true",  help="static unpack only")
    ap.add_argument("--components",  action="store_true",  help="component status board")
    ap.add_argument("--auto",        action="store_true",  help="use latest .lua in input/")
    args = ap.parse_args()

    ensure_dirs()

    if args.components:
        show_components()
        return 0

    if args.auto or args.input is None:
        latest = find_latest_lua()
        if latest is None:
            print(f"[!] No .lua/.luau in {INPUT_DIR}")
            show_components()
            return 1
        input_path = latest
    else:
        input_path = Path(args.input)
        if not input_path.is_file():
            print(f"[!] Not found: {input_path}")
            return 1

    stem        = input_path.stem
    output_path = Path(args.output) if args.output else OUTPUT_DIR / f"{stem}.deob.lua"

    print("=" * 64)
    print("  Luraph Deobfuscation Suite v3")
    print("=" * 64)
    print(f"  Input  : {input_path}")
    print(f"  Output : {output_path}")
    print(f"  Engine : {args.sandbox and 'sandbox' or args.engine}")
    if args.key:   print(f"  Key    : {'*'*min(len(args.key),8)}...")
    if args.bsdata: print(f"  bsdata0: {args.bsdata[:32]}...")
    print()

    if args.detect:
        run_detect(input_path)
        return 0

    if args.unpack:
        ok = run_static_unpack(input_path, output_path)
        return 0 if ok else 1

    engine  = "sandbox" if args.sandbox else args.engine.lower().strip()
    timeout = args.timeout
    success = False

    def _try(fn, *a, **kw) -> bool:
        nonlocal success
        if fn(*a, **kw):
            success = True
            return True
        return False

    if engine == "auto":
        # v15.1 / SuperFlow gets the dedicated module first.
        if not _try(engine_luraph_v151, input_path, output_path,
                    key=args.key, bsdata0=args.bsdata,
                    no_cff=args.no_cff, no_ssa=args.no_ssa,
                    no_fold=args.no_fold, no_dead=args.no_dead,
                    timeout=timeout):
            if not _try(engine_kers, input_path, output_path,
                        key=args.key, no_devirt=args.no_devirt, timeout=timeout):
                if not _try(engine_vm, input_path, output_path, "v15", timeout):
                    if not _try(engine_vm, input_path, output_path, "v14", timeout):
                        if not _try(engine_node, input_path, output_path, timeout):
                            if not _try(engine_sandbox, input_path, output_path,
                                        bsdata0=args.bsdata, rounds=args.rounds,
                                        timeout=min(timeout,90), no_devirt=args.no_devirt):
                                _try(engine_unluraph, input_path, output_path)

    elif engine == "luraph_v15.1":
        _try(engine_luraph_v151, input_path, output_path,
             key=args.key, bsdata0=args.bsdata,
             no_cff=args.no_cff, no_ssa=args.no_ssa,
             no_fold=args.no_fold, no_dead=args.no_dead,
             timeout=timeout)

    elif engine == "kers":
        _try(engine_kers, input_path, output_path,
             key=args.key, no_devirt=args.no_devirt, timeout=timeout)

    elif engine in ("v15","15"):
        if not _try(engine_vm, input_path, output_path, "v15", timeout):
            print("[!] KryptIT v15 failed — trying built-in sandbox")
            _try(engine_sandbox, input_path, output_path,
                 bsdata0=args.bsdata, rounds=args.rounds, timeout=90)

    elif engine in ("v14","14"):
        _try(engine_vm, input_path, output_path, "v14", timeout)

    elif engine == "node":
        _try(engine_node, input_path, output_path, timeout)

    elif engine == "sandbox":
        _try(engine_sandbox, input_path, output_path,
             bsdata0=args.bsdata, rounds=args.rounds,
             timeout=min(timeout,120), no_devirt=args.no_devirt)

    elif engine == "unluraph":
        _try(engine_unluraph, input_path, output_path)

    else:
        print(f"[!] Unknown engine: {engine}")
        return 1

    if success:
        size = output_path.stat().st_size
        print(f"\n[+] Done -> {output_path}  ({size:,} bytes)")
        return 0

    print("\n[!] All selected engines failed.")
    print()
    print("  Tips:")
    print("    python deob.py --components")
    print("    python deob.py --detect yourfile.lua")
    print("    git clone https://github.com/caomod2077/Deobfuscator-Luraph-V15 deobfuscator-luraph-v15")
    print("    python deob.py --engine sandbox --bsdata '<bsdata0_blob>' yourfile.lua")
    print("    python deob.py --engine kers --key YOUR-KEY yourfile.lua  (FlowAuth)")
    print("    python deob.py --timeout 900 big.lua  (large scripts)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
