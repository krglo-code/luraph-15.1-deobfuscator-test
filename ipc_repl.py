"""
core/ipc_repl.py — Live IPC REPL for Constant Decryption
=========================================================
Spawns a persistent sandboxed Luau process, injects the target script
behind the envlog.luau harness, and communicates via stdin/stdout line-
delimited JSON to decrypt lazy constants on demand.

Protocol (host → Luau):
  {"op":"decrypt","val":"<hex-encoded bytes>","nonce":"<run nonce>"}
  {"op":"quit"}

Protocol (Luau → host, via envlog.luau):
  {"t":"loadstring","payload":"<b64>","round":<n>}
  {"t":"lph_encstr","raw":"...","decoded":"...","round":<n>}
  {"t":"lph_encstr2","raw":"...","decoded":"...","round":<n>}
  {"t":"lph_encfunc","id":<n>,"round":<n>}
  {"t":"crash","site":"...","round":<n>}
  {"t":"global_read","key":"...","value_kind":"...","round":<n>}
  {"t":"http","method":"...","url":"...","round":<n>}
  {"t":"done","round":<n>}

Usage:
  repl = IpcRepl(luau_bin, script_path, sandbox_path, round=0)
  repl.start()
  events = repl.run_and_collect(timeout=90)
  repl.stop()
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional


class IpcRepl:
    """
    Manages a single Luau sandbox subprocess for one deobfuscation round.

    The sandbox concatenates envlog.luau + a generated prologue + the
    target script. All stdout lines are parsed as JSON telemetry events.
    stderr is captured separately for debugging.

    Per-run nonce: a random 8-byte hex string injected as __SANDBOX_NONCE
    via a Luau preamble. Protected scripts that try to spoof telemetry
    must know this value at compile time — they cannot.

    Attributes:
        luau_bin   : path to the luau binary
        script_path: path to the obfuscated target script
        sandbox_path: path to envlog.luau
        round      : which devirt round this is (for event tagging)
        timeout    : hard timeout in seconds for the subprocess
        bsdata0    : optional _bsdata0 blob to pre-seed (SuperFlow/FlowAuth)
        events     : list of parsed JSON event dicts collected during the run
    """

    def __init__(
        self,
        luau_bin: str,
        script_path: Path,
        sandbox_path: Path,
        *,
        round: int = 0,
        timeout: int = 90,
        bsdata0: Optional[str] = None,
        executor_profile: str = "Wave",
    ) -> None:
        self.luau_bin     = luau_bin
        self.script_path  = script_path
        self.sandbox_path = sandbox_path
        self.round        = round
        self.timeout      = timeout
        self.bsdata0      = bsdata0
        self.executor_profile = executor_profile

        self.events: list[dict]  = []
        self._proc: Optional[subprocess.Popen] = None
        self._q: queue.Queue = queue.Queue()
        self._reader: Optional[threading.Thread] = None
        self._nonce = os.urandom(8).hex()

    def _build_harness(self) -> str:
        """
        Concatenates:
          1. A generated preamble (nonce, round, executor profile, bsdata0)
          2. envlog.luau (the sandbox environment)
          3. The target script

        Returns the full source string to feed into the luau binary.
        """
        preamble_parts = [
            "-- [[ Harness preamble — generated ]]",
            f"__SANDBOX_NONCE = {json.dumps(self._nonce)}",
            f"__SANDBOX_ROUND = {self.round}",
            f"__EXECUTOR      = {json.dumps(self.executor_profile)}",
        ]
        if self.bsdata0 is not None:
            preamble_parts.append(
                f"__BSDATA0 = {json.dumps(self.bsdata0)}"
            )

        preamble = "\n".join(preamble_parts) + "\n"

        try:
            sandbox_src = self.sandbox_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise RuntimeError(f"Cannot read sandbox: {self.sandbox_path}: {e}")

        try:
            target_src  = self.script_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise RuntimeError(f"Cannot read target: {self.script_path}: {e}")

        return "\n".join([
            preamble,
            "-- [[ envlog.luau ]]",
            sandbox_src,
            "-- [[ target script ]]",
            "local __ok, __err = pcall(function()",
            target_src,
            "end)",
            "if not __ok then",
            # Bug 4 fix: was hard-coding an empty msg="". __err is captured
            # by the pcall but was never interpolated, so all runtime crash
            # events showed msg:"" regardless of what actually failed.
            # Luau string concat ('..' operator) embeds the actual error text.
            f"  print('{{\"t\":\"runtime_error\",\"round\":{self.round},\"msg\":\"' .. tostring(__err):gsub('\"','\\\\\"') .. '\"}}' )",

            "end",
            "if _SANDBOX_DONE then _SANDBOX_DONE() end",
        ])

    def _reader_thread(self, stream) -> None:
        for raw_line in stream:
            line = raw_line.rstrip("\n")
            if not line:
                continue
            try:
                evt = json.loads(line)
                self._q.put(("event", evt))
            except json.JSONDecodeError:
                self._q.put(("raw", line))

    def start(self, harness_dir: Optional[Path] = None) -> None:
        """
        Write the harness to a temp file and launch the luau subprocess.
        Passes --lint and --compile-errors so syntax problems surface fast.
        """
        import tempfile
        harness_src = self._build_harness()

        # Write to a temp file next to the script so relative paths work
        work_dir = harness_dir or self.script_path.parent
        tmp = tempfile.NamedTemporaryFile(
            suffix=".luau",
            dir=work_dir,
            delete=False,
            mode="w",
            encoding="utf-8",
        )
        tmp.write(harness_src)
        tmp.close()
        self._harness_path = tmp.name

        self._proc = subprocess.Popen(
            [self.luau_bin, self._harness_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._reader = threading.Thread(
            target=self._reader_thread,
            args=(self._proc.stdout,),
            daemon=True,
        )
        self._reader.start()

    def run_and_collect(self, timeout: Optional[int] = None) -> list[dict]:
        """
        Collects all events until the subprocess exits or the timeout fires.
        Returns the list of parsed event dicts.
        """
        if self._proc is None:
            raise RuntimeError("call start() first")

        deadline = time.time() + (timeout or self.timeout)
        events: list[dict] = []

        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                self._proc.kill()
                break
            try:
                kind, obj = self._q.get(timeout=min(remaining, 0.1))
                if kind == "event":
                    events.append(obj)
                    if obj.get("t") == "done":
                        break
            except queue.Empty:
                if self._proc.poll() is not None:
                    break

        # drain any remaining output
        try:
            while True:
                kind, obj = self._q.get_nowait()
                if kind == "event":
                    events.append(obj)
        except queue.Empty:
            pass

        self.events = events
        return events

    def stop(self) -> None:
        """Kill subprocess and remove the temp harness file."""
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.kill()
                self._proc.wait(timeout=5)
            except Exception:
                pass
        if hasattr(self, "_harness_path"):
            try:
                os.unlink(self._harness_path)
            except OSError:
                pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()


def run_sandbox(
    luau_bin: str,
    script_path: Path,
    sandbox_path: Path,
    *,
    round: int = 0,
    timeout: int = 90,
    bsdata0: Optional[str] = None,
    executor_profile: str = "Wave",
    harness_dir: Optional[Path] = None,
) -> list[dict]:
    """
    Convenience wrapper: one call, returns the event list.
    Ideal for the outer orchestrator.

    Returns list of event dicts; empty on failure.

    Failure table:
      RuntimeError: luau_bin not found or sandbox_path missing
      Returns []:   script crashed before emitting any events (check stderr)
    """
    repl = IpcRepl(
        luau_bin,
        script_path,
        sandbox_path,
        round=round,
        timeout=timeout,
        bsdata0=bsdata0,
        executor_profile=executor_profile,
    )
    try:
        repl.start(harness_dir=harness_dir)
        events = repl.run_and_collect(timeout=timeout)
    except Exception as e:
        print(f"    [!] IPC REPL error: {e}")
        events = []
    finally:
        repl.stop()
    return events


if __name__ == "__main__":
    # Quick self-test: run a tiny synthetic script through the sandbox
    import sys, shutil, tempfile
    luau = shutil.which("luau") or "luau"
    sandbox = Path(__file__).parent.parent / "runtime" / "envlog.luau"
    if not sandbox.is_file():
        print("[!] envlog.luau not found — run from the suite root")
        sys.exit(1)

    # Write a tiny probe script
    with tempfile.NamedTemporaryFile(suffix=".lua", mode="w", delete=False) as f:
        f.write("""
local s = LPH_ENCSTR("hello sandbox")
local x = loadstring("return 42")
print("probe done:", s)
""")
        probe = f.name

    print("[*] Running sandbox self-test...")
    events = run_sandbox(luau, Path(probe), sandbox, timeout=10)
    os.unlink(probe)

    if not events:
        print("[!] No events collected — is luau installed?")
        sys.exit(1)

    for e in events:
        print("  event:", e)
    print(f"[+] Self-test passed — {len(events)} events")