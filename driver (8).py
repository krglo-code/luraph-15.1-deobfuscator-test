"""Shim: load driver from the luraph_v15.1 directory."""
import sys as _sys
# Trigger the package __init__ to load all real modules if not done yet.
import importlib as _il
_pkg = _il.import_module("obfuscators.luraph_v15_1")
# Now re-export everything from the real module.
_real = _sys.modules["obfuscators.luraph_v15_1.driver"]
globals().update({k: v for k, v in vars(_real).items() if not k.startswith("__")})
