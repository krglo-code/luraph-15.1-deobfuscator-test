#!/usr/bin/env python3
"""
vmmap.py — SuperFlow VM Mapper + Opcode Map builder for Luraph v15.1.

Extends the original SuperFlow structural mapper with:
  • build_opcode_map()  — runs opclassify on the source and returns the
                          {opcode_id: canonical_name} table the devirt engine
                          needs.  This is the bridge between the heuristic
                          classifier and the VM lifting pipeline.
  • OpcodeMap           — typed wrapper around the raw dict; also persists
                          to / loads from JSON so maps can be cached between
                          runs and manually patched by Sam for unknowns.
  • map_v151_dispatch   — unchanged: scans for SuperFlow structure markers.
  • find_bsdata_slots   — unchanged.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .opclassify import (
    build_opcode_map as _classify_raw,
    classify_script,
    print_classification_report,
    ClassifyResult,
)

# ── SuperFlow structural markers (original) ──────────────────────────────────

_DISPATCH_RE = re.compile(
    r"LPH_ENCSTR2\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE
)
_BSDATA_TABLE_RE = re.compile(
    r"_bsdata0\s*=\s*(\{.*?\})", re.DOTALL
)


def map_v151_dispatch(source: str) -> dict:
    """
    Scan source for v15.1 SuperFlow dispatch structures. Returns a dict with:
      • encstr2_tokens: list of LPH_ENCSTR2 string tokens
      • bsdata_table: raw _bsdata0 table literal if inline
      • has_superflow: bool
    """
    info = {
        "has_superflow": False,
        "encstr2_tokens": [],
        "bsdata_table": None,
    }

    if _DISPATCH_RE.search(source) or "_bsdata0" in source:
        info["has_superflow"] = True

    info["encstr2_tokens"] = _DISPATCH_RE.findall(source)

    m = _BSDATA_TABLE_RE.search(source)
    if m:
        info["bsdata_table"] = m.group(1)

    return info


def find_bsdata_slots(source: str) -> list[str]:
    """Find all _bsdataN slot assignments in source."""
    return re.findall(r"_bsdata\d+\s*=", source)


# ── OpcodeMap ────────────────────────────────────────────────────────────────

@dataclass
class OpcodeMap:
    """
    {opcode_id (int): canonical_name (str)} plus confidence metadata.

    Usage:
        omap = OpcodeMap.from_source(source)
        name = omap.get(37)          # "MOVE", "CALL", ... or "UNKNOWN_37"
        omap.save(Path("map.json"))  # persist for manual patching
        omap2 = OpcodeMap.load(Path("map.json"))
    """
    entries: dict[int, str] = field(default_factory=dict)
    confidence: dict[int, float] = field(default_factory=dict)
    total_handlers: int = 0
    classified: int = 0
    source_hash: str = ""

    def get(self, opcode_id: int, default: Optional[str] = None) -> str:
        """Return canonical name or a stable UNKNOWN_N placeholder."""
        if opcode_id in self.entries:
            return self.entries[opcode_id]
        return default if default is not None else f"UNKNOWN_{opcode_id}"

    def __contains__(self, opcode_id: int) -> bool:
        return opcode_id in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def coverage(self) -> float:
        if not self.total_handlers:
            return 0.0
        return self.classified / self.total_handlers

    def unknown_ids(self) -> list[int]:
        """Return opcode IDs that weren't classified."""
        # We don't store the full handler list here; return IDs with low conf.
        return [oid for oid, conf in self.confidence.items() if conf < 0.5]

    def patch(self, opcode_id: int, canonical: str) -> None:
        """Manually override one entry (e.g. after inspecting an unknown)."""
        self.entries[opcode_id] = canonical
        self.confidence[opcode_id] = 1.0

    def save(self, path: Path) -> None:
        """Persist to JSON for caching and manual editing."""
        data = {
            "entries": {str(k): v for k, v in self.entries.items()},
            "confidence": {str(k): v for k, v in self.confidence.items()},
            "total_handlers": self.total_handlers,
            "classified": self.classified,
            "source_hash": self.source_hash,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "OpcodeMap":
        """Load from a saved JSON file."""
        data = json.loads(path.read_text(encoding="utf-8"))
        om = cls()
        om.entries = {int(k): v for k, v in data.get("entries", {}).items()}
        om.confidence = {int(k): v for k, v in data.get("confidence", {}).items()}
        om.total_handlers = data.get("total_handlers", 0)
        om.classified = data.get("classified", 0)
        om.source_hash = data.get("source_hash", "")
        return om

    @classmethod
    def from_source(cls, source: str, min_confidence: float = 0.35) -> "OpcodeMap":
        """
        Classify all VM handlers in source and return an OpcodeMap.

        This is the primary entry point for the devirt engine.
        """
        import hashlib
        src_hash = hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:16]

        results: dict[int, ClassifyResult] = classify_script(
            source, min_confidence=0.0  # keep all so total_handlers is accurate
        )

        om = cls()
        om.source_hash = src_hash
        om.total_handlers = len(results)

        for oid, result in results.items():
            if result.confidence >= min_confidence:
                om.entries[oid] = result.canonical
                om.confidence[oid] = result.confidence
                om.classified += 1
            else:
                # Still record the confidence for debugging
                om.confidence[oid] = result.confidence

        return om

    @classmethod
    def from_cache_or_source(cls, source: str, cache_dir: Optional[Path] = None,
                              min_confidence: float = 0.35) -> "OpcodeMap":
        """
        Load cached opcode map if the source hash matches; otherwise classify
        and save to cache.

        cache_dir defaults to /tmp/luraph_omap_cache/.
        """
        import hashlib
        src_hash = hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:16]

        if cache_dir is None:
            cache_dir = Path("/tmp/luraph_omap_cache")
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"omap_{src_hash}.json"

        if cache_file.is_file():
            try:
                om = cls.load(cache_file)
                if om.source_hash == src_hash:
                    return om
            except Exception:
                pass

        om = cls.from_source(source, min_confidence=min_confidence)
        try:
            om.save(cache_file)
        except OSError:
            pass
        return om


def build_opcode_map(source: str, min_confidence: float = 0.35) -> OpcodeMap:
    """
    Top-level convenience: classify all VM handler bodies in source and
    return a ready-to-use OpcodeMap.

    This is what devirt.py calls before walking the VM proto table.
    """
    return OpcodeMap.from_source(source, min_confidence=min_confidence)
