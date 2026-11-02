# Luraph v15.1 / SuperFlow devirt module
# Full pipeline: opcode classification → symexec constant recovery →
# VM proto walking → IR emission → SSA + CFF + fold + dead-elim lift.
from .driver import run, devirtualize
from .devirt import (SuperFlowDevirt, extract_bsdata0, seed_sandbox,
                     finish_text, V151Devirt, VMProtoWalker)
from .vmmap  import map_v151_dispatch, find_bsdata_slots, build_opcode_map, OpcodeMap
from .cff    import deflaten, CFFBlock, CFFResult
from .lifter import lift, LiftResult
from .opclassify import classify_script, build_opcode_map as classify_opcode_map
from .symexec import SymbolicExecutor, ConstantMap, recover_and_apply

__all__ = [
    "run", "devirtualize",
    "SuperFlowDevirt", "extract_bsdata0", "seed_sandbox", "finish_text",
    "V151Devirt", "VMProtoWalker",
    "map_v151_dispatch", "find_bsdata_slots", "build_opcode_map", "OpcodeMap",
    "deflaten", "CFFBlock", "CFFResult",
    "lift", "LiftResult",
    "classify_script", "classify_opcode_map",
    "SymbolicExecutor", "ConstantMap", "recover_and_apply",
]
