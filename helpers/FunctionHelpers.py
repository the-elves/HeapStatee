import angr
from angr.analyses.cfg.cfg_base import Function
angr.analyses.CFG
from typing import List

def get_callstack(cfg: angr.analyses.CFGFast, state: angr.SimState) -> List[str]:
    callstr = []
    for frame in state.callstack:
       callstr.append(get_function_name(cfg, frame.func_addr))
    return callstr


def get_function(cfg: angr.analyses.CFGFast, addr: int) -> Function:
    return cfg.kb.functions.ceiling_func(addr)
    
def get_function_name(cfg, addr) -> str:
    fun = get_function(cfg, addr)
    if not fun:
        return "<Unidentified function>"
    else:
        return fun.name