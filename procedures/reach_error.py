import angr
import logging
from utils.utils import radar_breakpoint, dump_callstack
vl = logging.getLogger('vuln_logger')
class reach_error(angr.SimProcedure):
    def run(self):
        vl.warning("reach error reached")
        print("reach error reached")
        print(dump_callstack(self.state))
        
        exit()

class __VERIFIER_error(angr.SimProcedure):
    def run(self):
        vl.warning("__VERIFIER_error reached")
        print("__VERIFIER_error reached")
        # radar_breakpoint()
        exit()
