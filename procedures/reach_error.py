import angr
import logging
from utils.utils import radar_breakpoint
vl = logging.getLogger('vuln_logger')
class reach_error(angr.sim_procedure):
    def run(self):
        vl.log("reach error reached")
        print("reach error reached")
        radar_breakpoint()