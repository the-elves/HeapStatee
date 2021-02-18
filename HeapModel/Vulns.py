from utils.utils import *
import pdb

class Vulnerability(Exception):
    def __init__(self, msg, address):
        self.addr = address
        self.msg = msg

class DoubleFreeVuln(Vulnerability):
    def __init__(self, msg, address):
        self.addr= address
        self.msg = msg
#        pdb.set_trace()
class ChunkNotFoundException(Vulnerability):
    pass
