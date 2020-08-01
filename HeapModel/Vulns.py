class Vulnerability(Exception):
    def __init__(self, msg, address):
        self.addr = address
        self.msg = msg

class DoubleFreeVuln(Vulnerability):
    pass