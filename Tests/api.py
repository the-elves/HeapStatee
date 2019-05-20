from mstate import *

h = HeapState(0x00)
def create_user():
    h.malloc(110)
    h.malloc(39)
    h.free(52)

def createAddress():
    