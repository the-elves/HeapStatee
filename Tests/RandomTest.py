from mstate import *
h = HeapState(0x0)
x = h.malloc(100)
y = h.malloc(20)
h.free(x)
z = h.malloc(10)
h.dump()