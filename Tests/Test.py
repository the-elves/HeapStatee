from HeapModel.mstate import HeapState

h = HeapState(0x2000000)

print("Initial")
h.dump()

p1 = h.malloc(10)
p1c = h.get_chunk_by_address(p1)

print("after Malloc 10")
h.dump()

# p2 = h.malloc(256)
# p2c = h.get_chunk_by_address(p2)
#
# print("after Malloc 256")
# h.dump()

g = h.malloc(20)
print("after malloc 20")
h.dump()

# h.free(p2)
#
# print("after free 256")
# h.dump()

p3 = h.realloc(p1, p1c.size, h.request2size(128))

print("after realloc 128")
h.dump()