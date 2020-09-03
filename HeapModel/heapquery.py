from HeapModel.mstate import HeapState, SIZE_SZ, Chunk


def addr_in_heap(addr, heap: HeapState):
    if heap.startAddress <= addr < heap.top.address + heap.top.size:
        return True


def chunk_containing_address(addr, heap: HeapState) -> Chunk:
    fst = heap.get_chunk_by_address(heap.startAddress)
    while fst:
        if fst.address <= addr < fst.address + fst.size:
            return fst
        fst = heap.get_chunk_at_offset(fst.address, fst.size)
    return None

def metadata_cloberring(addr, heap: HeapState):
    c = chunk_containing_address(addr, heap)
    prev_chunk = chunk_containing_address(c.address-c.prev_size, heap)
    if not prev_chunk.free:
        if c.address + SIZE_SZ <= addr < c.address + 2 * SIZE_SZ:
            return True
    else:
        if c.address  <= addr < c.address + 2 * SIZE_SZ:
            return True
    return False

def write_in_free_chunk(addr, heap: HeapState):
    c = chunk_containing_address(addr, heap)
    prev_chunk = chunk_containing_address(c.address-c.prev_size, heap)
    if not prev_chunk.free:
        if c.address  <= addr < c.address + SIZE_SZ:
            return False
    if c.free:
        return True