from HeapModel.mstate import HeapState, SIZE_SZ, Chunk, MALLOC_ALLIGNMENT, MALLOC_ALIGN_MASK


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

def possible_malloc_concretizations(heap: HeapState):
    possible_allocation_sizes = []
    for b in heap.fastbin:
        if len(b) > 0:
            possible_allocation_sizes.append(heap.size2request(b[0].size))
    for b in heap.smallbin:
        if len(b) > 0:
            possible_allocation_sizes.append(heap.size2request(b[-1].size))
    for b in heap.largebin:
        if len(b) > 0:
            current_size = -1
            for c in b:
                if current_size != c.size:
                    current_size = c.size
                    possible_allocation_sizes.append(heap.size2request(c.size))
    maxreq = max(possible_allocation_sizes)
    top_req = (maxreq + MALLOC_ALLIGNMENT) & MALLOC_ALIGN_MASK
    possible_allocation_sizes.append(top_req)
    return possible_allocation_sizes
