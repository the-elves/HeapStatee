from HeapModel.mstate import HeapState, SIZE_SZ, Chunk, MALLOC_ALLIGNMENT, MALLOC_ALIGN_MASK
from HeapModel.Vulns import ChunkNotFoundException
import pdb

def mem_leak(h:HeapState):
    return len(h.allocated_chunks) > 0

def is_consistent(h:HeapState):
    current_chunk = h.get_chunk_by_address(h.startAddress)
    allchunks = h.get_all_chunks()
    prev_size = 0
    # for c in allchunks:
    #     print('from consistent')
    #     c.dump_chunk()
    #     if c.address == 0x7001a90:
    #         pdb.set_trace()
    #         break
    while(current_chunk is not None):
        if current_chunk not in allchunks:
            return False
        if current_chunk.prev_size != prev_size:
            return False
        allchunks.remove(current_chunk)
        prev_size = current_chunk.size
        current_chunk = h.get_chunk_by_address(current_chunk.address+current_chunk.size)
    if len(allchunks) > 0:
        return False
    return True

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

def fastbin_chunk(chunk, heap):
    for b in heap.fastbin:
        if chunk in b:
            return True
    return False

def access_in_free_chunk(addr, heap: HeapState):
    c = chunk_containing_address(addr, heap)
    if c is None:
        raise(ChunkNotFoundException("Chunk for address {:x} not found".format(addr)))
    prev_chunk = chunk_containing_address(c.address-c.prev_size, heap)
    if not prev_chunk.free:
        if c.address  <= addr < c.address + SIZE_SZ:
            return False
    if c.free or fastbin_chunk(c, heap):
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

def possible_free_concretizations(heap: HeapState):
    possible_addresses = []
    chunk = heap.get_chunk_by_address(heap.startAddress)
    while chunk is not None:
        possible_addresses.append(chunk.address + 2 * SIZE_SZ)
        chunk = heap.get_chunk_at_offset(chunk.address, chunk.size)
    return possible_addresses
