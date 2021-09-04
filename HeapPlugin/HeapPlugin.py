from copy import deepcopy
from angr import SimStatePlugin, SimProcedure, SimState
from angr.calling_conventions import SimCCSystemVAMD64
from angr.engines import SimSuccessors
from HeapModel.mstate import HeapState, SIZE_SZ, MIN_SIZE
from HeapModel.Vulns import *
from HeapModel.heapquery import *
from utils.utils import *
from utils import utils 
import claripy
import logging
import pdb
import sys

l = logging.getLogger('heap_analysis')
vl = logging.getLogger('vuln_logger');

MAX_MALLOC_SIZE = 1<<30


class HeapPlugin(SimStatePlugin):
    # TODO merge and widen
    # def merge(self, _others, _merge_conditions, _common_ancestor=None):
    #     pass

    def __init__(self, h=None, startingAddress = 0):
        super().__init__()
        if (h is None):
            self.heap_state = HeapState(startingAddress)
        else:
            self.heap_state = h
        self.rands = []

    def set_heap(self, h):
        self.heap_state = h

    def print_heap(self):
        self.heap_state.dump()

    def __get_state__(self):
        return self.heap_state


    def __set_state(self, stored_heap):
        self.heap_state = stored_heap
        
        

    @SimStatePlugin.memo
    def copy(self, memo):
        heap_copy = deepcopy(self.heap_state)
        rands_copy = deepcopy(self.rands)
        new_heap_plugin = HeapPlugin(h = heap_copy)
        new_heap_plugin.rands = rands_copy
        return new_heap_plugin


class Malloc(SimProcedure):
    i = 0
    def run(self, size):
        if(utils.DEBUG):
            debug_dump(self.state, "== Before Malloc ==")
        s = self.state.solver.eval(size)
        if s > MAX_MALLOC_SIZE:
            return 0
        hs = self.state.my_heap.heap_state
        rip = self.state.solver.eval(self.state.regs.rip)
        print(f'rip {rip:x} malloc requested {Malloc.i} with requst_size {s}, allocated size {hs.request2size(s)}, heap state before')
        # hs.dump()
        try:
            addr = hs.malloc(s)
            if(not is_consistent(hs)):
                inconsistent_breakpoint()
                # pdb.set_trace()
        except Vulnerability as V:
            print(V.msg, V.addr)
            l.warning(V.msg + " @ " + str(V.addr))
            vl.warning('vl raised warning', V.msg + " @ " + str(V.addr))
            dump_concretized_file(self.state)
        if(utils.DEBUG):
            debug_dump(self.state, "== After Malloc ==")
        print(f'rip {rip:x} malloc called {Malloc.i} with requst_size {s}, allocated size {hs.request2size(s)}, allocated at 0x{addr:x}')
        Malloc.i += 1
        # hs.dump()
        print(self.state.callstack)
        
        return addr + 2*SIZE_SZ

class Calloc(SimProcedure):
    i = 0
    
    def run(self, size, num):
        if(utils.DEBUG):
            debug_dump(self.state, "== Before Calloc ==")
        s = self.state.solver.eval(size)
        n = self.state.solver.eval(num)
        hs = self.state.my_heap.heap_state
        rip = self.state.solver.eval(self.state.regs.rip)
        print(f'rip {rip:x} calloc requested {Calloc.i} {n} objects with with size {hs.request2size(s)} heap state before call: ')
        # hs.dump()
        try:
            addr = hs.malloc(n*s)
            self.memset_zero(addr, n*s)
            if(not is_consistent(hs)):
                print("heap state inconsistent")
                pass
                # pdb.set_trace()
        except Vulnerability as V:
            print(V.msg, V.addr)
            l.warning(V.msg + " @ " + str(V.addr))
            vl.warning('vlraised warning', V.msg + " @ " + str(V.addr))
            dump_concretized_file(self.state)
        print(f'rip {rip:x} calloc called {Calloc.i} with size {hs.request2size(s)}, allocated at 0x{addr:x}')
        if(utils.DEBUG):
            debug_dump(self.state, "== After Calloc ==")
        Malloc.i += 1
        #hs.dump()
        return addr + 2*SIZE_SZ

    def memset_zero(self, addr, size):
        s = self.state
        hs = s.my_heap.heap_state
        write_start = addr+2*SIZE_SZ
        write_size = hs.request2size(size)-SIZE_SZ
        for l in range(write_start, write_start + write_size):
            s.mem[l].uint8_t = 0
    

class Realloc(SimProcedure):
    i = 0
    def run(self, soldmem, sbytes):
        if(utils.DEBUG):
            debug_dump(self.state, "== Before Realloc ==")
        oldmem = self.state.solver.eval(soldmem)
        nbytes = self.state.solver.eval(sbytes)
        hs = self.state.my_heap.heap_state
        oldp = oldmem - 2 * SIZE_SZ
        nb = hs.request2size(nbytes)
        print(f'realloc requested {Realloc.i} with requested size:0x{nbytes:x}, requested chunksize:0x{nb:x}@0x{oldmem:x}(current chunk) heap state before call: ')
        # Handle corner cases (free and simple malloc)
        if nbytes == 0 and oldmem != 0:
            hs.free(oldp)
            if(utils.DEBUG):
                debug_dump(self.state, "== AFter Realloc ==")
            if(not is_consistent(hs)):
                inconsistent_breakpoint()
            return 0
        if oldmem == 0:
            new_chunk_ptr = hs.malloc(nbytes)
            new_chunk_ptr += 2*SIZE_SZ
            if(utils.DEBUG):
                debug_dump(self.state, "== AFter Realloc ==")
            if(not is_consistent(hs)):
                inconsistent_breakpoint()
            return new_chunk_ptr
        # By now normal case
        
        old_chunk = hs.get_chunk_by_address(oldp)
        if old_chunk is None:
            vl.warning(f'Freeing Non existent chunk in realloc requested {Realloc.i} with size {nb:x}@{oldp:x} ')
            pass
            # pdb.set_trace()
            dump_concretized_file(self.state)
            newp = -2*SIZE_SZ #setting to zero before returning
        else:
            old_size = old_chunk.size
            # TODO mmapped chunk logic
            # todo if single thread (check)
            try:
                newp = hs.realloc(oldp, old_size, nb)
                if(not is_consistent(hs)):
                    inconsistent_breakpoint()
            except Vulnerability as V:
                print(V.msg, V.addr)
                l.warning(V.msg + " @ " + str(V.addr))
                vl.warning('vlraised warning', V.msg + " @ " + str(V.addr))
                dump_concretized_file(self.state)
                if utils.DEBUG:
                    print("Vulnerability raised in realloc")
                    pass
                    # pdb.set_trace()
        if(utils.DEBUG):
            debug_dump(self.state, "== AFter Realloc ==")
            
        if old_chunk.address != newp:
            self.copy_data(old_chunk, newp)
        newp += 2*SIZE_SZ
        Realloc.i+=1
        if(not is_consistent(hs)):
            inconsistent_breakpoint()
        return newp
        #todo multi threaded logic

    def copy_data(self, old_chunk: Chunk, new_chunkp):
        old_addr = old_chunk.address + 2*SIZE_SZ
        write_size = old_chunk.size - SIZE_SZ
        new_addr = new_chunkp + 2*SIZE_SZ
        if (old_chunk.address+old_chunk.size) != (new_chunkp):
            for idx in range(write_size):
                self.state.mem[new_addr + idx].uint8_t = self.state.memory.load(old_addr + idx, 1, disable_actions=True, inspect=False)

class Free(SimProcedure):
    i = 0
    def run(self, address):
        ohs = self.state.my_heap.heap_state
        possible_addresses = possible_free_concretizations(ohs)
        # print(f'Possible addresses = {possible_addresses}')
        self.state: SimState
        if self.state.solver.symbolic(address):
            pass
            # pdb.set_trace()
        for pa in possible_addresses:
            sat = self.state.solver.satisfiable(extra_constraints=[address == pa])
            add = pa
            if sat :
                print(f'Matched {pa}')
                state_copy = self.state.copy()
                hs = state_copy.my_heap.heap_state
                if(add == 0):
                    l.warning('free 0 called, skipping')
                    vl.warning('free 0 called, skipping')
                    continue
                add = add - 2 * SIZE_SZ
                print(address)
                print(f'free called {Free.i}, address 0x{add:x}')
                if(utils.DEBUG):
                    debug_dump(state_copy, "== Before Free ==")
                try:
                    hs.free(add)
                    if(not is_consistent(hs)):
                        inconsistent_breakpoint()
                except Vulnerability as V:
                    pass
                    # pdb.set_trace()
                    print("Error")
                    l.warning(V.msg + " @ " + str(V.addr))
                    vl.warning( V.msg + " @ " + str(V.addr))
                    dump_concretized_file(self.state)
                if(utils.DEBUG):
                    debug_dump(state_copy, "== After Free ==")
                orig_state = self.state
                self.state = state_copy
                self.ret()
                self.state = orig_state
                Free.i += 1




class Posix_Memalign(SimProcedure):
    def run(self, sppmem, salignment, ssize):
        state = self.state
        alignment = state.solver.eval(salignment)
        size = state.solver.eval(ssize)
        ppmem = state.solver.eval(sppmem)
        pmem = state.solver.eval(state.mem[ppmem].uintptr_t.resolved)
        hs = state.my_heap.heap_state
        nb = hs.request2size(size)
        
        print(f'rip memalign requested size 0x{size:x} with allignemnt 0x{alignment:x} heap state before call: ')
        if utils.DEBUG:
            debug_dump(state, "==Before memalign==")
        if alignment <= MALLOC_ALLIGNMENT:
            m = hs.malloc(size)+2*SIZE_SZ
            state.mem[ppmem].uintptr_t = m
            if(not is_consistent(hs)):
                inconsistent_breakpoint()
            return 0
        if alignment <= MIN_SIZE:
            alignment = MIN_SIZE

        alignment = self.powerof2(alignment)

        # TODO : Missing a check for >size max
        p = hs.malloc(nb+alignment+MIN_SIZE)
        if(not is_consistent(hs)):
            inconsistent_breakpoint()
        m = p + 2*SIZE_SZ
        pchunk = hs.get_chunk_by_address(p)
        if m % alignment != 0:
            brk = (p+alignment -1) & (-alignment)
            if (brk - p) <= MIN_SIZE:
                brk += alignment
            lead_size = brk - p
            new_size = pchunk.size - lead_size
            pchunk.address = brk
            pchunk.size = new_size
            orig_prevsize = pchunk.prev_size
            pchunk.prev_size = lead_size
            
            new_chunk = Chunk()
            new_chunk.address = p
            new_chunk.size = lead_size
            new_chunk.free = False
            new_chunk.prev_size = orig_prevsize
            hs.allocated_chunks.append(new_chunk)
            hs.free(p)
            p=brk
        
            
        pchunk = hs.get_chunk_by_address(p)
        if size > (nb+MIN_SIZE):
            remainder_size = pchunk.size - nb
            remainder_address = p + nb
            new_chunk = Chunk()
            new_chunk.address = remainder_address
            new_chunk.size = remainder_size
            new_chunk.prev_size = pchunk.size
            new_chunk.free = False
            hs.allocated_chunks.append(new_chunk)
            hs.free(remainder_address)
        
        m = p+2*SIZE_SZ
        state.mem[ppmem].uint64_t = m
        print(f"mem align returning address {m:x}")
        print(state.mem[pmem])
        if utils.DEBUG:
            debug_dump(state, "==After memalign==")
        if(not is_consistent(hs)):
            inconsistent_breakpoint()
        return 0
            
        
        
    def powerof2(self, alignment):
        a= 1
        while alignment > a:
            a = a<<1
        return a
    
class Perror(SimProcedure):
    def run(self):
        self.exit(1)
