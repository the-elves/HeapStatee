from copy import deepcopy
from angr import SimStatePlugin, SimProcedure, SimState
from angr.calling_conventions import SimCCSystemVAMD64
from angr.engines import SimSuccessors
from HeapModel.mstate import HeapState, SIZE_SZ
from HeapModel.Vulns import *
from HeapModel.heapquery import *
import claripy
import logging
l = logging.getLogger('heap_analysis')
vl = logging.getLogger('vuln_logger');




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

    def set_heap(self, h):
        self.heap_state = h

    def print_heap(self):
        self.heap_state.dump()

    @SimStatePlugin.memo
    def copy(self, memo):
        heap_copy = deepcopy(self.heap_state)
        return HeapPlugin(h = heap_copy)


class Malloc(SimProcedure):
    i = 0
    def run(self, size):
        s = self.state.solver.eval(size)
        hs = self.state.my_heap.heap_state
        rip = self.state.solver.eval(self.state.regs.rip)
        print(f'rip {rip:x} malloc requested {Malloc.i} with requst_size {s}, allocated size {hs.request2size(s)}, heap state before')
        hs.dump()
        try:
            addr = hs.malloc(s)
        except Vulnerability as V:
            print(V.msg, V.addr)
            l.warning(V.msg + " @ " + str(V.addr))
            vl.warning(V.msg + " @ " + str(V.addr))
        print(f'rip {rip:x} malloc called {Malloc.i} with requst_size {s}, allocated size {hs.request2size(s)}, allocated at 0x{addr:x}')
        Malloc.i += 1
        hs.dump()
        print(self.state.callstack)
        return addr + 2*SIZE_SZ

class Calloc(SimProcedure):
    i = 0
    def run(self, size, num):
        s = self.state.solver.eval(size)
        n = self.state.solver.eval(num)
        hs = self.state.my_heap.heap_state
        rip = self.state.solver.eval(self.state.regs.rip)
        print(f'rip {rip:x} calloc requested {Calloc.i} with size {hs.request2size(s)} heap state before call: ')
        hs.dump()
        try:
            addr = hs.malloc(n*s)
        except Vulnerability as V:
            print(V.msg, V.addr)
            l.warning(V.msg + " @ " + str(V.addr))
            vl.warning(V.msg + " @ " + str(V.addr))
        print(f'rip {rip:x} calloc called {Calloc.i} with size {hs.request2size(s)}, allocated at 0x{addr:x}')
        Malloc.i += 1
        hs.dump()
        return addr + 2*SIZE_SZ


class Realloc(SimProcedure):
    i = 0
    def run(self, soldmem, sbytes):
        oldmem = self.state.solver.eval(soldmem)
        nbytes = self.state.solver.eval(sbytes)
        hs = self.state.my_heap.heap_state
        oldp = oldmem - 2 * SIZE_SZ
        print(f'realloc requested {Realloc.i} with size {hs.request2size(nbytes)} heap state before call: ')
        hs.dump()
        if nbytes == 0 and oldmem != 0:
            hs.free(oldp)
        if oldmem == 0:
            new_chunk_ptr = hs.malloc(nbytes)
            new_chunk_ptr += 2*SIZE_SZ
            return new_chunk_ptr
        old_chunk = hs.get_chunk_by_address(oldp)
        old_size = old_chunk.size

        nb = hs.request2size(nbytes)
        old_chunk_ptr = oldmem-2*SIZE_SZ
        # TODO mmapped chunk logic
        # todo if single thread (check)
        newp = hs.realloc(oldp, old_size, nb)
        newp += 2*SIZE_SZ
        return newp
        #todo multi threaded logic


class Free(SimProcedure):
    i = 0
    def run(self, address):
        ohs = self.state.my_heap.heap_state
        possible_addresses = possible_free_concretizations(ohs)
        print(f'Possible addresses = {possible_addresses}')
        self.state: SimState
        for pa in possible_addresses:
            sat = self.state.solver.satisfiable(extra_constraints=[address == pa])
            add = pa
            if sat :
                state_copy = self.state.copy()
                hs = state_copy.my_heap.heap_state
                if(add == 0):
                    l.warning('free 0 called, skipping')
                    vl.warning('free 0 called, skipping')
                    continue
                add = add - 2 * SIZE_SZ
                print(address)
                print(f'free called {Free.i}, address {add}')
                try:
                    hs.free(add)
                except Vulnerability as V:
                    print("Error")
                    l.warning(V.msg + " @ " + str(V.addr))
                    vl.warning(V.msg + " @ " + str(V.addr))

                orig_state = self.state
                self.state = state_copy
                self.ret()
                self.state = orig_state
                Free.i += 1



class Perror(SimProcedure):
    def run(self):
        self.exit(1)
