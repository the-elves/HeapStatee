from copy import deepcopy
from angr import SimStatePlugin, SimProcedure
from HeapModel.mstate import HeapState, SIZE_SZ
from HeapModel.Vulns import *
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
        return HeapPlugin(heap_copy)


class Malloc(SimProcedure):
    i = 0
    def run(self, size):
        s = self.state.solver.eval(size)
        hs = self.state.my_heap.heap_state
        try:
            addr = hs.malloc(s)
        except Vulnerability as V:
            print(V.msg, V.addr)
            l.warning(V.msg + " @ " + str(V.addr))
            vl.warning(V.msg + " @ " + str(V.addr))
        print(f'malloc called {Malloc.i} with size {hs.request2size(s)}, allocated at 0x{addr:x}')
        Malloc.i += 1
        hs.dump()
        return addr + 2*SIZE_SZ


class Free(SimProcedure):
    i = 0
    def run(self, address):
        add = self.state.solver.eval(address)
        if(add == 0):
            l.warning('free 0 called, skipping')
            vl.warning('free 0 called, skipping')
            return
        add = add - 2 * SIZE_SZ
        print(address)
        print(f'free called {Free.i}, address {add}')
        hs = self.state.my_heap.heap_state
        try:
            hs.free(add)
        except Vulnerability as V:
            print("Error")
            l.warning(V.msg + " @ " + str(V.addr))
            vl.warning(V.msg + " @ " + str(V.addr))

        Free.i += 1

