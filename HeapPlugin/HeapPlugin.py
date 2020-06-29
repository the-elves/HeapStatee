from copy import deepcopy
from angr import SimStatePlugin, SimProcedure
from HeapModel.mstate import HeapState


class HeapPlugin(SimStatePlugin):

    #TODO merge and widen
    # def merge(self, _others, _merge_conditions, _common_ancestor=None):
    #     pass

    def __init__(self, h=None):
        super().__init__()
        if (h is None):
            self.heap_state = HeapState(0)
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
        addr = self.state.my_heap.heap_state.malloc(s)
        print(f'malloc called {self.i} with size {s}, allocated at {addr}')
        self.i += 1

class Free(SimProcedure):
    i = 0
    def run(self, address):
        add = self.state.solver.eval(address)
        hs = self.state.my_heap.heap_state
        hs.free(add)
        print(f'free called {self.i}, address {add}')

        self.i += 1