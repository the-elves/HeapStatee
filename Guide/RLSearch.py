# Distance between chunk c1 and c2 should be d
from mstate import *
from Tests.user_functions import *
from enum import Enum
import copy
tempheap = HeapState(0)
c1_size = tempheap.request2size(110)
c2_size = tempheap.request2size(44)
d = 512
h = HeapState(0)
gamma = 0.9
RECURSIVE_DEPTH = 11
class API(Enum):
    ALL = 1
    DEL = 2

class Action:
    def __init__(self, a, f: int):
        self.act = a
        self.free_no = f

class State:
    def __init__(self, h: HeapState):
        self.users = []
        self.s = h
        self.v = 0

def end_goal(s: State, a: Action):
    _h = s.s
    for c1 in _h.allocated_chunks:
        if c1.size == c1_size:
            for c2 in h.allocated_chunks:
                if c2.size == c2_size:
                    if (c2.address - c1.address) == d:
                        return 1
    return 0

#TODO Memoize
def calculate_v(s: State, depth: int, reward):
    print("Depth = ", depth)
    if depth == RECURSIVE_DEPTH:
        return 0
    else:
        # action allocate
        a = Action(API.ALL, -1)
        rallocate = reward(s, a)
        newstate = copy.deepcopy(s)
        u = User_Info(newstate.s)
        u.create_user()
        newstate.users.append(u)
        future_v = calculate_v(newstate, depth + 1, reward)
        accum_v = rallocate + gamma * future_v
        # action delete user
        for i in range(len(s.users)):
            a = Action(API.DEL, i)
            rdel = reward(s, a)
            newstate = copy.deepcopy(s)
            u = newstate.users[i]
            u.update_heap(newstate.s)
            u.delete_user()
            newstate.users.remove(u)
            future_v = calculate_v(newstate, depth + 1, reward)
            accum_v = accum_v + rdel +  gamma * future_v
        return accum_v

def main():
    h = HeapState(0)
    initstate = State(h)
    initstate.v = calculate_v(initstate, 0, end_goal)
    print (initstate.v)
main()
