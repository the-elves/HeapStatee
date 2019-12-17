# Distance between chunk c1 and c2 should be d
from mstate import *
from Tests.user_functions import *
from enum import Enum

c1_size = HeapState.request2size(110)
c2_size = HeapState.request2size(44)
d = 512
users = []
h = HeapState(0)
gamma = 0.9

class API(Enum):
    ALL = 1
    DEL = 2
class Action
    def __init__(self):
        self.act:API
        self.free_no = 0

class State:
    def __init__(self):
        self.s : HeapState
        self.v: int

def reward(s: HeapState, a: Action):

    if a.act == API.ALL:
        for c in s.allocated_chunks:
            if c.address == c1_size:
                user: User_Info = users[a.free_no]
                if user.first_name - c.address <= d:
                    return -1
                else:
                    return +1

    elif a.act == API.DEL:
        for c in s.allocated_chunks:
            if c.size == c1_size:
                if c2_size <= MAX_FASTBIN_SIZE:
                    c2idx = s.get_fast_bin_index(c2_size)
                    if len(s.fastbin) != 0:
                        if s.fastbin[c2idx][0].address - c.address == d:
                            return 2
                        else:
                            if s.fastbin[c2idx][0].address - c.address > d:
                                return -1
                            elif s.fastbin[c2idx][0].address - c.address < d-c2_size:
                                return 1
                else:
                    c2idx = s.smallbin_index(c2_size)
                    victim_bin = s.smallbin[c2idx]
                    if len(s.smallbin) != 0:
                        if s.smallbin[c2idx][-1].address - c.address == d:
                            return 2
                        else:
                            if s.smallbin[c2idx][-1].address - c.address > d:
                                return -1
                            elif s.smallbin[c2idx][-1].address - c.address < d-c2_size:
                                return 1
                #bins could not allocate. That means top will be used
                #this means top will be pushed further apart
                if c.address - s.top.address < d-c2_size:
                    return 1
                else:
                    return -1


def calculate_v(s: HeapState, depth):
    #XXX May be chunks not duplicated
    if depth == 100:
        return 0
    r = reward(s, )



