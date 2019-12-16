from user_functions import *
from mstate import *
import copy
import random
DEBUG = True

users = []

class tree_node:
    def __init__(self):
        self.state = None
        self.free_number = -1
        self.type = ""
        self.allocations = []

root = tree_node()
root.state =  HeapState(0x00)


q = [root]


node_count = 1
while len(q) > 0:
    print("iteration: " + str(node_count))
    node_count += 1
    current = q.pop(0)
    # current.state.dump()
    print( current.type)
    a = current.state.check_distance(110, 44,528)
    if a != None:
        print("found ", a[0], a[1])
        break
    create_child = copy.deepcopy(current)
    ui = User_Info(create_child.state)
    ui.create_user()
    create_child.allocations.append(ui)
    # create_child.type = "c"
    q.append(create_child)

    for i in range(len(current.allocations)):
        free_child = copy.deepcopy(current)
        ui = free_child.allocations[i]
        ui.deleteUser()
        # free_child.type = "f"+str(i)
        del free_child.allocations[i]
        q.append(free_child)
    # if current.type == 'c':
    #     u=User_Info(h)
    #     u.create_user()
    #     current.allocations.append(u)
    # elif current.type == 'f':
    #     u = current.allocations[current.free_number]
    #     u.deleteUser()
    #     current.allocations.remove(u)
    # child = tree_node()
    # child.type = 'c'
    # child.allocations = current.allocations
    # child.free_number = -1
    # q.append(child)
    # for i in range(len(current.allocations)):
    #     child = tree_node()
    #     child.type = 'f'
    #     child.free_number = i
    #     child.allocations = current.allocations
    #     q.append(child)
    # h.dump()

