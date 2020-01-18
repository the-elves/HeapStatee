from user_functions import *
from mstate import *
import random
DEBUG = False
TRACE = False

users = []
h = HeapState(0x00)
seed = random.randrange(sys.maxsize)
print ("Seed is ", seed)
random.seed(1)
allocation_number = 0
if TRACE:
    f = open("../MemTraceGenerator/UserAPI/trace", "w")

for x in range(100):
    print ("Iteration ",x)
    if random.randint(1, 2) % 2 == 0:
        print ('Allocate ', len(users))
        # allocate
        u = User_Info(h)
        u.create_user()
        u.allocation_num = allocation_number
        allocation_number += 1
        users.append(u)
        if TRACE:
            f.write("m\n")
    else:
        if len(users) == 0:
            continue
        idx = random.randint(0, len(users) - 1)
        elem = users[idx]
        print('Free ', idx)
        elem.delete_user()
        if TRACE:
            f.write("f " + str(users[idx].allocation_num) +" \n")
        del users[idx]
    if DEBUG:
        h.dump()
    print ("--------------------------------")
    tup = h.check_distance(110, 44, 142)
    if tup != None:
        print ("found")
        print(tup[0], tup[1])
        break
if TRACE:
    f.close()
print ("iterations done")

#4252839798660292209
#4933591529458070792