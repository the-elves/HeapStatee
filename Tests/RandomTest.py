from user_functions import *
from mstate import *
import random
DEBUG = False

users = []
h = HeapState(0x00)
seed = random.randrange(sys.maxsize)
print ("Seed is ", seed)
random.seed(1)
allocation_number = 0
f = open("/home/ajinkya/College/Guided_HML/HeapStatee/MemTraceGenerator/UserAPI/trace", "w")
for x in range(10000):
    print ("Iteration ",x)
    if random.randint(1, 2) % 2 == 0:
        print ('Allocate ', len(users))
        # allocate
        u = User_Info(h)
        u.create_user()
        u.allocation_num = allocation_number
        allocation_number += 1
        users.append(u)
        f.write("m\n")
    else:
        if len(users) == 0:
            continue
        idx = random.randint(0, len(users) - 1)
        elem = users[idx]
        print('Free ', idx)
        elem.delete_user()
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
f.close()
print ("iterations done")

#4252839798660292209
#4933591529458070792