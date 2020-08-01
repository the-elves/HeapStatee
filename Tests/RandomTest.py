from Tests.user_functions import *
from HeapModel.mstate import *
import random
DEBUG = 0
TRACE = True

users = []
h = HeapState(500000)
seed = random.randrange(sys.maxsize)
# print ("Seed is ", seed)
random.seed(1)
allocation_number = 0
if TRACE:
    f = open("../MemTraceGenerator/UserAPI/trace", "w")

for x in range(500):
    if DEBUG >0:
        print ("Iteration ",x)
    if random.randint(1, 2) % 2 == 0:
        if DEBUG > 0:
            print ('Allocate ', len(users))
        # allocate
        u = User_Info(h)
        print('command m' + str(x) + '\n')
        u.create_user()
        h.dump_parsed()
        u.allocation_num = allocation_number
        allocation_number += 1
        users.append(u)
        if TRACE:
            f.write("m" + str(x) + "\n")
    else:
        if len(users) == 0:
            continue
        idx = random.randint(0, len(users) - 1)
        elem = users[idx]
        if DEBUG > 0:
            print('Free ', idx)
        print("command f " + str(users[idx].allocation_num) + " \n")
        # print(elem.first_name, elem.last_name, elem.house_no, elem.street, elem.city_state)
        elem.delete_user()
        h.dump_parsed()
        if TRACE:
            f.write("f " + str(users[idx].allocation_num) +" \n")
        del users[idx]
    if DEBUG > 0:
        h.dump()
        print ("--------------------------------")
    # tup = h.check_distance(110, 44, 142)
    # if tup != None:
    #     if(DEBUG > 0):
    #         print ("found")
    #         print(tup[0], tup[1])
    #     break
if TRACE:
    f.close()
if(DEBUG >0):
    print ("iterations done")

#4252839798660292209
#4933591529458070792