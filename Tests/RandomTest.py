from Tests.user_functions import *
from mstate import *
import random

users = []
h = HeapState(0x00)

for x in range(1000):
    if random.randint(1, 2) % 2 == 0:
        # allocate
        u = User_Info(h)
        u.create_user()
        users.append(u)
    else:
        if(len(users) == 0):
            continue
        idx = random.randint(0,len(users) - 1)
        elem = users[idx]
        elem.deleteUser()
        del users[idx]
    tup = h.check_distance(39, 128, 70)
    if tup != None:
        print(tup[0], tup[1])
        break