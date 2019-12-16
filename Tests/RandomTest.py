from mstate import *
from user_functions import *
import random
DEBUG = True

users = []
h = HeapState(0x00)
seed = random.randrange(sys.maxsize)
print ("Seed is ", seed)
random.seed(4933591529458070792)
for x in range(20000):
    print ("Iteration ",x)
    if random.randint(1, 2) % 2 == 0:
        print ('Allocate ', len(users))
        # allocate
        u = User_Info(h)
        u.create_user()
        users.append(u)
    else:
        if( len(users) == 0 ):
            continue
        idx = random.randint(0,len(users) - 1)
        elem = users[idx]
        print('Free ', idx)
        elem.deleteUser()
        del users[idx]
    if DEBUG:
        h.dump()
    print ("--------------------------------")
    tup = h.check_distance(110, 44, 528)
    if tup != None:
        print ("found")
        print(tup[0], tup[1])
        break
print ("iterations done")

#4252839798660292209
#4933591529458070792