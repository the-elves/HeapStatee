with open("output") as f:
    l = [x for x in f.readlines() if (x.find("Freeing user") != -1 or x.find("Allocating")!=-1) ]
    for x in l:
        print x
