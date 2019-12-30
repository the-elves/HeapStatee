import random as r

r.seed(100)
allocated = []
all_no = 0
def create_command():
    global allocated
    global all_no
    command = ""
    op = r.randint(0,10)
    if(op == 0):
        if(len(allocated) == 0):
            return ""
        free_no = r.randint(0, len(allocated)-1)
        command = command + "f " + str(allocated[free_no]) + "\n"
        allocated.remove(allocated[free_no])
        return command
    else:
        command = command + "m" + "\n"
        allocated.append(all_no)
        all_no +=1
        return command
    
        
    
    
    

with open("trace", "w") as f:
    i =0;
    while(i < 1000):
        f.write(create_command())
        i+=1
