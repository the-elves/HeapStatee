import sys

f = open(sys.argv[1])
line = f.readline()

def skip_lines():
    global f
    global line
    while line:
        if line.find("Breakpoint 2 at") != -1:
            break
        line = f.readline()

        
def contains(line, subst):
    if line.find(subs) == -1:
        return False
    else:
        return True

def parse_fastbins():
    global line
    global f
    
    
def parse_line():
    global line
    global f
    while line:
        if contains(line, "Tcache"):
            continue
        elif contains(line, "Fastbins for arena"):
            parse_fastbins()
        
        
        line = f.readline()
    

with open(sys.argv[1]) as f:
if __name__ == '__main__':

    #skip first lines
    
    while line:
        print line
        line = f.readline()
