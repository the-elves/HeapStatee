import sys
import os
sys.path.append("/home/" + os.environ["USERNAME"] + "/College/Guided_HML/HeapStatee")
# from mstate import Chunk
startingAddress = 500000
f = open(sys.argv[1])
line = f.readline()
first_address = 0
def skip_lines():
    global f
    global line
    while line:
        if line.find("Breakpoint 2 at") != -1:
            break
        line = f.readline()

        
def contains(line, subst):
    if line.find(subst) == -1:
        return False
    else:
        return True

    
def find_pos_after(st, sub):
    return st.find(sub)+len(sub)


def parse_chunk(line):
    pchunks = find_pos_after(line, "Chunk(addr=")
    pchunkse = line.find(", size=")
    chunk_addr = int(line[pchunks:pchunkse], 0)
    global first_address
    if(first_address == 0):
        first_address = chunk_addr
    chunk_addr = chunk_addr - first_address -560 -4112*2 + startingAddress
    pchunksize = find_pos_after(line, ", size=")
    pchunksizee = line.find(", flags=")
    size = int(line[pchunksize:pchunksizee],0)
    
    pflags = find_pos_after(line, ", flags=")
    pflagse = line.find(")")
    flags = line[pflags:pflagse]

#    print("Chunk\n  addr = {:x}\n  size = {:x}\n  flags = {}".format(chunk_addr
#                                                                         ,size
#                                                                         , flags))
    return (chunk_addr, size, flags)

def parse_chunks():
    global line
    global f
    line = f.readline()
    while(line.find("==Chunks Done==") == -1):
        if (contains(line, "Chunk")):
            c = parse_chunk(line)
            if c[1] != 4112 and c[1] != 560:
                print (c)
        line = f.readline()

def parse_fastbins():
    global line
    global f
    line = f.readline()
    while( line.find("Unsorted Bin for arena") == -1):
        pidx = line.find("idx=")+4
        pidxe = line.find(", size=")
        idx = int(line[pidx:pidxe],0)

        psize = pidxe+7
        psizee = line.find("]")
        size = int(line[psize:psizee],0)

        line = line[psizee+1:]
        while(line.find("Chunk(addr=") != -1):
            chunk = parse_chunk(line)
            print (chunk)
            chunke = line.find(")")+1
            line = line[chunke:]
        pos = f.tell()
        line = f.readline()
    f.seek(pos)


def parse_smallbins():
    global f
    global line
    line=f.readline()
    while line.find('Large Bins for arena') == -1:
        if contains(line, 'small_bins['):
            pidx = find_pos_after(line,'small_bins[')
            pidxe = line.find(']:')
            binidx = int(line[pidx:pidxe],0)
            line = f.readline()
            # print('small bin[{}]'.format(binidx))
            while(contains(line, 'Chunk')):
                pchunk = line.find('Chunk(')
                pchunke = line.find(')')+1
                c = parse_chunk(line[pchunk:pchunke])
                print (c)
                line = line[pchunke:]
        pos = f.tell()
        line = f.readline()
    f.seek(pos)

def parse_unsortedbins():
    global f
    global line
    while line.find('Small Bins for arena') == -1:
        if contains(line, 'unsorted_bins['):
            pidx = find_pos_after(line, 'unsorted_bins[')
            pidxe = line.find(']:')
            binidx = int(line[pidx:pidxe],0)
            # print('unsorted bin[{}]'.format(binidx))
            line = f.readline()
            while(contains(line, 'Chunk')):
                pchunk = line.find('Chunk(')
                pchunke = line.find(')')+1
                c = parse_chunk(line[pchunk:pchunke])
                print (c)
                line = line[pchunke:]
        pos = f.tell()
        line = f.readline()
    f.seek(pos)


def parse_largebins():
    return 0



def parse_line():
    global line
    global f
    while line:
        line = f.readline()
        if contains(line, "Fastbins for arena"):
            print( 'fastbins')
            parse_fastbins()
        elif contains(line, "Small Bins for arena"):
            print( 'smallbins')
            parse_smallbins()
        elif contains(line, "Unsorted Bin for arena"):
            print( 'unsorted')
            parse_unsortedbins()
        elif contains(line, "Large Bins for arena"):
            print( 'largebins')
            parse_largebins()
        elif contains(line, "==Chunks=="):
            print( 'chunks')
            parse_chunks()
        elif contains(line, 'command'):
            print(line)


if __name__ == '__main__':

    #skip first lines
    skip_lines()
    line = f.readline()
    while line:
        line = f.readline()
        parse_line()
        
