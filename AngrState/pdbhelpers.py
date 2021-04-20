s = None
def sets(st):
    global s
    s= st
def get(a):
    return s.solver.eval(a)

def print_mem(addr, sz):
    for i in range(sz):
        print(chr(get(s.mem[addr+i].uint8_t.resolved)))

def local(offset):
    rbp = get(s.regs.rbp)
    pl = rbp + offset
    return get(s.mem[pl].uint64_t.resolved)
