s = None
def sets(st):
    global s
    s= st
def concretize(a):
    return s.solver.eval(a)

def print_mem(addr, sz):
    for i in range(sz):
        print(chr(concretize(s.mem[addr+i].uint8_t.resolved)))

def get_mem(addr, sz):
    memobj = s.mem[addr]
    attrname = "uint"+str(sz)+"_t"
    memobj = getattr(memobj, attrname)
    return concretize(memobj.resolved)

def stack_value(offset):
    rbp = concretize(s.regs.rbp)
    pl = rbp + offset
    return concretize(s.mem[pl].uint64_t.resolved)

def print_stack_ptr(offset, size):
    ptr = stack_value(offset)
    print_mem(ptr, size)



