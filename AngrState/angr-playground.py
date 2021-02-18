#!/usr/bin/env python
# coding: utf-8
import psutil
import sys
print(sys.getrecursionlimit())
sys.setrecursionlimit(1500)
sys.path.append('../')
from HeapPlugin.HeapPlugin import HeapPlugin, Malloc, Free, Calloc, Realloc, Perror
from HeapModel.heapquery import *
import angr
from angr import SIM_PROCEDURES
import claripy
import logging
from datetime import datetime
import signal
import pdb
from angr.exploration_techniques import DFS
import os
from utils.utils import *

HOUR = 60*60
time_limit = HOUR*40
start_time = datetime.now()

l = logging.getLogger('heap_analysis')



def sigquit_handler(signal, frame):
    for s in m.active:
        dump_callstack(s)
        s.my_heap.heap_state.dump()


def initialize_logger(bname):
    global vl
    global l
    bname = bname.split('/')[-1]
    vl = logging.getLogger('vuln_logger')
    vl.addHandler(logging.FileHandler('../reports/vuln-reports/' + bname +'.log', 'w'))
    
    l.addHandler(logging.FileHandler('../reports/logs/'+bname+'.log', 'w'))
    l.setLevel(logging.DEBUG)


def get_heap_starting_address(b):
    objs = b.loader.all_objects
    current_max_addr = 0
    for o in objs:
        if o.max_addr > current_max_addr:
            current_max_addr = o.max_addr
    max_addr_string=str(hex(current_max_addr))
    msd = str(hex(int(max_addr_string[2], 16)+1))[2:]
    max_addr_len = len(max_addr_string)-2
    heap_starting_address = int(msd + '0'*(max_addr_len-1), 16)
    return heap_starting_address

        
def initialize_project(b, ss):
    heap_starting_address = get_heap_starting_address(b)
    h = HeapPlugin(startingAddress=heap_starting_address)
    ss.register_plugin('my_heap', h)
    print("[+] hooking malloc")
    b.hook_symbol('malloc', Malloc())
    print("[+] hooking calloc")
    b.hook_symbol('calloc', Calloc())
    print("[+] hooking free")
    b.hook_symbol('free', Free())
    print("[+] hooking reallloc")
    b.hook_symbol('realloc', Realloc())
    print("[+] hooking perror")
    b.hook_symbol('perror', Perror())

    print("[+] hooking fopen64")
    # print(SIM_PROCEDURES)
    b.hook_symbol('fopen64', SIM_PROCEDURES['libc']['fopen']())

    print("[+] hooking seek")
    b.hook_symbol('fseeko64', SIM_PROCEDURES['libc']['fseek']())

    print("[+] hooking tell")
    b.hook_symbol('ftello64', SIM_PROCEDURES['libc']['ftell']())
    
    
    ss.inspect.b('mem_write', when=angr.BP_BEFORE, action=bp_action_write)
    initialize_logger(b.filename)
    setup_filesystem(ss)


    
def handle_heap_write(state):
    write_address = state.solver.eval(state.inspect.mem_write_address)
    wl = state.solver.eval(state.inspect.mem_write_length)
    wexpr = state.inspect.mem_write_expr
    l.warning("writting to %x for %d bytes writing expr" % (write_address, wl))
    l.warning(bvv_to_string(state, wexpr))
    i = 0
    vuln = False
    for wi in range(wl):
        wa = write_address + wi
        c = chunk_containing_address(wa, state.my_heap.heap_state)
        if c is None:
            l.warning('Writing outside chunks @ 0x{:x}'.format(write_address))
            vuln=True
        else:
            if write_in_free_chunk(wa, state.my_heap.heap_state):
                conc_argv = state.solver.eval(argvinp)
                conc_stdin = state.posix.dumps(1)
                state.block().pp();
                l.warning('write @ {:x} is in free chunk {:x} argv = {} stdin={}'.format(wa, c.address, conc_argv, conc_stdin))
                rip = state.solver.eval(state.regs.rip)
                vl.warning('rip = {:x} write @ {:x} is in free chunk {:x} argv = {} stdin={} write_address = {:x}'.format(rip, wa, c.address, conc_argv, conc_stdin, write_address + wi))
                vl.warning(dump_callstack(state))
                vuln = True    
            if metadata_cloberring(wa, state.my_heap.heap_state):
                conc_argv = state.solver.eval(argvinp)
                conc_stdin = state.posix.dumps(1)
                state.block().pp();
                rip = state.solver.eval(state.regs.rip)
                l.warning('Metadata of heap chunk @ 0x{:x} cloberred argv = {} stdin={} write_address = 0x{:x}'.format(c.address, conc_argv, conc_stdin, write_address+wi))
                vl.warning('rip = {:x} Metadata of heap chunk @ 0x{:x} cloberred argv = {} stdin={} write_address = 0x{:x}'.format(rip, c.address, conc_argv, conc_stdin, write_address+wi))
                vl.warning(dump_callstack(state))
                vuln = True
    if(vuln):
        h = state.my_heap
        h.heap_state.dump()
        VULN_FLAG=True
        pdb.set_trace()
        dump_concretized_file(state)



def bp_action_write(state):
    write_address = state.solver.eval(state.inspect.mem_write_address)
    if addr_in_heap(write_address, state.my_heap.heap_state):
        handle_heap_write(state)


def setup_filesystem(estate):
    host_file_system = angr.SimHostFilesystem('/home/ajinkya/Guided_HLM/guest_chroot/')
    host_file_system.set_state(estate)
    estate.fs.mount('/exploits/',host_file_system)
    
    symfilename = 'mysymfile'
    symfile = angr.SimFile(symfilename, size=200*1024)
    symfile.set_state(estate)
    estate.fs.insert('/symfiles/mysymfile', symfile)

    
def alarm_handler(signum, frame):
    exit()
        

def stopping_condition():
    if psutil.virtual_memory().percent > 90:
        return True
    if (datetime.now() - start_time).total_seconds() > time_limit:
        return True
    return False

def print_libs(p):
    for k,v in p.loader.shared_objects.items():
        print(f'{k} : {v} : {v.binary}')
        


def pdb_stopping_condition():    
    if next_stopping_addr in m.active[0].block().instruction_addrs or \
       next_stopping_addr == -1:
        return True
    else: return False

def dump_regs(s):
    e = s.solver.eval
    for n in [rn for rn in dir(s.regs) if rn[0] == 'r']:
        reg = getattr(s.regs, n)
        print(n,':', hex(e(reg)))

        
def dump_context(s):
    print("=============>")
    s.my_heap.heap_state.dump()
    print()
    print("Regs")
    dump_regs(s)
    s.block().pp()
    print(dump_callstack(s))
    
    
signal.signal(signal.SIGQUIT, sigquit_handler)

binary_name = sys.argv[2]
loader_libraries = ['../../tools/glibc-dir/install/lib64/libc-2.27.so',
                                  '/home/ajinkya/Guided_HLM/tools/glibc-dir/install/lib64/ld-2.27.so']
if 'HEAPSTATE_LIBS' in os.environ.keys():
    loader_libraries.extend(os.environ['HEAPSTATE_LIBS'].split(' '))

print('External Libraries ', loader_libraries)
b = angr.Project(binary_name, auto_load_libs=True,
                 force_load_libs=loader_libraries
                 )

print_libs(b)


num_sym_bytes = 20
input_chars = [claripy.BVS(f'flag{i}',8) for i in range(num_sym_bytes)] + [claripy.BVV('\n', 8)]
argvinp = claripy.Concat(*input_chars)


stdin_bytes_list = [claripy.BVS('byte_%d' % i, 8) for i in range(3200)]
stdin_bytes_ast = claripy.Concat(*stdin_bytes_list)


estate = b.factory.entry_state(args = sys.argv[2:]) #, stdin=angr.SimFile('/dev/stdin', content=stdin_bytes_ast))

# estate = b.factory.entry_state(argc = 2, argv = [binary_name, input_chars])
# for i in range(num_sym_bytes-1):
#     c=argvinp.chop(8)[i]
#     estate.add_constraints(c!=0)
    
initialize_project(b, estate)

print("Heap starting at ", hex(estate.my_heap.heap_state.startAddress))

m = b.factory.simulation_manager(estate)
m.use_technique(DFS())
# pdb.set_trace()
progress=0

# m.run()
# for s in m.deadended:
#     print('posix out', str(s.posix.dumps(1)))
#     print('posix err', str(s.posix.dumps(2)))
# exit()

while len(m.active) > 0:
    now = datetime.now()
    starting_time = now
    timestr = now.strftime("%H:%M:%S")
    addr = m.active[0].solver.eval(m.active[0].regs.ip)
    print(timestr, 'active states = ', len(m.active), 'rip = ', hex(addr))
    if sys.argv[1] == 'd':
        try:
            for s in m.active:
                dump_context(s)
            if pdb_stopping_condition():
                pdb.set_trace()     
        except Exception as e:
            print(str(e))
            print("Disassembly not available")
    if(not stopping_condition()):
        m.step()
        try:            
            print('posix out', str(m.active[0].posix.dumps(1))[:100])
            print('posix err', str(m.active[0].posix.dumps(2))[:100])
            # for es in m.errored:
            #     print('Errored: ', es.error)
            #     vl.warning('Errored: ' + str(es.error))
            pass        
        except:
            print('\nno output error')
    else:
        print('System memory too low, exiting')
        break

for s in m.deadended:
    print(f'Out: {s.posix.dumps(1)}')

if len(m.errored) > 0:
    print("============== Errored States ======================")
    for es in m.errored:
        print('Errored: ' + str(es.error))
        vl.warning('Errored: ' + str(es.error))
        print(dump_callstack())

    # print('--')
    # print(len(m.active))
# 8605882639
