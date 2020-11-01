#!/usr/bin/env python
# coding: utf-8
import psutil
import sys
sys.path.append('../')
from HeapPlugin.HeapPlugin import HeapPlugin, Malloc, Free, Calloc, Realloc, Perror
from HeapModel.heapquery import *
import angr
import claripy
import logging
from datetime import datetime
import signal
import pdb
from angr.exploration_techniques import DFS

HOUR = 60*60
time_limit = HOUR/4
l = logging.getLogger('heap_analysis')
h = HeapPlugin(startingAddress=0x2000000)


def initialize_logger(bname):
    global vl
    global l
    bname = bname.split('/')[-1]
    vl = logging.getLogger('vuln_logger')
    vl.addHandler(logging.FileHandler('../reports/vuln-reports/' + bname +'.log', 'w'))
    
    l.addHandler(logging.FileHandler('../reports/logs/'+bname+'.log', 'w'))
    l.setLevel(logging.DEBUG)

    

def initialize_project(b, ss):
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
    ss.inspect.b('mem_write', when=angr.BP_BEFORE, action=bp_action_write)
    initialize_logger(b.filename)
    
    
def handle_heap_write(state):
    write_address = state.solver.eval(state.inspect.mem_write_address)
    wl = state.solver.eval(state.inspect.mem_write_length)
    l.warning("writting to %x for %d bytes" % (write_address, wl))
    i = 0
    vuln = False
    for wi in range(wl):
        wa = write_address + wi
        c = chunk_containing_address(wa, state.my_heap.heap_state)
        if c is None:
            l.warning('Writing outside chunks @ 0x{:x}'.format(write_address))
        else:
            if write_in_free_chunk(wa, state.my_heap.heap_state):
                conc_argv = state.solver.eval(argvinp)
                conc_stdin = state.posix.dumps(1)
                state.block().pp();
                l.warning('write @ {:x} is in free chunk {:x} argv = {} stdin={}'.format(wa, c.address, conc_argv, conc_stdin))
                rip = state.solver.eval(state.regs.rip)
                vl.warning('rip = {:x} write @ {:x} is in free chunk {:x} argv = {} stdin={} write_address = {:x}'.format(rip, wa, c.address, conc_argv, conc_stdin, write_address + wi))
                vl.warning(str(state.callstack))
                vuln = True    
            if metadata_cloberring(wa, state.my_heap.heap_state):
                conc_argv = state.solver.eval(argvinp)
                conc_stdin = state.posix.dumps(1)
                state.block().pp();
                rip = state.solver.eval(state.regs.rip)
                l.warning('Metadata of heap chunk @ 0x{:x} cloberred argv = {} stdin={} write_address = 0x{:x}'.format(c.address, conc_argv, conc_stdin, write_address+wi))
                vl.warning('rip = {:x} Metadata of heap chunk @ 0x{:x} cloberred argv = {} stdin={} write_address = 0x{:x}'.format(rip, c.address, conc_argv, conc_stdin, write_address+wi))
                vl.warning(str(state.callstack))
                vuln = True
    if(vuln):
        h.heap_state.dump()

                

def bp_action_write(state):
    write_address = state.solver.eval(state.inspect.mem_write_address)
    if addr_in_heap(write_address, state.my_heap.heap_state):
        handle_heap_write(state)

def alarm_handler(signum, frame):
    exit()
        

def stopping_condition():
    if psutil.virtual_memory().percent > 90:
        return True

    return False


next_stopping_addr = -1
def pdb_stopping_condition():    
    if m.active[0].solver.eval(m.active[0].regs.rip) == next_stopping_addr or \
       next_stopping_addr == -1:
        return True
    else: return False
    

binary_name = sys.argv[1]
b = angr.Project(binary_name, auto_load_libs=True,
                 use_sim_procedures=False,
                 force_load_libs=['../../tools/glibc-dir/install/lib64/libc-2.27.so',
                                  '/home/ajinkya/Guided_HLM/tools/glibc-dir/install/lib64/ld-2.27.so',
                                  '/home/ajinkya/Guided_HLM/tools/openjpeg/build/bin/libopenjp2.so.2.3.1']
                 )
print(b.loader.shared_objects)

num_sym_bytes = 20
input_chars = [claripy.BVS(f'flag{i}',8) for i in range(num_sym_bytes)] + [claripy.BVV('\n', 8)]
argvinp = claripy.Concat(*input_chars)

# estate = b.factory.entry_state(args = [binary_name, '/f'])
# simfilename = 'mysimfile'
# simfile = angr.SimFile(simfilename, size=5*1024*1024)
# simfile.set_state(estate)
# estate.fs.insert('/f', simfile)


estate = b.factory.entry_state(args = sys.argv[1:])
host_file_system = angr.SimHostFilesystem('/home/ajinkya/Guided_HLM/guest_chroot/')
host_file_system.set_state(estate)
estate.fs.mount('/home/user/exploits/',host_file_system)

# estate = b.factory.entry_state(argc = 2, argv = [binary_name, input_chars])
# for i in range(num_sym_bytes-1):
#     c=argvinp.chop(8)[i]
#     estate.add_constraints(c!=0)
    
initialize_project(b, estate)
m = b.factory.simulation_manager(estate)
m.use_technique(DFS())
# pdb.set_trace()
while len(m.active) > 0:
    now = datetime.now()
    timestr = now.strftime("%H:%M:%S")
    print(timestr, 'active states = ',len(m.active), end='         ')
    if True:
        try:
            for s in m.active:
                print("=============>", m.active)
                s.my_heap.heap_state.dump()
                s.block().pp()
                print(s.callstack)
                if pdb_stopping_condition():
                    pdb.set_trace()     
        except:
            print("Disassembly not available")
    if(not stopping_condition()):
        m.step()
        try:
            print(', posix out', str(m.active[0].posix.dumps(1)), '\r', end='')
            # for es in m.errored:
            #     print('Errored: ', es.error)
            #     vl.warning('Errored: ' + str(es.error))
                    
        except:
            print('\nno output error')
    else:
        print('System memory too low, exiting')
        break
if len(m.errored) > 0:
    print("============== Errored States ======================")
    for es in m.errored:
        print('Errored: ' + str(es.error))
        vl.warning('Errored: ' + str(es.error))
        print(str(es.state.callstack))

    
    # print('--')
    # print(len(m.active))
# 8605882639
