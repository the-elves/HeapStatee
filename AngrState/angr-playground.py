#!/usr/bin/env python
# coding: utf-8
import psutil
import sys
sys.path.append('../')
from HeapPlugin.HeapPlugin import HeapPlugin, Malloc, Free
from HeapModel.heapquery import *
import angr
import claripy
import logging
import time
import signal

HOUR = 60*60
time_limit = HOUR/4
l = logging.getLogger('heap_analysis')
h = HeapPlugin(startingAddress=0x2000000)


start_time = time.monotonic()

def initialize_logger(bname):
    global vl
    global l
    bname = bname.split('/')[-1]
    vl = logging.getLogger('vuln_logger')
    vl.addHandler(logging.FileHandler('../reports/vuln-reports/' + bname +'.log', 'w'))
    
    l.addHandler(logging.FileHandler('../reports/logs/'+bname+'.log', 'w'))
    l.setLevel(logging.DEBUG)

    

def initialize_project(b, ss):
    print("[+] hooking malloc")
    b.hook_symbol('malloc', Malloc())
    print("[+] hooking calloc")
    b.hook_symbol('calloc', Malloc())
    print("[+] hooking free")
    b.hook_symbol('free', Free())    
    ss.register_plugin('my_heap', h)
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
            if c.free:
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

    

signal.signal(signal.SIGALRM, alarm_handler)
signal.alarm(int(time_limit))
        

def stopping_condition():
    if psutil.virtual_memory().percent > 90:
        return True

    return False
# binary_name = TestCases/ls
#binary_name = '/bin/ls'
binary_name = sys.argv[1]
b = angr.Project(binary_name, auto_load_libs=True,
                 use_sim_procedures=False,
                 force_load_libs=['../../tools/glibc-dir/install/lib64/libc-2.27.so',
                                  '/home/ajinkya/Guided_HLM/tools/glibc-dir/install/lib64/ld-2.27.so'])
print(b.loader.shared_objects)
# exit() 
# main_addr = b.loader.find_symbol('main').rebased_addr
# print("%x"%(main_addr))
# cfg = b.analyses.CFGFast()
input_chars = [claripy.BVS(f'flag{i}',8) for i in range(20)] + [claripy.BVV('\n', 8)]
argvinp = claripy.Concat(*input_chars)
estate = b.factory.entry_state()#argc = 2, argv = [binary_name, input_chars])
initialize_project(b, estate)
m = b.factory.simulation_manager(estate)
while len(m.active) > 0:
    print('active states = ',len(m.active))
    try:
        m.active[0].block().pp()
    except:
        print("Disassembly not available")
    if(not stopping_condition()):
        m.step()
    else:
        print('System memory too low, exiting')
        break
    # print('--')
    # print(len(m.active))
# 8605882639
