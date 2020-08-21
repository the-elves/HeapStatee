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
l = logging.getLogger('heap_analysis')
h = HeapPlugin(startingAddress=0x500000)


def initialize_project(b, ss):
    print("[+] hooking malloc")
    b.hook_symbol('malloc', Malloc())
    print("[+] hooking calloc")
    b.hook_symbol('calloc', Malloc())
    print("[+] hooking free")
    b.hook_symbol('free', Free())    
    ss.register_plugin('my_heap', h)
    ss.inspect.b('mem_write', when=angr.BP_BEFORE, action=bp_action_write)

def handle_heap_write(state):
    write_address = state.solver.eval(state.inspect.mem_write_address)
    wl = state.solver.eval(state.inspect.mem_write_length)
    l.warning("writting to %x for %d bytes" % (write_address, wl))
    for wi in range(wl):
        wa = write_address + wi
        c = chunk_containing_address(wa, state.my_heap.heap_state)
        if c is None:
            l.warning('Writing outside chunks @ 0x{:x}'.format(write_address))
        else:
            if c.free:
                conc_argc = state.solver.eval(argcinp)
                conc_stdin = state.posix.dumps(1)
                state.block().pp();
                l.warning('write @ {:x} is in free chunk {:x} argc = {} stdin={}'.format(wa, c.address, conc_argc, conc_stdin))

            if metadata_cloberring(wa, state.my_heap.heap_state):
                conc_inp = state.solver.eval(argcinp)
                conc_stdin = state.posix.dumps(1)
                state.block().pp();
                l.warning('Metadata of heap chunk @ 0x{:x} cloberred argc = {} stdin={}'.format(c.address, conc_argc, conc_stdin))
    input()
                

def bp_action_write(state):
    write_address = state.solver.eval(state.inspect.mem_write_address)
    if addr_in_heap(write_address, state.my_heap.heap_state):
        handle_heap_write(state)

# binary_name = TestCases/ls
#binary_name = '/bin/ls'
binary_name = sys.argv[1]
b = angr.Project(binary_name, auto_load_libs=True)

# exit()
# main_addr = b.loader.find_symbol('main').rebased_addr
# print("%x"%(main_addr))
# cfg = b.analyses.CFGFast()
input_chars = [claripy.BVS(f'flag{i}',8) for i in range(20)] + [claripy.BVV('\n', 8)]
argcinp = claripy.Concat(*input_chars)
estate = b.factory.entry_state()#argc = 2, argv = [binary_name, input_chars])
initialize_project(b, estate)
m = b.factory.simulation_manager(estate)
while len(m.active) > 0:
    print('active states = ',len(m.active))
    m.active[0].block().pp()
    if(psutil.virtual_memory().percent < 90):
        m.step()
    else:
        print('System memory too low, exiting')
        break
    # print('--')
    # print(len(m.active))
# 8605882639
