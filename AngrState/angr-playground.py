#!/usr/bin/env python
# coding: utf-8
from HeapPlugin.HeapPlugin import HeapPlugin, Malloc, Free
import angr
import claripy

def initialize_project(b, ss):
    b.hook_symbol('malloc', Malloc())
    b.hook_symbol('free', Free())
    h = HeapPlugin()
    ss.register_plugin('my_heap', h)


b = angr.Project('TestCases/UAF')
# estate = b.factory.blank_state(addr=b.loader.find_symbol('main').rebased_addr)
# cfg = b.analyses.CFGFast()
estate = b.factory.entry_state(argc=claripy.BVS('s_argc', 64))
initialize_project(b, estate)
m = b.factory.simulation_manager(estate)
while True:
    # m.active[0].block().pp()
    m.step()
    # print('--')
    if (len(m.active) > 1 or len(m.active)==0):
        break
print(m.active)
