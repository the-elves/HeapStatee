#!/usr/bin/env python
# coding: utf-8

import angr
import claripy

b = angr.Project('TestCases/UAF')
# estate = b.factory.blank_state(addr=b.loader.find_symbol('main').rebased_addr)
estate = b.factory.entry_state(argc = claripy.BVS('s_argc',32))
m = b.factory.simulation_manager(estate)
while(True):
    m.active[0].block().pp()
    m.step()
    print('--')
    if (len(m.active) > 1 or len(m.active)==0):
        break
print(m.active)
print(b.kb.functions._function_map)