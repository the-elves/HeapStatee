#!/usr/bin/env python
# coding: utf-8
import psutil
import sys
print(sys.getrecursionlimit())
sys.setrecursionlimit(1500)
sys.path.append('../')
from HeapPlugin.HeapPlugin import HeapPlugin, Malloc, Free, Calloc, Realloc, Perror, Posix_Memalign
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
from utils.fcntl import *
from angr import sim_options as o
from HeapModel.Colors import bcolors as c


HOUR = 60*60
time_limit = HOUR*24
start_time = datetime.now()
start = False
last_deferred_count = 0



if sys.argv[1][1] == 's':
    nsa=-1
else:
    nsa=1

l = logging.getLogger('heap_analysis')

logging.getLogger('angr').setLevel('INFO')


def sigquit_handler(signal, frame):
    pass
    if not PYCHARM : pdb.set_trace()
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

def hook_unlocked_functions(b):
    funcs ="getc, getchar, putc, putchar, feof, fflush, fgetc, fputc, fread, fwrite, fgets, fputs".split(", ")
    for f in funcs:
        b.hook_symbol(f+"_unlocked", SIM_PROCEDURES['libc'][f]())

def hook_iso_prefixed_functions(b):
#    funcs ="sscanf, sprintf".split(", ")
    funcs ="sprintf".split(", ")    
    for f in funcs:
        b.hook_symbol("__isoc99_"+f, SIM_PROCEDURES['libc'][f]())

def modify_sim_procedures():
    angr.SIM_PROCEDURES['libc']['malloc'] = Malloc
    angr.SIM_PROCEDURES['libc']['calloc'] = Calloc
    angr.SIM_PROCEDURES['libc']['free'] = Free
    angr.SIM_PROCEDURES['libc']['realloc'] = Realloc
    angr.SIM_PROCEDURES['libc']['posix_memalign'] = Posix_Memalign


def hook_simprocs(b, ss):
    print("[+] hooking malloc")
    b.hook_symbol('malloc', Malloc())
    print("[+] hooking calloc")
    b.hook_symbol("calloc", Calloc())
    print("[+] hooking free")
    b.hook_symbol("free", Free())
    print("[+] hooking realloc")
    b.hook_symbol('realloc', Realloc())
    print("[+] hooking memalign")
    b.hook_symbol('posix_memalign', Posix_Memalign())
    print("[+] hooking perror")
    b.hook_symbol('perror', Perror())

    
    print("[+] hooking fopen64")
    b.hook_symbol('fopen64', SIM_PROCEDURES['libc']['fopen']())

    print("[+] hooking seek")
    b.hook_symbol('fseeko64', SIM_PROCEDURES['libc']['fseek']())

    print("[+] hooking tell")
    b.hook_symbol('ftello64', SIM_PROCEDURES['libc']['ftell']())
    
    print("[+] hooking _unlocked functions")
    hook_unlocked_functions(b)

    print("[+] hooking __isoc99_ functions")
    hook_iso_prefixed_functions(b)

    print("[+] hooking open64")
    b.hook_symbol('open64', SIM_PROCEDURES['posix']['open']())

    print("[+] hooking fstat64")
    b.hook_symbol('fstat64', SIM_PROCEDURES['linux_kernel']['fstat64']())

    print("[+] hooking fstat")
    b.hook_symbol('fstat', SIM_PROCEDURES['linux_kernel']['fstat']())

    '''Experimental be careful might need to remove'''
    print("[+] hooking fcntl")
    b.hook_symbol('fcntl', Fcntl())
    
def initialize_project(b, ss):
    heap_starting_address = get_heap_starting_address(b)
    h = HeapPlugin(startingAddress=heap_starting_address)
    ss.register_plugin('my_heap', h)

    hook_simprocs(b, ss)
    
    ss.inspect.b('mem_write', when=angr.BP_BEFORE, action=bp_action_write)
    ss.inspect.b('mem_read', when=angr.BP_BEFORE, action=bp_action_read)
    initialize_logger(b.filename)
    setup_filesystem(ss)
    VULN_FLAG = False


def handle_heap_read(state):
    read_start_address = state.solver.eval(state.inspect.mem_read_address)
    rl = normalize_size(state, state.inspect.mem_read_expr, state.inspect.mem_read_length)
    # l.warning("reading from %x for %d bytes reading expr"%(read_start_address, rl))
    vuln=False
    for i in range(rl):
        ra = read_start_address + i
        c = chunk_containing_address(ra, state.my_heap.heap_state)
        if c is None:
            l.warning('Read address outside chunk @0x{:x} Possible USE AFTER FREE(None type)'.format(ra))
            vuln=True
        else:
            if access_in_free_chunk(ra, state.my_heap.heap_state):
                rip = state.solver.eval(state.regs.rip)
                l.warning('read @ {:x} is in free chunk {:x} USE AFTER FREE '.format(ra, c.address))
                # vl.warning('rip = {:x} read @ {:x} is in free chunk {:x}  write_address = {:x}'.format(rip, ra, c.address, ra))
                # vl.warning(dump_callstack(state))
                vuln = True
    if(vuln):
        h = state.my_heap
        h.heap_state.dump()
        VULN_FLAG=True
        pass
        if not PYCHARM : pdb.set_trace()
        dump_concretized_file(state)
        
def handle_heap_write(state):
    write_address = state.solver.eval(state.inspect.mem_write_address)
    wl = normalize_size(state, state.inspect.mem_write_expr, state.inspect.mem_write_length)
    wexpr = state.inspect.mem_write_expr
    # l.warning("writting to %x for %d bytes writing expr" % (write_address, wl))
    # l.warning(bvv_to_string(state, wexpr))
    i = 0
    vuln = False
    for wi in range(wl):
        wa = write_address + wi
        c = chunk_containing_address(wa, state.my_heap.heap_state)
        if c is None:
            # l.warning('Writing outside chunks @ 0x{:x}'.format(wa))
            vuln=True
        else:
            if access_in_free_chunk(wa, state.my_heap.heap_state):
                conc_argv = state.solver.eval(argvinp)
                conc_stdin = state.posix.dumps(1)
                state.block().pp();
                # l.warning('write @ {:x} is in free chunk {:x} argv = {} stdin={}'.format(wa, c.address, conc_argv, conc_stdin))
                rip = state.solver.eval(state.regs.rip)
                # vl.warning('rip = {:x} write @ {:x} is in free chunk {:x} argv = {} stdin={} write_address = {:x}'.format(rip, wa, c.address, conc_argv, conc_stdin, write_address + wi))
                # vl.warning(dump_callstack(state))
                vuln = True    
            if metadata_cloberring(wa, state.my_heap.heap_state):
                conc_argv = state.solver.eval(argvinp)
                conc_stdin = state.posix.dumps(1)
                state.block().pp();
                rip = state.solver.eval(state.regs.rip)
                # l.warning('Metadata of heap chunk @ 0x{:x} cloberred argv = {} stdin={} write_address = 0x{:x}'.format(c.address, conc_argv, conc_stdin, write_address+wi))
                # vl.warning('rip = {:x} Metadata of heap chunk @ 0x{:x} cloberred argv = {} stdin={} write_address = 0x{:x}'.format(rip, c.address, conc_argv, conc_stdin, write_address+wi))
                # vl.warning(dump_callstack(state))
                vuln = True
    if(vuln):
        h = state.my_heap
        h.heap_state.dump()
        VULN_FLAG=True
#        temp-----------
#        cons = {}
#        for addr in range(0x2000030, 0x2000031):
#            cons[addr] = addr - 0x2000030
#        constrained_concretize_file(state, cons)
#        ------------
#
        pass
        if not PYCHARM : pdb.set_trace()
        dump_concretized_file(state)



def bp_action_write(state):
    write_address = state.solver.eval(state.inspect.mem_write_address)
    write_length = normalize_size(state, state.inspect.mem_write_expr, state.inspect.mem_write_length)
    # if write_address <= 0x1f07b20 and 0x1f07b20 <= write_address + write_length: 
    #     print("writing to got")
    # if not PYCHARM : pdb.set_trace()
    if addr_in_heap(write_address, state.my_heap.heap_state):
        handle_heap_write(state)

def bp_action_read(state):
    read_address = state.solver.eval(state.inspect.mem_read_address)
    read_length = normalize_size(state, state.inspect.mem_read_expr, state.inspect.mem_read_length)
    # if write_address <= 0x1f07b20 and 0x1f07b20 <= write_address + write_length: 
    #     print("writing to got")
    # if not PYCHARM : pdb.set_trace()
    if addr_in_heap(read_address, state.my_heap.heap_state):
        handle_heap_read(state)


def setup_filesystem(estate):
    host_file_system = angr.SimHostFilesystem('../../guest_chroot/')
    host_file_system.set_state(estate)
    estate.fs.mount('/exploits',host_file_system)
    
    symfilename = 'mysymfile'
    symfile = angr.SimFile(symfilename, size=200*1024)
    symfile.set_state(estate)
    if 'SYMFILE_NAME' in os.environ.keys():
        estate.fs.insert(os.environ['SYMFILE_NAME'], symfile)
    # else:
    #     estate.fs.insert('/symfiles/mysymfile', symfile)

    
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
    global nsa
    global m
    global last_deferred_count
    last_deffered_count_holder = last_deferred_count
    last_deferred_count = len(m.deferred)
    try:
        current_addresses = m.active[0].block().instruction_addrs
        if checkpoint_address in current_addresses and sys.argv[2] != 'l':
            print("creating checkpoint ", hex(m.active[0].addr))
            dump_checkpoint(m, str(hex(m.active[0].addr)) + ".ckp")
        # if len(m.deferred) > last_deffered_count_holder:
        #     print("Deferred stated added.")
        #     return True
        if len(m.deferred) < last_deffered_count_holder:
            print("Deferred stated removed.")
            return True
        if nsa in current_addresses  or \
           nsa == -1:
            return True
    except angr.SimEngineError as e:
        print("Disassembly not available")
    # elif len(m.deferred) > last_deferred_count:
    #     print("Stopping reason: deferred state added")
    #     last_deferred_count+=1
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

parsePlaylistCount = 0
binary_name = sys.argv[2]
loader_libraries = ['../../tools/glibc-dir/install/lib64/libc-2.27.so',
                                  '../../tools/glibc-dir/install/lib64/ld-2.27.so']

# sim_procedure_blacklist = ['fopen', 'fclose']
if 'HEAPSTATE_LIBS' in os.environ.keys():
    loader_libraries.extend(os.environ['HEAPSTATE_LIBS'].split(' '))

print('External Libraries ', loader_libraries)
modify_sim_procedures()
b = angr.Project(binary_name, auto_load_libs=True,
                 force_load_libs=loader_libraries,
                 exclude_sim_procedures_list =  ["__isoc99_sscanf"]
                 )

print_libs(b)


num_sym_bytes = 20
input_chars = [claripy.BVS(f'flag{i}',8) for i in range(num_sym_bytes)] + [claripy.BVV('\n', 8)]
argvinp = claripy.Concat(*input_chars)


stdin_bytes_list = [claripy.BVS('byte_%d' % i, 8) for i in range(3200)]
stdin_bytes_ast = claripy.Concat(*stdin_bytes_list)

add_options = [o.USE_SYSTEM_TIMES, o.MEMORY_CHUNK_INDIVIDUAL_READS]
remove_options = [o.ALL_FILES_EXIST]
estate = b.factory.entry_state(args = sys.argv[2:], add_options=add_options, remove_options=remove_options) #, stdin=angr.SimFile('/dev/stdin', content=stdin_bytes_ast))

#estate = b.factory.entry_state(argc = 2, argv = [binary_name, input_chars])
# for i in range(num_sym_bytes-1):
#     c=argvinp.chop(8)[i]
#     estate.add_constraints(c!=0)
    
initialize_project(b, estate)

print("Heap starting at ", hex(estate.my_heap.heap_state.startAddress))

if sys.argv[1][2] == 'l':
    cp_name = '0x4eca00.ckp'
    print("loading checkpoint ", cp_name)
    stashes = load_checkpoint(cp_name)
    m = b.factory.simulation_manager([],stashes=stashes)
else:
    m = b.factory.simulation_manager(estate)
m.use_technique(DFS())


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
    print('no active stashes ', len(m.active), "no. deferred ", len(m.deferred))
    #print('stashes ', m.active)    
    if sys.argv[1][0] == 'd':
        try:
            for s in m.active:
                dump_context(s)
            pass
            if pdb_stopping_condition():
                if not PYCHARM : pdb.set_trace()
        except angr.SimEngineError as e:
            print(str(e))
            print("Disassembly not available")
            
    if(not stopping_condition()):
        try:
            if 0x08f6490 in m.active[0].block().instruction_addrs:
                parsePlaylistCount+=1
        except angr.SimEngineError as e:
            print("Disassembly not available")
        try:
            m.step()
            if len(m.active) > 0:
                print(c.ENDC, 'posix out', str(m.active[0].posix.dumps(1))[:100], c.ENDC)
                print(c.ENDC, 'posix err', str(m.active[0].posix.dumps(2))[:100], c.ENDC)
            print('parsePlaylistCount', parsePlaylistCount)
            # for es in m.errored:
            #     print('Errored: ', es.error)
            #     vl.warning('Errored: ' + str(es.error))
            pass        
        except angr.SimEngineError as e:
            raise e
            if "No bytes" not in str(e):
                pass
                if not PYCHARM : pdb.set_trace()
#        except:
            print('\nno output error')
            print(str(e))
        except Exception as e:
            raise(e)

    else:
        print('System memory too low, exiting')
        break

for s in m.deadended:
    print(f'Out: {s.posix.dumps(1)}')

if len(m.errored) > 0:
    print("============== Errored States ======================")
    for es in m.errored:
        print(sys.argv)
        print('Errored: ' + str(es.error))
        # vl.warning('Errored: ' + str(es.error))
        print(dump_callstack(es.state))

    # print('--')
    # print(len(m.active))
# 8605882639
