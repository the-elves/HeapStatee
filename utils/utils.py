from datetime import datetime
import pickle
import pdb
import code
import sys

checkpoint_address = 0
nsa = -1
START_TRACKING_FLAG = False
DEBUG=True
VULN_FLAG = False
PYCHARM = True

def radar_breakpoint():
    global PYCHARM
    if not PYCHARM:
        pdb.set_trace()


def normalize_size(state, data, size):
    if size is not None:
        return state.solver.eval(size)
    max_size = len(data) // state.arch.byte_width
    if size is None:
        out_size = max_size
    elif type(size) is int:
        out_size = size
    elif getattr(size, 'op', None) == 'BVV':
        out_size = size.args[0]
    else:
        raise Exception("Size must be concretely resolved by this point in the memory stack")
    return state.solver.eval(out_size)

def constrained_concretize_file(state, constraints):
    b=state.project
    today = datetime.now()
    time = today.strftime('%d-%m-%H-%M')
    sym_file_name = '/symfiles/mysymfile'
    fname = '../../concretized-files/' + b.filename.split('/')[-1] + '-constrined-exp-'+time
    sf = state.fs.get(sym_file_name)
    ec = []
    
    for addr,value in constraints.items():
        mem = state.mem[addr].byte.resolved
        ec.append( mem == value)
    file_contents = sf.concretize(extra_constraints=ec)
    if all([x == 0 for x in file_contents]):
        print('All zeros in concretized files, skipping')
    else:
        with open(fname, 'wb') as f:
            f.write(file_contents)

def bvv_to_string(state, bvv):
    
    try:
        chops = bvv.chop(8)
    except:
        print(bvv)
        print("cannot chop into 8")
        return ''
    string = ''.join([chr(state.solver.eval(chop)) for chop in chops])
    return '**' + string + '**'

def dump_concretized_file(state):
    b=state.project
    sym_file_name = '/symfiles/mysymfile'
    sf = state.fs.get(sym_file_name)
    if sf is None:
        return
    today = datetime.now()
    time = today.strftime('%d-%m-%H-%M')
    print("concretizing file", sym_file_name)
    fname = '../../concretized-files/' + b.filename.split('/')[-1] + '-exp-'+time
    file_contents = sf.concretize()
    if all([x == 0 for x in file_contents]):
        print('All zeros in concretized files, skipping')
    else:
        with open(fname, 'wb') as f:
            f.write(file_contents)
        fname = '../../concretized-files/stdins/' + b.filename.split('/')[-1] + '-exp-'+time
        print("Concretizing stdin")
        with open(fname, 'wb') as f:
            f.write(state.posix.dumps(0))
        dump_state(state)
        if sys.argv[1] == 'ds':
            next_stopping_addr=-1
            code.interact(local=locals())

def debug_dump(state, message):
    global VULN_FLAG
    print(message)
    print(dump_callstack(state))
    heap_state = state.my_heap.heap_state
    heap_state.dump()
    if VULN_FLAG:
        VULN_FLAG = False
        pass
        # pdb.set_trace()


def inconsistent_breakpoint():
    print("heap state inconsistent")
    pass
    # pdb.set_trace()


def dump_state(state, state_name=None):
    b=state.project
    today = datetime.now()
    time = today.strftime('%d-%m-%H-%M')
    fname = '../../concretized-files/pickles/'
    if state_name is not None:
        fname=fname + state_name
    else:
        fname += b.filename.split('/')[-1] + '-state-'+time

    with open(fname,'wb') as f:
        pickle.dump(state, f)

def load_state(state_name):
    with open(state_name, 'rb') as f:
        state = pickle.load(f)
    return state

def dump_checkpoint(m, cp_name=None):
    if cp_name is None:
        cp_name = str(hex(m.active[0].addr))+'.ckp'
    with open(cp_name, 'wb') as f:
        pickle.dump(m.stashes, f)


def load_checkpoint(cp_name):
    with open(cp_name, 'rb') as f:
        stashes = pickle.load(f)
    return stashes
        

def dump_callstack(state):
    cs = state.callstack

    callstack_string = ""
    for frame in cs:
        name = get_function_name(state, frame.func_addr)
        callstack_string = callstack_string + '\n' + hex(frame.call_site_addr)+ " => " +  hex(frame.func_addr) +  f"({name})"
    return callstack_string


def get_function_name(state, address):
    ldr = state.project.loader
    allobjs = state.project.loader.all_elf_objects
    mainobj = state.project.loader.main_object
    name = ''
    sym = ldr.find_symbol(address)    
    if sym is None:
        name = ''
    else:
        name = sym.name
    if name == '':
        for obj in allobjs:
            if address in obj.reverse_plt.keys():
                name=obj.reverse_plt[address]
            if name is None:
                name = ''    
    return name
    
