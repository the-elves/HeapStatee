from datetime import datetime
import pickle
import pdb
import code
import sys
next_stopping_addr = -1
special_states=[]
START_TRACKING_FLAG = False
DEBUG=True
VULN_FLAG = False


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
    print(message)
    print(dump_callstack(state))
    heap_state = state.my_heap.heap_state
    heap_state.dump()
    if VULN_FLAG:
        pdb.set_trace()


        
def dump_state(state):
    b=state.project
    today = datetime.now()
    time = today.strftime('%d-%m-%H-%M')
    fname = '../../concretized-files/pickles/' + b.filename.split('/')[-1] + '-state-'+time
    with open(fname,'wb') as f:
        pickle.dump(state, f)


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
    
