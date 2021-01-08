from datetime import datetime
import pickle
import pdb
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
    with open(fname, 'wb') as f:
        f.write(sf.concretize())
    fname = '../../concretized-files/stdins/' + b.filename.split('/')[-1] + '-exp-'+time
    print("Concretizing stdin")
    with open(fname, 'wb') as f:
        f.write(state.posix.dumps(0))
    dump_state(state)

def dump_state(state):
    b=state.project
    today = datetime.now()
    time = today.strftime('%d-%m-%H-%M')
    fname = '../../concretized-files/pickles/' + b.filename.split('/')[-1] + '-state-'+time
    with open(fname,'wb') as f:
        pickle.dump(state, f)


def dump_callstack(state):
    cs = state.callstack
    ldr = state.project.loader
    allobjs = state.project.loader.all_elf_objects
    mainobj = state.project.loader.main_object
    for frame in cs:
        name = ''
        for obj in allobjs:
            pdb.set_trace()
            if frame.func_addr not in obj.reverse_plt.keys():
                continue
            name = obj.reverse_plt[frame.func_addr]
            if frame.func_addr in mainobj.reverse_plt.keys():
                name = mainobj.reverse_plt[frame.func_addr]
            if name != '':
                break
        print(hex(frame.call_site_addr), "=>", hex(frame.func_addr), f"({name})")
