from datetime import date

def dump_concretized_file(state):
    b=state.project
    sf = state.fs.get('/symfiles/mysymfile')
    if sf is None:
        return
    today = date.now()    
    time = today.strftime('%d-%m-%H-%M')
    fname = '../../concretized-files/' + b.filename.split('/')[-1] + '-exp-'+time
    with open(fname, 'wb') as f:
        f.write(sf.concretize())

    
