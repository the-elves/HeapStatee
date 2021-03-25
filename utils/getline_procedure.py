import angr

class getline(angr.SimProcedure):
    # char **lineptr
    # size_t *n
    #
    def run(self,pplineptr, psize, fp):
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        
        readLenght=0
        getc = angr.SIM_PROCEDURES['libc']['fgetc']
        while True:
            
            self.state.solver.If(self.state.solver.Or(size == 0, nm == 0), 0, ret // size)
