import angr
from angr.exploration_techniques import DFS
from pathlib import Path
from enum import Enum
from pydantic import BaseModel, ValidationError
from typing import Any, List
import argparse
import claripy
import pickle


class Error(angr.SimProcedure):
    def run(self,status, error_num):
        error_no = self.state.solver.eval(error_num)
        print("Errored and exited", error_no)
        self.exit(error_num) 

class SetLocale(angr.SimProcedure):
    def run(self):
        print("Setlocale skipped")
        return 

class MemAccessType(Enum):
    MEM_READ = "READ"
    MEM_WRITE = "WRITE"

class MemAccess(BaseModel):
    access_type: MemAccessType
    address: Any
    value: Any
    is_addr_symbolic: bool 
    is_value_symbolic: bool

class Fuzzer:
    binary_path: Path
    project = angr.Project
    mgr = angr.SimulationManager
    memory_accesses: List[MemAccess] = []
    cfg: angr.analyses.CFGFast
    callstack = []
    visited_addresses = []
    argv = []
    num_ended = 0

    def __init__(self, path: Path):
        self.binary_path = path
        self.setup()
        
    def get_called_function_name(self, state, addr):
        concrete_address = state.solver.eval(addr)
        return self.cfg.kb.functions.ceiling_func(concrete_address).name

    def call(self, s):
        concrete_address = s.solver.eval(s.inspect.function_address)
        called_function = self.cfg.kb.functions.ceiling_func(concrete_address).name
        self.callstack.append(called_function)
        if called_function == "malloc" or \
            called_function == "calloc":
            print("malloc called")

    def ret(self, s):
        if len(self.callstack) == 0:
            return
        self.callstack.pop()

    def hook_procedures(self, s: angr.SimState) -> angr.SimState:
        # s.inspect.b("call", when=angr.BP_BEFORE, action=self.call)
        # s.inspect.b("return", when=angr.BP_BEFORE, action=self.ret)
        self.project.hook_symbol("setlocale", SetLocale())
        self.project.hook_symbol("error", Error())
        return s

    def link_concrete_file(self, state: angr.SimState, path:Path):
        file_content = path.read_bytes()
        file = angr.SimFile(path, content=file_content)
        file.set_state(state)
        state.fs.insert(path, file)


    def gen_cfg(self):
        cfg_path = Path("cached-cfg")/self.binary_path.name
        cfg_path = cfg_path.with_suffix(".pkl")
        if cfg_path.exists():
            print("[+] Found cached cfg at ", cfg_path.as_posix())
            with open(cfg_path, "rb") as f:
                self.cfg = pickle.load(f)
            return
        self.cfg = self.project.analyses.CFGFast()
        with open(cfg_path, "wb") as f:
            pickle.dump(self.cfg, f)
        print("dumping cfg at ", cfg_path.as_posix())

    def setup(self):
        self.project = angr.Project(self.binary_path)
        self.gen_cfg()
        print("Loaded libraries: ", self.project.loader.all_objects)
        print("Use simprocedures", self.project.use_sim_procedures)
        self.argv = [claripy.BVS("inp_"+str(i),8) for i in range(100) ]

        init_state = self.hook_procedures(self.project.factory.entry_state(args = self.argv) )
        # init_state.options['ALL_FILES_EXIST'] = False
        init_state.libc.max_variable_size = 0x2048
        
        
        self.mgr = self.project.factory.simulation_manager(init_state)
        self.mgr.use_technique(DFS())
    
    def process_memory_read(self, state):
        read_address = state.inspect.mem_read_address
        read_value = state.inspect.mem_read_expression
        self.memory_accesses.append(MemAccess(MemAccessType.MEM_READ), read_address, read_value, read_address.symbolic, read_value.symbolic)

    def process_memory_write(self, state):
        address = state.inspect.mem_read_address
        value = state.inspect.mem_read_expression
        self.memory_accesses.append(MemAccess(MemAccessType.MEM_READ), address, value, address.symbolic, value.symbolic)

    def dump_callstack(self, state: angr.SimState):
        print("----- call stack start -----")
        for frame in state.callstack:
            fun = self.cfg.kb.functions.ceiling_func(frame.func_addr)
            if fun:
                print(fun.name)
            else :
                print("<Unidentified function>")
        print("----- call stack start -----")

    def dump_state(self, state: angr.SimState):

        self.dump_callstack(state)
        # if stdin == b'' and stdout == b'' and stderr == b'':
        #     return
        self.print_args(state, 5)
        print("STDIN", state.posix.stdin.concretize())
        print("STDOUT", state.posix.stdout.concretize())
        print("STDERR", state.posix.stderr.concretize())
    
    def shuffle_mgr(self):
        if len(self.mgr.deferred) == 0:
            return
        new_active = None
        for s in self.mgr.deferred:
            if s.addr in self.visited_addresses:
                continue
            new_active = s
            break
        if new_active is None:
            return
        current_addr = self.mgr.active.pop()
        self.mgr.deferred.remove(new_active)
        self.mgr.active.append(new_active)
        self.mgr.deferred.append(current_addr)

    def print_args(self, state, len=100):
        print("ARGV", [chr(state.solver.eval(v)) for v in self.argv[:len]])

    def check_finished_states(self):
        if len(self.mgr.deadended) > self.num_ended:
            print("Found deadended")
            finished_state = self.mgr.deadended[-1]
            self.num_ended+=1
            self.dump_state(finished_state)
            # input()
            
    def run(self):
        while len(self.mgr.active) > 0:
            # current_addr = self.mgr.active[0].addr
            # if current_addr in self.visited_addresses:
            #     self.shuffle_mgr()
            # else:
            #     self.visited_addresses.append(current_addr)
            # print(self.mgr)
            # self.mgr.active[0].block().pp()
            # self.print_args(self.mgr.active[0], 5)
            self.dump_state(self.mgr.active[0])
            # input()
            self.mgr.step()
            self.check_finished_states()
            # print("============================")

        for s in self.mgr.deadended:
            self.dump_state(s)

            
            
                
if __name__ == '__main__':
    parser = argparse.ArgumentParser("A program to profile memory read and writes")
    parser.add_argument("binary", type=str, help="The binary to be examined")
    args = parser.parse_args()
    f = Fuzzer(Path(args.binary))
    f.run()
