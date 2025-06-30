import angr
from angr.exploration_techniques import DFS
from pathlib import Path
from enum import Enum
import angr.sim_type
from pydantic import BaseModel, ValidationError
from typing import Any, List
import argparse
import claripy
import pickle
import traceback
import os
import random
import time
import json

class Error(angr.SimProcedure):
    def run(self,status, error_num):
        error_no = self.state.solver.eval(error_num)
        if error_no != 0:
            print("Errored and exited", error_no)
            self.exit(error_num) 

class DCGetText(angr.SimProcedure):
    def run(self,domain, msg, category):
        self.ret( msg)

class FPrinfChk(angr.SimProcedure):
    def run(self, file, flag, fmt, arg1, arg2, arg3, arg4, arg5):
        self.inline_call(angr.SIM_PROCEDURES['libc']['fprintf'], file, fmt, 
                         arg1, 
                         arg2, 
                         arg3,
                         arg4, 
                         arg5)

class SetLocale(angr.SimProcedure):
    def run(self):
        print("Setlocale skipped")
        return 

class MemAccessType(Enum):
    MEM_READ = "READ"
    MEM_WRITE = "WRITE"

class MemLayoutType(Enum):
    MALLOC = "MALLOC"
    FREE = "FREE"

class MemAccess(BaseModel):
    ip: Any
    address: Any
    is_addr_symbolic: bool 
    concretization_time: int
    num_states_encountered: int
    callstack: List[str]
    input: str
    stdin: str

class MemLayout(BaseModel):
    ip: Any
    access_type: MemLayoutType
    arg: Any
    is_arg_symbolic: bool
    concretization_time: int
    num_states_encountered: int
    callstack: List[str]
    input: str
    stdin: str


class Fuzzer:
    binary_path: Path
    project = angr.Project
    mgr = angr.SimulationManager
    cfg: angr.analyses.CFGFast
    callstack = []
    visited_addresses = []
    argv = []

    num_ended = 0
    num_errored = 0
    loader_libs = []
    results_dir: Path
    mem_accesses_path: Path
    mem_layouts_path: Path
    inputs_path: Path

    memory_accesses: List[MemAccess] = []



    def __init__(self, args):
        self.binary_path = Path(args.binary)
        self.loader_libs.append("./libs/libc.so.6")
        random.seed(100)
        self.setup_paths()
        self.argv = [claripy.BVS("inp_"+str(i),8*20) for i in range(args.num_sym_args) ]
        self.setup()

    def setup_paths(self):
        self.results_dir = Path("experiments/results")/Path(self.binary_path.name)
        if not self.results_dir.exists():
            self.results_dir.mkdir()
        self.mem_accesses_path = self.results_dir/Path("mem_accesses.json")
        self.mem_layouts_path = self.results_dir/Path("mem_layouts.json")
        self.inputs_path = self.results_dir/Path("inputs.txt")

        if(self.mem_accesses_path.exists()):
            self.mem_accesses_path.unlink()
        if(self.mem_layouts_path.exists()):
            self.mem_layouts_path.unlink()
        if(self.inputs_path.exists()):
            self.inputs_path.unlink()
        
        self.mem_accesses_path.touch()
        self.mem_layouts_path.touch()
        self.inputs_path.touch()
        
    def record_address_concretization(self, state: angr.SimState):
        ip = state.addr
        address = state.inspect.address_concretization_expr
        is_addr_symbolic = state.solver.symbolic( state.inspect.address_concretization_expr)
        concretization_time = 0
        if is_addr_symbolic:
            now = time.time()
            state.solver.eval(address)
            concretization_time = time.time() - now
        num_states = self.num_ended + len(self.mgr.deferred)
        callstack = self.get_callstack(state)
        inp = self.get_args(state)
        stdin = state.posix.dumps(0)
        mem_access = MemAccess(ip=str(ip), 
                               address=str(address),
                                is_addr_symbolic= is_addr_symbolic,
                                 concretization_time= concretization_time,
                                  num_states_encountered= num_states,
                                   callstack= callstack,
                                    input= inp,
                                     stdin= stdin)
        with open(self.mem_accesses_path, "+a") as f:
            j = json.loads(mem_access.model_dump_json())
            json.dump(j, f)
        

    def record_mem_layout_call(self, state: angr.SimState, mem_type: MemLayoutType):
        ip = state.addr
        access_type = mem_type
        charp = angr.sim_type.SimTypePointer(angr.sim_type.SimTypeChar())
        malloc_type = angr.sim_type.SimTypeFunction([angr.sim_type.SimTypeInt()], charp )
        free_type = angr.sim_type.SimTypeFunction([charp], None)
        if access_type == MemLayoutType.FREE:
            arg = self.project.factory.cc().get_args(state, free_type)[0]
        if access_type == MemLayoutType.MALLOC:
            arg = self.project.factory.cc().get_args(state, malloc_type)[0]
        is_arg_symbolic = state.solver.symbolic(arg)
        concretization_time = 0
        if is_arg_symbolic:
            now = time.time()
            state.solver.eval(arg)
            concretization_time = time.time() - now
        num_states = self.num_ended + len(self.mgr.deferred)
        callstack = self.get_callstack(state)
        inp = self.get_args(state)
        stdin = state.posix.dumps(0)
        mem_access = MemLayout(ip = str(ip), 
                               access_type= access_type, 
                               arg=str(arg),
                                is_arg_symbolic= is_arg_symbolic, 
                                concretization_time=concretization_time, 
                                num_states_encountered = num_states, 
                                callstack=callstack, 
                                input=inp, 
                                stdin = stdin)
        with open(self.mem_layouts_path, "+a") as f:
            j = json.loads(mem_access.model_dump_json())
            json.dump(j, f)
            f.write("\n")

    def record_input(self, state: angr.SimState):
        with open(self.inputs_path, "a+") as f:
            f.write(self.get_args(state))
    
    def get_called_function_name(self, state, addr):
        concrete_address = state.solver.eval(addr)
        return self.cfg.kb.functions.ceiling_func(concrete_address).name

    def call(self, s):
        concrete_address = s.solver.eval(s.inspect.function_address)
        called_function = self.cfg.kb.functions.ceiling_func(concrete_address).name
        self.callstack.append(called_function)
        if called_function == "malloc" or \
            called_function == "calloc" or called_function == "xmalloc":
            self.record_mem_layout_call(s, MemLayoutType.MALLOC)
        elif called_function == "free":
            self.record_mem_layout_call(s, MemLayoutType.FREE)

    def ret(self, s):
        if len(self.callstack) == 0:
            return
        self.callstack.pop()

    

    def hook_procedures(self, s: angr.SimState) -> angr.SimState:
        s.inspect.b("address_concretization", when=angr.BP_BEFORE, action=self.record_address_concretization)
        s.inspect.b("call", when=angr.BP_BEFORE, action=self.call)
        # s.inspect.b("return", when=angr.BP_BEFORE, action=self.ret)
        # self.project.hook_symbol("setlocale", SetLocale())
        self.project.hook_symbol("__fprintf_chk", FPrinfChk())
        self.project.hook_symbol("error", Error())
        self.project.hook_symbol("dcgettext", DCGetText())
        self.project.hook_symbol("setlocale", SetLocale())
        self.project.hook_symbol("_IO_vfwprintf", angr.SIM_PROCEDURES['libc']['fprintf']())
        self.project.hook_symbol("_IO_vfprintf", angr.SIM_PROCEDURES['libc']['fprintf']())
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
        self.project = angr.Project(self.binary_path, force_load_libs = self.loader_libs)
        self.gen_cfg()
        print("Loaded libraries: ", self.project.loader.all_objects)
        print("Use simprocedures", self.project.use_sim_procedures)
        args = [self.binary_path.name] + self.argv
        init_state = self.project.factory.entry_state(args = args, stdin=claripy.BVS("stdin", 8*10), env=os.environ)
        init_state = self.hook_procedures(init_state)
        init_state.options['ALL_FILES_EXIST'] = False
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

    def get_callstack(self, state:angr.SimState) -> List[str]:
        callstr = []
        for frame in state.callstack:
            fun = self.cfg.kb.functions.ceiling_func(frame.func_addr)
            if fun:
                callstr.append( fun.name)
            else :
                print("<Unidentified function>")
        return callstr

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
        print()
        state.block().pp()
        self.dump_callstack(state)
        # if stdin == b'' and stdout == b'' and stderr == b'':
        #     return
        self.print_args(state, 5)
        print(hex(state.addr))
        print("STDIN:", end="")
        try: 
            s = state.posix.dumps(0).decode()
            print(s)
        except Exception:
            print(state.posix.dumps(0))
        print("STDOUT:", end="")
        try: 
            s = state.posix.dumps(1).decode()
            print(s)
        except Exception:
            print(state.posix.dumps(1))
        print("STDERR:", end="")
        try: 
            s = state.posix.dumps(2).decode()
            print(s)
        except Exception:
            print(state.posix.dumps(2))
    
    def shuffle_mgr(self):
        if len(self.mgr.deferred) == 0:
            return
        new_active = self.mgr.deferred[-1]
        # for s in self.mgr.deferred:
        #     if s.addr in self.visited_addresses:
        #         continue
        #     new_active = s
        #     break
        if new_active is None:
            return
        current_state = self.mgr.active.pop()
        self.mgr.deferred.remove(new_active)
        self.mgr.active.append(new_active)
        self.mgr.deferred.append(current_state)

    def get_args(self, state:angr.SimState, len=100):
        argc = state.solver.eval(state.posix.argc)
        pargv = state.posix.argv
        args = ''
        for i in range(argc):
            arg_i = state.mem[pargv+i*state.arch.byte_width].uint64_t.resolved
            args += f""
            j=0
            while True:
                arg_i_j = state.solver.eval(state.mem[arg_i+j].uint8_t.resolved)
                if arg_i_j == 0:
                    break
                args += chr(arg_i_j)
                j+=1
            args+='\n---\n'
        args+="\n===\n"
        return args
    
    def print_args(self, state:angr.SimState, len=100):
        argc = state.solver.eval(state.posix.argc)
        pargv = state.posix.argv
        for i in range(argc):
            arg_i = state.mem[pargv+i*state.arch.byte_width].uint64_t.resolved
            print(f"ARGV{i}: '", end="")
            j=0
            while True:
                arg_i_j = state.solver.eval(state.mem[arg_i+j].uint8_t.resolved)
                if arg_i_j == 0:
                    break
                print(chr(arg_i_j), end="")
                j+=1
            print(end="'         ")
        print()


    def check_finished_states(self):
        if len(self.mgr.deadended) > 1:
            print("Dead ended")
            self.dump_state(self.mgr.deadended[-1])
            self.mgr.deadended.pop()
            self.record_input(self.mgr.deadended[-1])
            self.num_ended+=1
            del self.mgr.deadended[-1]

            print("deleted deadended")
            print(self.mgr)
        if len(self.mgr.errored) > 1:
            print("Errored")
            try:
                raise self.mgr.errored[-1].error
            except Exception:
                print(traceback.format_exc())
            self.dump_state(self.mgr.errored[-1].state)
            self.mgr.errored.pop()
            del self.mgr.errored[-1]
            print("deleted errored")
        # if len(self.mgr.deadended) > 0:
        #     self.mgr.deadended.pop()
        # if len(self.mgr.errored) > 0:
        #     self.mgr.errored.pop()
            
    def run(self):
        while len(self.mgr.active) > 0:
            current_addr = self.mgr.active[0].addr
            if current_addr in self.visited_addresses:
                self.shuffle_mgr()
            else:
                self.visited_addresses.append(current_addr)
            print(f"\r {hex(self.mgr.active[0].addr)} {self.mgr}", end = "")
            # self.mgr.active[0].block().pp()
            # self.print_args(self.mgr.active[0], 5)
            # self.dump_state(self.mgr.active[0])
            # input()
            # print(f"\r {hex(self.mgr.active[0].addr)}", end="")
            self.mgr.step()
            self.check_finished_states()
            # print("============================")
        print(self.mgr)
        for s in self.mgr.deadended:
            self.dump_state(s)

            
            
                
if __name__ == '__main__':
    parser = argparse.ArgumentParser("A program to profile memory read and writes")

    parser.add_argument("binary", type=str, help="The binary to be examined")
    parser.add_argument("num_sym_args", type=int, help="number of arguments to be passed as symbolic")
    args = parser.parse_args()
    f = Fuzzer(args)
    f.run()
