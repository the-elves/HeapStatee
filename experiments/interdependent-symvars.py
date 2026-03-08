from pathlib import Path
import sys
p = Path.cwd()
sys.path.extend((p.parent/'helpers').as_posix())
import angr
from pathlib import Path
import claripy
from CFGHelpers import get_cfg
from FunctionHelpers import get_function_name


def dump_regs(s):
    e = s.solver.eval
    for n in [rn for rn in dir(s.regs) if rn[0] == 'r']:
        reg = getattr(s.regs, n)
        print(n,':', reg)

class Executor:
    def __init__(self, bin_path:Path, n: int, sym_size: int):
        self.bin_path = bin_path
        self.project = angr.Project(self.bin_path, cache_limits={"functions": None, "cfg_edges": None, "cfg_nodes": None})
        self.num_args = n
        self.sym_size = sym_size
        self.initialize_init_state()
        self.sim_mgr = self.project.factory.simulation_manager(self.init_state)
        self.cfg = get_cfg(self.project)


    def initialize_init_state(self):
        argv = [ claripy.BVS("argv_"+str(i), 8*self.sym_size) for i in range(self.num_args) ]
        argv.insert(0, claripy.BVV(self.bin_path))
        self.init_state = self.project.factory.full_init_state(argc=2, args=argv)

    def run_till_main(self):
        main_symbol = self.project.loader.find_symbol('main')
        if main_symbol is None:
            print("Could not find 'main' symbol.")
            return
        
        main_addr = main_symbol.rebased_addr
        print(f"Running until main at {hex(main_addr)}...")
        
        while len(self.sim_mgr.active) > 0:
            if any(s.addr == main_addr for s in self.sim_mgr.active):
                print("\nReached main.")
                self.sim_mgr.move(from_stash='active', to_stash='found', filter_func=lambda s: s.addr == main_addr)
                self.sim_mgr.move(from_stash='found', to_stash='active')
                return
            
            # Display current function for the first active state
            current_state = self.sim_mgr.active[0]
            func_name = get_function_name(self.cfg, current_state.addr)
            print(f"\r[+] Executing in: {func_name} ({hex(current_state.addr)})", end="", flush=True)
            
            self.sim_mgr.step()
        
        print("\nFailed to reach main.")


    def run(self):
        self.run_till_main()
        while(len(self.sim_mgr.active) > 0 ):
            print(self.sim_mgr)
            for state in self.sim_mgr.active:
                state.block().pp()
                print(state.ip_constraints)
            self.sim_mgr.step()
            input()
            print("===================DFS state ended================")

    
if __name__ == '__main__':
    t = Executor(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
    t.run()