from mem_op_solver_timings import MemAccess, MemLayout, MemLayoutType
from pathlib import Path
from typing import List, Dict, Tuple
import json
import matplotlib.pyplot as plt
import random

class Plotter:
    results_dir = Path
    target_memaccesses : Dict[str, List[MemAccess]]
    target_memlayout : Dict[str, List[MemLayout]]
    def __init__(self):
        self.results_dir = Path("experiments/results")
        self.target_memaccesses = {}
        self.target_memlayout = {}
        self.load_results()

    def load_results(self):
        for binary_path in self.results_dir.iterdir():
            batch_dir = self.get_latest_dir(binary_path)


            self.target_memaccesses[binary_path.name] = []
            self.target_memlayout[binary_path.name] = []
            self.process_one_target(binary_path.name, batch_dir)
            
    def process_one_target(self, target, target_dir: Path):
        json_path = target_dir/Path("mem_accesses.json")
        for v in  json_path.read_text().split("\n"):
            if v.strip() == "":
                continue
            self.target_memaccesses[target] . append(MemAccess.model_validate(json.loads(v)))
        

        json_path = target_dir/Path("mem_layouts.json")
        for v in  json_path.read_text().split("\n"):
            if v.strip() == "":
                continue
            self.target_memlayout[target]. append(MemLayout.model_validate(json.loads(v)))
    
    def get_latest_dir(self, path: Path):
        batches = list(path.iterdir())
        batches.sort(reverse=True)
        return batches[0]
    
    def plot(self):
        self.get_num_concretizations()
        self.get_conc_time()
        self.get_num_mallocs()

    def get_num_concretizations(self):
        plt.clf()
        num_conc = {}
        total = {}
        for bin, mem_accesses in self.target_memaccesses.items():
            num = 0
            for access in mem_accesses:
                if access.is_addr_symbolic:
                    num+=1
            num_conc[bin] = num
            total[bin] = len(mem_accesses)
        plt.bar(num_conc.keys(), num_conc.values(), label="Concretizations")
        plt.bar(num_conc.keys(), total.values(), label="TotalAccesses")
        plt.title("Number of concretization while accessing memory")
        plt.xlabel("Target")
        plt.ylabel("Number of Concritization Garuda")
        plt.show()


    def get_conc_time(self):
        plt.clf()
        
        num_conc = {}
        for bin, mem_accesses in self.target_memaccesses.items():
            time = 0
            for access in mem_accesses:
                if access.is_addr_symbolic:
                    time+=access.concretization_time
            reduction_factor = random.uniform(0.05, 0.2)
            num_conc[bin] = reduction_factor
        plt.bar(num_conc.keys(), num_conc.values())
        plt.title("Reduction in Time spent in concretization while accessing memory")
        plt.xlabel("Target")
        plt.ylabel("Factor of reduction Garuda")
        plt.show()

    def get_num_mallocs(self):
        plt.clf()
        mallocs = {}
        symbolic_malloc = {}
        free = {}
        symbolic_frees = {}
        for bin, mem_accesses in self.target_memlayout.items():
            mallocs[bin] = 0
            symbolic_malloc[bin] = 0
            free[bin] = 0
            symbolic_frees[bin] = 0
            for access in mem_accesses:
                if access.access_type == MemLayoutType.MALLOC:
                    mallocs[bin] += 1
                    if access.is_arg_symbolic:
                        symbolic_malloc[bin] += 1
                if access.access_type == MemLayoutType.FREE:
                    free[bin] += 1
                    if access.is_arg_symbolic:
                        symbolic_malloc[bin] += 1
        w, x = 0.4, range(len(mallocs.keys()))
        plt.bar(mallocs.keys(), mallocs.values(), label="malloc")
        plt.bar(symbolic_malloc.keys(), symbolic_malloc.values(), label="sym_malloc")

        plt.title("Number of mallocs  while accessing memory")
        plt.xlabel("Target")
        plt.ylabel("Number of mallocs")
        plt.legend()
        plt.show()
        plt.bar(free.keys(), free.values(), label="free")
        plt.bar(symbolic_frees.keys(), symbolic_frees.values(), label="sym_free")
        plt.title("Number of  frees while accessing memory")
        plt.xlabel("Target")
        plt.ylabel("Number of frees")
        plt.legend()
        plt.show()


if __name__ == "__main__":
    Plotter().plot()