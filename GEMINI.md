# Garuda (HeapStatee) Project Overview

Garuda (also referred to as HeapStatee) is a specialized symbolic execution-based tool for analyzing heap vulnerabilities in binaries. It is built on top of the **angr** framework and utilizes a custom, high-fidelity Python implementation of the **glibc heap allocator** to detect common memory safety issues with higher accuracy than standard symbolic execution engines.

## Key Technologies
- **angr:** The core symbolic execution engine.
- **claripy:** The solver backend for symbolic expressions.
- **Python:** Used for the heap model implementation, state plugins, and analysis scripts.
- **glibc Heap Allocator:** The model re-implements glibc's malloc/free/realloc logic (bins, chunks, consolidation, etc.).

## Core Architecture
- **`HeapModel/`**: Contains the core logic for the heap simulation.
  - `mstate.py`: Implements `Chunk` and `HeapState` classes, simulating glibc's internal heap management (fastbins, smallbins, largebins, unsorted bins, top chunk).
  - `Vulns.py`: Defines vulnerability classes for various heap-based errors.
- **`HeapPlugin/`**: Bridges the custom heap model with the `angr` state.
  - `HeapPlugin.py`: An `angr` `SimStatePlugin` that manages the `HeapState` and provides `SimProcedure` replacements for standard heap functions (`malloc`, `free`, `realloc`, `calloc`, `posix_memalign`).
- **`AngrState/`**: The main execution and analysis logic.
  - `angr-playground.py`: The entry point script. It initializes the `angr` project, registers the `HeapPlugin`, hooks memory operations via `state.inspect`, and monitors for vulnerabilities.
- **`MemTraceGenerator/`**: Tools for generating and parsing memory traces (e.g., using GDB) to aid in analysis and validation.
- **`benchmarks/` & `AngrState/TestCases/`**: Collections of target binaries and test cases for vulnerability research.

## Usage and Execution

### Main Analysis
To run the analysis on a target binary, use the `angr-playground.py` script:
```bash
python AngrState/angr-playground.py <path_to_binary>
```

### Key Scripts
- `AngrState/runTool.fish`: A helper script to automate analysis over multiple binaries (e.g., coreutils).
- `experiments/`: Contains scripts for specific research experiments and plotting results.

### Configuration
- `AngrState/config.py`: Global configuration for the tool (e.g., recursion limits, debug flags, checkpoints).
- Logging: Vulnerability reports and logs are generated in `reports/vuln-reports/` and `reports/logs/`.

## Building and Running Targets
Target binaries are typically compiled using glibc-specific environments or custom toolchains.
- Use `MemTraceGenerator/UserAPI/Makefile` as a template for building custom test cases.
- Prefer `-g` (debug symbols) and `-no-pie` (disable Position Independent Executables) for more reliable analysis.

## Development Conventions
- **Heap Logic:** Any changes to the underlying heap allocation/deallocation behavior must be implemented in `HeapModel/mstate.py`.
- **Custom Procedures:** New `angr` procedures or hooks should be added to `HeapPlugin/HeapPlugin.py` or within `AngrState/angr-playground.py`.
- **Vulnerability Checks:** Memory read/write monitoring is handled in `AngrState/angr-playground.py` via `bp_action_read` and `bp_action_write`.
- **Nix Environment:** A `flake.nix` is provided for managing dependencies in a reproducible environment.
