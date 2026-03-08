import angr
import pickle
from pathlib import Path
import os
import hashlib

def get_cfg(project: angr.Project, cache_dir="cached-cfg", force_rebuild=False):
    """
    Returns a CFG for the given project. If a cached version exists, it loads it.
    Otherwise, it generates a new CFG and caches it.
    
    The cache filename is derived from the SHA-256 hash of the binary contents.
    """
    binary_path = project.filename
    if not binary_path or not os.path.exists(binary_path):
        # Fallback if filename isn't easily accessible or is a stream
        print("[-] Could not determine binary path from project. Using 'unknown' for naming.")
        binary_hash = "unknown"
        display_name = "unknown"
    else:
        with open(binary_path, "rb") as f:
            binary_content = f.read()
            binary_hash = hashlib.sha256(binary_content).hexdigest()[:8]
        display_name = Path(binary_path).name

    cfg_cache_dir = Path(cache_dir)
    if not cfg_cache_dir.exists():
        cfg_cache_dir.mkdir(parents=True)
    
    # Use the hash as the unique identifier for the cache
    cfg_path = (cfg_cache_dir / binary_hash).with_suffix(".pkl")
    
    if not force_rebuild and cfg_path.exists():
        print(f"[+] Found cached CFG for {display_name} ({binary_hash[:8]}...) at {cfg_path.as_posix()}")
        with open(cfg_path, "rb") as f:
            try:
                cfg = pickle.load(f)
                
                # Restore project reference if it was stripped or missing
                if hasattr(cfg, 'project') and cfg.project is None:
                    cfg.project = project
                
                return cfg
            except Exception as e:
                print(f"[-] Failed to load cached CFG: {e}. Rebuilding...")

    print(f"[+] Generating CFGFast for {display_name}...")
    cfg = project.analyses.CFGFast()
    print(f"[+] Dumping CFG to {cfg_path.as_posix()}")
    
    with open(cfg_path, "wb") as f:
        pickle.dump(cfg, f, -1)
        print(f"[+] CFG cached successfully.")
    return cfg
