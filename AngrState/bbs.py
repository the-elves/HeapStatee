#!/usr/bin/env python3
# A script to dump function and basic block locations, size, etc.
# Install angr (https://docs.angr.io/introductory-errata/install) before use it.
# @author: xiaogw (https://stackoverflow.com/users/1267984/xiaogw)
import angr
import sys

def dump_functions_bbs(p, cfg):
  lines = []
  for key in cfg.kb.functions:
    for bb in cfg.kb.functions[key].blocks:
      print("%s: %s" % (hex(bb.addr), hex(bb.size)))
      lines.append("%s: %s".format(hex(bb.addr), hex(bb.size)))
  return lines
      
def main(argv):
  if (len(argv) < 2):
    print("Usage %s <BIN>" % argv[0])
    return 1
  path_to_binary = argv[1]
  p = angr.Project(path_to_binary, load_options={'auto_load_libs': False})
  cfg = p.analyses.CFGFast()
  lines = dump_functions_bbs(p, cfg)
  filename = argv[1].split('/')[-1]
  with open('outputs/'+filename+'-bbs', 'w') as f:
      f.writelines(lines)
  return 0

if __name__ == '__main__':
  main(sys.argv)
