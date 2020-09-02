#!/bin/fish
pwd
for f in (ls ../../tools/coreutils-8.32/bin)
     echo $f
     python angr-playground.py '../../tools/coreutils-8.32/bin/'$f
end