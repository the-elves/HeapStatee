#!/bin/bash
gdb ./driver.out -batch -x heap-output.g | tee output.txt

