#!/bin/bash

if [ "$#" -gt 3 ] || [ "$#" -lt 1 ]; then
    echo "Usage: <program to run in gdb> [python script to run alongside]"
    echo "       If no python script is provided, then \"detect_input_str_len.py\" will be used"
    exit 1
fi

if [ "$#" -eq 1 ]; then
    program=$1
    gdb -ex "source detect_input_str_len.py" $program
fi

if [ "$#" -eq 2 ]; then
    program=$1
    script=$2
    gdb -ex "source $script" $program
fi