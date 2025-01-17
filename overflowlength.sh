#!/bin/bash

# telling gdb to f off about debug info
export DEBUGINFOD_URLS=""

if [ "$#" -gt 3 ] || [ "$#" -lt 1 ]; then
    echo "Usage: <program to run in gdb> [python script to run alongside]"
    echo "       If no python script is provided, then \"detect_input_str_len.py\" will be used"
    exit 1
fi

if [ ! -f "detect_input_str_len.py" ]; then
    echo "detect_input_str_len.py does not exist! Make sure it is in the working directory where this bash script was ran"
    exit 1
fi

program=$1

if [ "$#" -eq 1 ]; then
    offset=$(gdb -q -ex "source detect_input_str_len.py" --args $program | tail -n 1)
    echo $offset
fi

if [ "$#" -eq 2 ]; then
    script=$2
    offset=$(gdb -q -ex "source $script" --args $program | tail -n 1)
    echo $offset
fi

objdump -h $program > objdump.txt
ROPgadget --binary $program > gadgets.txt