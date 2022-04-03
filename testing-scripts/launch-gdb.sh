#!/bin/bash -x

sysname=$1
socket=$2

python3 tools/run_saffire.py launch-bootloader-gdb \
    --emulated \
    --sysname $sysname \
    --sock-root socks \
    --uart-sock $socket
