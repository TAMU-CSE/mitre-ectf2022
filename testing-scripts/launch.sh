#!/bin/bash -x

sysname=$1
socket=$2

python3 tools/run_saffire.py launch-bootloader \
    --physical \
    --serial-port /dev/ttyACM0 \
    --sysname $sysname \
    --sock-root socks \
    --uart-sock $socket
