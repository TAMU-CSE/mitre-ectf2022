#!/bin/bash -x

python3 tools/run_saffire.py kill-system \
    --sysname $1

python3 tools/run_saffire.py cleanup \
    --sysname $1

docker system prune -a

rm -f socks/*
