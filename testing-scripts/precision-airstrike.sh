#!/bin/bash -x

python3 tools/run_saffire.py kill-system \
    --sysname $1

rm -f socks/*
