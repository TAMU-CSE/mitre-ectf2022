#!/bin/bash -x

sysname="riir"
socket="51337"

raw_cfg="example_cfg.bin"
protected_cfg="protected_cfg.bin"

python3 tools/run_saffire.py cfg-protect \
    --sysname $sysname \
    --cfg-root configuration \
    --raw-cfg-file $raw_cfg \
    --protected-cfg-file $protected_cfg

python3 tools/run_saffire.py cfg-load \
    --sysname $sysname \
    --cfg-root configuration \
    --protected-cfg-file $protected_cfg \
    --uart-sock $socket
