#!/bin/bash -x

sysname="riir"
socket="51337"

fw_version=3
raw_fw="example_fw.bin"
protected_fw="protected_fw.bin"
release_msg="noice"

python3 tools/run_saffire.py fw-protect \
    --sysname $sysname \
    --fw-root firmware \
    --raw-fw-file $raw_fw \
    --protected-fw-file $protected_fw \
    --fw-version $fw_version \
    --fw-message $release_msg

python3 tools/run_saffire.py fw-update \
    --sysname $sysname \
    --fw-root firmware \
    --protected-fw-file $protected_fw \
    --uart-sock $socket
