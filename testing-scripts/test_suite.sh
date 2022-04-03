#!/bin/bash -x

# attach to bootloader w gdb
# gdb-multiarch  -ex 'target remote socks/gdb.sock'

sysname="riir"
socket="51337"

min_version=2

fw_rb_len=100
cfg_rb_len=100

workdir="$(pwd)/testing-scripts"

"${workdir}/build.sh" $sysname $min_version

#"${workdir}/launch-gdb.sh" $sysname $socket
"${workdir}/launch.sh" $sysname $socket

sleep 10 # because we're fast af

"${workdir}/firmware-test.sh"
"${workdir}/config-test.sh"

#python3 tools/run_saffire.py fw-readback \
#    --sysname $sysname \
#    --uart-sock $socket \
#    --rb-region fw \
#    --rb-len $fw_rb_len
#
#python3 tools/run_saffire.py cfg-readback \
#    --sysname $sysname \
#    --uart-sock $socket \
#    --rb-region cfg \
#    --rb-len $cfg_rb_len

python3 tools/run_saffire.py boot \
    --sysname $sysname \
    --msg-root messages \
    --boot-msg-file release_msg.txt \
    --uart-sock $socket \
