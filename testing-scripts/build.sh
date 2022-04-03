#!/bin/bash -x

workdir="$(pwd)/testing-scripts"
sysname=$1
min_version=$2

"${workdir}/precision-airstrike.sh" $sysname
python3 tools/run_saffire.py build-system \
    --physical \
    --sysname $sysname \
    --oldest-allowed-version $min_version

python3 tools/run_saffire.py load-device \
    --physical \
    --sysname $sysname
