#!/bin/sh
rm -rf workspace
mkdir workspace
cp -r gen_eeprom workspace
cp -r riir_bootloader workspace
cp -r riir_host_tools workspace
cat <<EOF >> workspace/Cargo.toml
[workspace]
members = [
    "gen_eeprom",
    "riir_bootloader",
    "riir_host_tools",
]
EOF
cd workspace
cargo doc
cat <<EOF >> target/doc/index.html
<head>
    <meta http-equiv="Refresh" content="0; URL=riir_bootloader/index.html">
</head>
EOF
cp -r target/doc ../docs
rm -rf workspace
