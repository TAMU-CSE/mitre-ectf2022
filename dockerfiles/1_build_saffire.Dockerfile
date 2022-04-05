# 2022 eCTF
# Host-Tools and Bootloader Creation Dockerfile
# Andrew Mirghassemi
#
# (c) 2022 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2022 Embedded System
# CTF (eCTF). This code is being provided only for educational purposes for the
# 2022 MITRE eCTF competition, and may not meet MITRE standards for quality.
# Use this code at your own risk!

FROM rustlang/rust:nightly-buster-slim as base
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y gcc-aarch64-linux-gnu
RUN rustup target add thumbv7em-none-eabihf
RUN rustup component add llvm-tools-preview
RUN rustup component add rust-src
RUN cargo install cargo-binutils

# Build host tools
FROM base as build-host-tools
COPY host_tools /host_tools
WORKDIR /host_tools
RUN cargo clean && rm -f Cargo.lock
RUN cargo build --features production,emulator --release

# Build bootloader
FROM base as build-bootloader
COPY --from=build-host-tools /secrets /secrets
COPY bootloader /bootloader
WORKDIR /bootloader
RUN cargo clean && rm -f Cargo.lock

ARG BOOT_PATH="/bootloader/target/thumbv7em-none-eabi/release"
ARG OLDEST_VERSION="1"

RUN cargo objcopy --bin bootloader --release --features production -- -O binary unencrypted_bootloader.bin
RUN mv $BOOT_PATH/bootloader /bootloader/bootloader.elf

# Encrypt bootloader
COPY gen_eeprom /gen_eeprom
WORKDIR /gen_eeprom
RUN cargo clean && rm -f Cargo.lock
RUN OLDEST_VERSION=$OLDEST_VERSION cargo run --release
RUN dd if=/bootloader/encrypted_bootloader.bin of=/bootloader/bootloader.bin ibs=22528 skip=1

# Final image
FROM ubuntu:focal
RUN apt-get update && apt-get upgrade -y && apt-get install -y python3

# Create system folders
RUN mkdir /bootloader
RUN mkdir /host_tools
COPY --from=build-host-tools /secrets /secrets

ARG HOST_PATH="/host_tools/target/release"

# Add binaries
COPY --from=build-host-tools $HOST_PATH/boot $HOST_PATH/cfg_load $HOST_PATH/cfg_protect $HOST_PATH/fw_protect $HOST_PATH/fw_update $HOST_PATH/readback /host_tools/
COPY host_tools/monitor host_tools/__init__.py host_tools/util.py /host_tools/
COPY --from=build-bootloader /bootloader/bootloader.elf /bootloader/bootloader.bin /bootloader/eeprom.bin /bootloader/
