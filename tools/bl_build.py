#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import os
import pathlib
import subprocess
from Crypto.Random import get_random_bytes

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")


def write_bytearr_to_secrets(variable_name, variable, secrets, isConst):
    if variable_name != "AES_KEY" and variable_name != "AES_NONCE":
        return

    vals = [f'{k:02X}' for k in variable]
    if isConst:
        secrets.write("const ")
    secrets.write("byte " + variable_name + "[" + str(len(variable)) + "] = {")
    secrets.write("0x" + vals[0])
    for i in range(1, len(variable)):
        secrets.write(", ")
        secrets.write("0x" + vals[i])
    secrets.write("};\n")


def write_bytes_to_build_output(variable, build_output):
    vals = [f'{k:02X}' for k in variable]
    for i in range(0, len(variable)):
        build_output.write(vals[i])
        build_output.write(" ")
    build_output.write("\n")


def make_bootloader() -> bool:
    key = get_random_bytes(16)  # generate 16-byte long key
    nonce = b'\x00' * 8 + get_random_bytes(4)

    # write keys & nonce to secret_build_output.txt
    build_output = open("secret_build_output.txt", "w")
    write_bytes_to_build_output(key, build_output=build_output)
    write_bytes_to_build_output(nonce, build_output=build_output)
    build_output.close()

    os.chdir(BOOTLOADER_DIR)  # change to bootloader directory

    # write keys & nonce to inc/secrets.h
    secrets = open("inc/secrets.h", "w")
    secrets.write("#ifndef SECRETS_H\n")
    secrets.write("#define SECRETS_H\n")
    write_bytearr_to_secrets("AES_KEY", key, secrets=secrets, isConst=False)
    write_bytearr_to_secrets("AES_NONCE", nonce, secrets=secrets, isConst=False)
    secrets.write("#endif")
    secrets.close()

    # build the bootloader
    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # remove secrets.h after build
    os.remove("inc/secrets.h")
    if os.path.exists("bin/bootloader.axf"):
        os.remove("bin/bootloader.axf")

    # return the status of whether make worked
    return status == 0


if __name__ == "__main__":
    make_bootloader()
