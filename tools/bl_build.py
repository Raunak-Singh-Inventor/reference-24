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
    if variable_name!="AES_KEY" and variable_name!="AES_NONCE":
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
    key = get_random_bytes(16) # generate 16-byte long key
    nonce = b'\x00'*12

    build_output = open("secret_build_output.txt", "w")
    write_bytes_to_build_output(key, build_output=build_output)
    write_bytes_to_build_output(nonce, build_output=build_output)
    build_output.close()

    # Build the bootloader from source.
    os.chdir(BOOTLOADER_DIR)

    # write secrets (Key and Nonce have to be secret, but Tag and AAD can be sent with firmware in plaintext)
    secrets = open("inc/secrets.h", "w") 
    secrets.write("#ifndef SECRETS_H\n");
    secrets.write("#define SECRETS_H\n");
    write_bytearr_to_secrets("AES_KEY", key, secrets=secrets, isConst=False)
    write_bytearr_to_secrets("AES_NONCE", nonce, secrets=secrets, isConst=False)
    secrets.write("#endif")
    secrets.close()

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    os.remove("inc/secrets.h")

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    make_bootloader()
