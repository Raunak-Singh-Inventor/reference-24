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
from Crypto.PublicKey import RSA


REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")
RSA_LENGTH = 2048

def arrayize(binary_string):
    return '{' + ','.join([hex(char) for char in binary_string]) + '}'

def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    # Create RSA keys
    rsaKey = RSA.generate(RSA_LENGTH)
    privKey = rsaKey.exportKey(format = 'PEM')
    pubKey = rsaKey.publickey().exportKey(format = 'DER')

    # Write private key to secret_build_output.txt
    with open('secret_build_output.txt', 'wb+') as f:
        f.write(privKey + b'\n')

    # Write public key to secrets.h
    with open('./src/secrets.h', 'w') as f:
        f.write("#ifndef SECRETS_H\n")
        f.write("#define SECRETS_H\n")
        f.write("const uint8_t publicKey[" + str(RSA_LENGTH) + "] = " + arrayize(pubKey) + ";\n")
        f.write("#endif")

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")


    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    make_bootloader()
