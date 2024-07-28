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
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes


REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")
ECC_LENGTH = 32


def arrayize(binary_string):
    return '{' + ','.join([hex(char) for char in binary_string]) + '}'


def make_bootloader() -> bool:
    # Build the bootloader from source.
    os.chdir(BOOTLOADER_DIR)

    # Create ECC keys
    ecc_key = ECC.generate(curve='p256')
    pub_key = ecc_key.public_key().export_key(format='SEC1')

    # Create password for ECC key
    pwd = get_random_bytes(16)

    # Write private key password to secret_build_output.txt
    with open('secret_build_output.txt', 'wb+') as f:
        f.write(pwd + b'\n')

    # Export private key securely to privatekey.pem
    with open("privatekey.pem", "wt") as f:
        data = ecc_key.export_key(format='PEM',
                                  passphrase=pwd,
                                  protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                  prot_params={'iteration_count':131072})
        f.write(data)

    # Write public key to secrets.h
    with open('./inc/secrets.h', 'w') as f:
        f.write("#ifndef SECRETS_H\n")
        f.write("#define SECRETS_H\n")
        f.write("const uint8_t publicKey[" + str(ECC_LENGTH) + "] = " + arrayize(pub_key) + ";\n")
        f.write("#endif")

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    make_bootloader()
