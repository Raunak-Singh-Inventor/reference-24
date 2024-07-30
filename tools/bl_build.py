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
from Crypto.Random import get_random_bytes


REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")
RSA_LENGTH = 2048  # Define RSA key length


# Formats inputted byte array to be written to secrets.h
def write_bytearr_to_secrets(variable_name, variable, secrets, isConst):
    # Make sure that the variables inputted are only variables we are writing to secrets
    if variable_name != "AES_KEY" and variable_name != "AES_NONCE" and variable_name != "RSA_PBK":
        return

    # Arrayize the variable array
    vals = [f'{k:02X}' for k in variable]

    # Write to secrets with the correct format
    if isConst:
        secrets.write("const ")
    secrets.write("unsigned char " + variable_name + "[" + str(len(variable)) + "] = {")
    secrets.write("0x" + vals[0])
    for i in range(1, len(variable)):
        secrets.write(", ")
        secrets.write("0x" + vals[i])
    secrets.write("};\n")


# Formats inputted variable to be written to secret_build_output.txt
def write_bytes_to_build_output(variable, build_output):

    # Arrayize the variable array
    vals = [f'{k:02X}' for k in variable]

    # Write variable to secret_build_output.txt
    for i in range(0, len(variable)):
        build_output.write(vals[i])
        build_output.write(" ")
    build_output.write("\n")


def make_bootloader() -> bool:
    # Generate AES-GCM key and nonce
    key = get_random_bytes(16)
    nonce = b'\x00' * 8 + get_random_bytes(4)

    # Create password for RSA key
    pwd = get_random_bytes(16)

    # Write password, key, and nonce to secret_build_output.txt
    build_output = open("secret_build_output.txt", "w")
    write_bytes_to_build_output(pwd, build_output=build_output)
    write_bytes_to_build_output(key, build_output=build_output)
    write_bytes_to_build_output(nonce, build_output=build_output)
    build_output.close()

    os.chdir(BOOTLOADER_DIR)  # Change to bootloader directory

    # Create RSA keys
    rsa_key = RSA.generate(RSA_LENGTH)
    pub_key = rsa_key.publickey().exportKey(format="DER")

    # Export private key securely to privatekey.pem
    with open("../tools/privatekey.pem", "wb") as f:
        data = rsa_key.export_key(format="PEM", passphrase=pwd, pkcs=8, protection='PBKDF2WithHMAC-SHA512AndAES256-CBC', prot_params={'iteration_count':131072})
        f.write(data)

    # Write keys & nonce to inc/secrets.h with proper header information
    secrets = open("inc/secrets.h", "w")
    secrets.write("#ifndef SECRETS_H\n")
    secrets.write("#define SECRETS_H\n")
    write_bytearr_to_secrets("AES_KEY", key, secrets=secrets, isConst=False)
    write_bytearr_to_secrets("AES_NONCE", nonce, secrets=secrets, isConst=False)
    write_bytearr_to_secrets("RSA_PBK", pub_key, secrets=secrets, isConst=True)
    secrets.write("#endif")
    secrets.close()

    # Build the bootloader
    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Remove secrets.h after build
    os.remove("inc/secrets.h")

    #  Remove bin/bootloader.axf after build if not removed already
    if os.path.exists("bin/bootloader.axf"):
        os.remove("bin/bootloader.axf")

    # return the status of whether make worked
    return status == 0


if __name__ == "__main__":
    make_bootloader()
