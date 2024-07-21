#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def write_bytearr_to_secrets(variable_name, variable, ln, secrets):
    vals = [f'{k:02X}' for k in variable]
    secrets.write("const byte " + variable_name + "[" + str(ln) + "] = {")
    secrets.write("0x" + vals[0])
    for i in range(1, ln):
        secrets.write(", ")
        secrets.write("0x" + vals[i])
    secrets.write("};\n")

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b"\00"

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')  

    key = get_random_bytes(16) # generate 16-byte long key
    nonce = get_random_bytes(16) # generate 16-byte nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce) # initialize AES cipher object
    cipher.update(metadata) # add the additional associated data to the cipher
    ciphertext, tag = cipher.encrypt_and_digest(firmware_and_message) # encrypt the plaintext firmware

    # write secrets (Key and Nonce have to be secret, but Tag and AAD can be sent with firmware in plaintext)
    secrets = open("../bootloader/inc/secrets.h", "w") 
    secrets.write("#ifndef SECRETS_H\n");
    secrets.write("#define SECRETS_H\n");
    write_bytearr_to_secrets("AES_KEY", key, len(key), secrets)
    write_bytearr_to_secrets("AES_NONCE", cipher.nonce, len(cipher.nonce), secrets)
    write_bytearr_to_secrets("AES_TAG", tag, len(tag), secrets)
    write_bytearr_to_secrets("AES_AAD", metadata, len(metadata), secrets)
    secrets.write("const uint32_t FW_LEN = " + str(len(ciphertext)) + ";\n")
    secrets.write("#endif")
    secrets.close()

    # Append firmware and message to metadata
    firmware_blob = metadata + ciphertext
    # print(firmware_blob)
    # Write firmware blob to outfile
    with open(outfile, "wb+") as outfile:
        outfile.write(firmware_blob)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
