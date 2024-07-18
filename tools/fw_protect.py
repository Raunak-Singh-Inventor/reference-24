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

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b"\00"

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM)
    secrets = open("secret_build_output.txt", "wb")
    secrets.write(key)
    secrets.write(b"\n")
    secrets.write(cipher.nonce)
    secrets.write(b"\n")
    ciphertext, tag = cipher.encrypt_and_digest(firmware_and_message)
    secrets.write(tag)
    secrets.write(b"\n")
    secrets.close()

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')  

    # Append firmware and message to metadata
    firmware_blob = metadata + ciphertext

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
