#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from pwn import *
from Crypto.Cipher import AES

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b"\00"

    firmware_and_message += b"\00"*(1024-(len(firmware_and_message)%1024))

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')  

    firmware_blob = metadata

    build_output = open("secret_build_output.txt", "r")
    key = bytes.fromhex(build_output.readline())[:16]
    nonce = bytes.fromhex(build_output.readline())[:12]
    build_output.close()

    i = 0
    while(i<len(firmware_and_message)):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce) # initialize AES cipher object
        cipher.update(metadata) # add the additional associated data to the cipher
        ciphertext, tag = cipher.encrypt_and_digest(firmware_and_message[i:i+256]) # encrypt the plaintext firmware
        print(ciphertext, end="")
        nonce = int.to_bytes(int.from_bytes(nonce, byteorder="big")+1, byteorder="big")
        firmware_blob += tag + ciphertext
        i+=256

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
