#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import os
import argparse
from pwn import *
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def protect_firmware(infile, outfile, version, message):

    # Load secrets
    with open('../bootloader/secret_build_output.txt', 'rb') as secrets_file:
        pwd = secrets_file.readline().strip(b'\n')

    # Load private key
    with open("../bootloader/privatekey.pem", "rb") as f:
        data = f.read()
        priv_key = RSA.import_key(data, pwd)
    
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b"\00"

    # Create RSA signature
    h = SHA256.new()
    h.update(firmware_and_message)
    # signer = pkcs1_15.new(priv_key)
    # signature = signer.sign(h)
    signature = pss.new(priv_key).sign(h)

    # Delete privatekey.pem
    os.remove("../bootloader/privatekey.pem")
    
    # Add together firmware and message along with signature to make the firmware blob
    firmware_blob = metadata + signature + firmware_and_message

    # Write firmware blob along with signature to outfile
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
