#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import os
import argparse
from pwn import p16
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def protect_firmware(infile, outfile, version, message):
    # Load secrets to import passwords, key, and nonce
    build_output = open('secret_build_output.txt', 'r')
    pwd = bytes.fromhex(build_output.readline())[:16]
    key = bytes.fromhex(build_output.readline())[:16]
    nonce = bytes.fromhex(build_output.readline())[:12]
    build_output.close()

    # Load private key
    with open("privatekey.pem", "rb") as f:
        data = f.read()
        priv_key = RSA.import_key(data, pwd)

    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')

    # Initialize the firmware blob
    firmware_blob = metadata

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b"\00"

    # Pad firmware and message
    if len(firmware_and_message) % 1024 > 0:
        firmware_and_message += b"\00" * (1024 - (len(firmware_and_message) % 1024))

    h = SHA256.new()
    h.update(firmware_and_message)
    signer = pss.new(priv_key)
    signature = signer.sign(h)
    firmware_and_message = signature + firmware_and_message

    # Encrypt firmware and message
    i = 0
    while i < len(firmware_and_message):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(metadata)
        ciphertext, tag = cipher.encrypt_and_digest(firmware_and_message[i:i + 256])
        nonce = int.to_bytes(int.from_bytes(nonce, byteorder="little") + 1, byteorder="little", length=12)
        firmware_blob += tag + ciphertext
        i += 256

    # Delete privatekey.pem
    os.remove("privatekey.pem")

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
