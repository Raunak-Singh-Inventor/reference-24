# Cryptographic Automotive Software Handler and Bootloader (CrASHBoot)

![cover image](https://github.com/user-attachments/assets/dc3bc142-c873-420e-a984-2090c8761457)

Welcome to the future of bootloaders and software that will transform the automotive industry for years. Equipped with features and security, it is set to go to market... as long as some testing is conducted.

# Project Structure
```
├── bootloader *
│   ├── bin
│   │   ├── bootloader.bin
│   ├── src
│   │   ├── bootloader.c
│   │   ├── startup_gcc.c
│   ├── bootloader.ld
│   ├── Makefile
├── firmware
│   ├── bin
│   │   ├── firmware.bin
│   ├── lib
│   ├── src
├── lib
│   ├── driverlib
│   ├── inc
│   ├── uart
├── tools *
│   ├── bl_build.py
│   ├── fw_protect.py
│   ├── fw_update.py
│   ├── util.py
├── README.md

Directories marked with * are part of the CrASHBoot system
```

# Overall Design Flow Chart:
<img width="1251" alt="image" src="https://github.com/user-attachments/assets/216a9b60-069e-4d97-9889-0078fdb4a8c3">
Credits: Shubh, Stephanie, & Lin

# AES-GCM
AES-GCM encrypts firmware frames in (`tools/fw_protect.py`) using a private key and counter nonce under pycryptodome's implementation, with the version number and firmware size used as Additional Authenticated Data (AAD). (`tools/fw_update.py`) sends these encrypted frames to the bootloader over a serial connection. See below for our frame format.

<img width="762" alt="frames" src="https://github.com/user-attachments/assets/0d35d2ca-5981-4920-b7c0-3336816b1b57">

In (`bootloader/src/bootloader.c`), the received private key and nonce are placed in EEPROM. Metadata (version number and size) are received, and frames are decrypted using the wolfSSL library's implementation of AES_GCM. The decrypted firmware is loaded and booted.

# RSA
RSA PSS (Probabilistic Signature Scheme) encrypts (signs) the SHA-256 hash of the firmware with a private key.  Thus, if someone decrypts the ciphertext with the public key and receives a matching text to the hashed firmware, they know the firmware is authentic. The signature is sent in a frame before the ciphertext frames. Firmware is signed in (`tools/fw_protect.py`) using pycryptodome's pss module, and decrypted/verified in (`bootloader/src/bootloader.c`) using wolfSSL.

## Bootloader

The `bootloader` directory contains source code compiled and loaded onto the TM4C microcontroller. The bootloader manages which firmware can be updated to the TM4C by implementing decryption, hash checking, and authentication before updating the firmware. In addition, when connected to the fw_update tool, the bootloader checks the version of the new firmware against the internal firmware version before accepting the new firmware.

The bootloader will also start the execution of the loaded vehicle firmware when prompted to boot.

### bootloader.c
The bootloader.c file contains the bulk of the code used for the bootloader. The
main job of the bootloader is to receive the keys required to decrypt and verify
the firmware in a secure fashion, then to receive the firmware, decrypt it, and then
verify its integrity and authenticity before allowing it to be booted.

Two main algorithms are used during this process, these being AES-GCM and RSA PSS(with
a SHA-256 hash). All secrets are securely read in through a header file, `secrets.h`.
The key and nonce for the AES procedure are then securely stored in EEPROM, while the
RSA public key will be subsequently used for verification procedures.

The metadata is read and stored in a 4 byte array, `aad`. The metadata consists
of a version short and a size short, which encodes the version number and size of 
the firmware respectively. The version number is compared with the current loaded
firmware to prevent rollback to earlier versions. The metadata is used as 
additional authenticated data in the AES process in order to ensure authenticity.

The signature is then read in and split into the signature ciphertext encrypted with
AES, `signature_ct`, and the authentication tag, `signature_tag`. The key and nonce
for AES, `EEPROM_AES_KEY` and `EEPROM_AES_NONCE` are read in and used to decrypt 
`signature_ct` and store it in `signature`. Then, nonce is incremented to ensure
security.

After a Sha256 object is initialized to compare the hashes to, we begin reading in
the firmware in frames. Each frame begins with a size and is followed by data. 
Once we fill our page buffer, we decrypt it using the AES key and nonce, and then 
it is programmed to a temporary location in flash, encoded in `FW_BASE` to ensure 
that we are not replacing our working firmware if the current firmware to be updated
is invalid or malicious. The flash is programmed to be readonly and the nonce is 
incremented each time to ensure security. Each time, the Sha256 object is also 
updated to calculate the hash.

After all the firmware is read in and decrypted successfully, the Sha256 hash is
calculated. Then, using RSA we verify the signature by hashing the new hash that
was directly calculated from the firmware we read in. If it matches the sent hash,
the firmware is accepted and we rewrite the firmware to the permanent location 
in flash, encoded in `FW_BASE`.

## Tools

There are three python scripts in the `tools` directory which are used to:

1. Provision the bootloader (`bl_build.py`)
2. Package the firmware (`fw_protect.py`)
3. Update the firmware to a TM4C with a provisioned bootloader (`fw_update.py`)

### bl_build.py

This script:

calls `make` in the `bootloader` directory.
generates and exports secrets to secrets.h, privatekey.pem, and secret_build_output.txt

### fw_protect.py

This script bundles the version and release message with the firmware binary and the RSA
PSS signature. It then encrypts the binary, message, and signature in blocks of 256 bytes,
generating a protected firmware binary to be exported for update.

### fw_update.py

This script opens a serial channel with the bootloader, then writes the firmware metadata
and protected binary broken into data frames to the bootloader.

# Building and Flashing the Bootloader

1. Enter the `tools` directory and run `bl_build.py`

```
cd ./tools
python bl_build.py
```

2. Flash the bootloader using `lm4flash` tool
   
```
sudo lm4flash ../bootloader/bin/bootloader.bin
```

Note: if flashing to the bootloader does not work, you may have triggered our anti-debug feature. In order to fix this, please
download the official TI [LMFLASHPROGRAMMER](https://www.ti.com/tool/LMFLASHPROGRAMMER) and follow the detailed steps to 
reset/unlock your board.

# Bundling and Updating Firmware

1. Enter the firmware directory and `make` the example firmware.

```
cd ./firmware
make
```

2. Enter the tools directory and run `fw_protect.py`

```
cd ../tools
python fw_protect.py --infile ../firmware/bin/firmware.bin --outfile firmware_protected.bin --version 2 --message "Firmware V2"
```

This creates a firmware bundle called `firmware_protected.bin` in the tools directory.

3. Reset the TM4C by pressing the RESET button

4. Run `fw_update.py`

```
python fw_update.py --firmware ./firmware_protected.bin
```

If the firmware bundle is decrypted successfully by the bootloader, the `fw_update.py` tool will report it wrote all frames successfully. However, the tool will not
show whether the RSA signature and hash were verified successfully or not. This can be checked by seeing whether the new firmware was booted or not in the serial itself.

Additional firmwares can be updated by repeating steps 3 and 4, but only firmware versions higher than the one flashed to the board (or version 0) will be accepted.

# Interacting with the Bootloader
(ONLY FOR OFFICIAL DEVELOPERS)
For convenience, use the `debug.sh` shell script in the `tools` directory
for debugging purposes, which will launch either `picocom` or `gdb-multiarch`.

©2024 TEAM SUPER AUTO PETS. ALL RIGHTS RESERVED. <br> 
APPROVED FOR PUBLIC RELEASE. DISTRIBUTION UNLIMITED 24-01337-1
