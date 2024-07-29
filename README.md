# Cryptographic Automotive Software Handler and Bootloader (CrASHBoot)

![cover image](https://github.com/user-attachments/assets/dc3bc142-c873-420e-a984-2090c8761457)

Welcome to the Car Bootloader and Software that will transform the automotive industry to years to come. Equipped with features and security, it is set to go to market... as long as some testing is conducted.

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
AES-GCM encrypts firmware frames in (`tools/fw_protect.py`) using a private key and nonce under pycryptodome's implementation, with the version number and firmware size used as Additional Authenticated Data (AAD). (`tools/fw_update.py`) sends these encrypted frames to the bootloader over a serial connection. See below for our frame format.

<img width="762" alt="frames" src="https://github.com/user-attachments/assets/0d35d2ca-5981-4920-b7c0-3336816b1b57">

In (`bootloader/src/bootloader.c`), the received private key and nonce are placed in EEPROM. Metadata (version number and size) are received, and frames are decrypted using the wolfSSL library's implementation of AES_GCM. The decrypted firmware is loaded and booted.

# RSA
RSA encrypts (signs) the SHA-256 hash of the firmware with a private key.  Thus, if someone decrypts the ciphertext with the public key and receives a matching text to the hashed firmware, they know the firmware is authentic. The signature is sent in a frame before the ciphertext frames. Firmware is signed in (`tools/fw_protect.py`) using pycryptodome, and decrypted in (`tools/fw_update.py`) using wolfSSL.


## Bootloader

The `bootloader` directory contains source code that is compiled and loaded onto the TM4C microcontroller. The bootloader manages which firmware can be updated to the TM4C. When connected to the fw_update tool, the bootloader checks the version of the new firmware against the internal firmware version before accepting the new firmware.

The bootloader will also start the execution of the loaded vehicle firmware.

## Tools

There are three python scripts in the `tools` directory which are used to:

1. Provision the bootloader (`bl_build.py`)
2. Package the firmware (`fw_protect.py`)
3. Update the firmware to a TM4C with a provisioned bootloader (`fw_update.py`)

### bl_build.py

This script:
1.
calls `make` in the `bootloader` directory.

### fw_protect.py

This script bundles the version and release message with the firmware binary.

### fw_update.py

This script opens a serial channel with the bootloader, then writes the firmware metadata and binary broken into data frames to the bootloader.

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

3. Reset the TM4C by pressig the RESET button

4. Run `fw_update.py`

```
python fw_update.py --firmware ./firmware_protected.bin
```

If the firmware bundle is accepted by the bootloader, the `fw_update.py` tool will report it wrote all frames successfully.

Additional firmwares can be updated by repeating steps 3 and 4, but only firmware versions higher than the one flashed to the board (or version 0) will be accepted.

# Interacting with the Bootloader

Using the custom `car-serial` script:
```
car-serial
```

Using `pyserial` module:

```
python -m serial.tools.miniterm /dev/ttyACM0 115200
```

You can now interact with the bootloader and firmware! Type 'B' to boot.

Exit miniterm: `Ctrl-]`
Exit picocom: `Ctrl-A X`

# Launching the Debugger
Use OpenOCD with the configuration files for the board to get it into debug mode and open GDB server ports:
```bash
openocd -f /usr/share/openocd/scripts/interface/ti-icdi.cfg -f /usr/share/openocd/scripts/board/ti_ek-tm4c123gxl.cfg
```

Start GDB and connect to the main OpenOCD debug port:
```bash
gdb-multiarch -ex "target extended-remote localhost:3333" bootloader/bin/bootloader.axf
```

Go to `main` function and set a breakpoint
```
layout src
list main
break bootloader.c:50
```


©2024 TEAM SUPER AUTO PETS. ALL RIGHTS RESERVED. <br> 
APPROVED FOR PUBLIC RELEASE. DISTRIBUTION UNLIMITED 24-01337-1
