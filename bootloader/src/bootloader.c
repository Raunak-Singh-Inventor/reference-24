// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"
#include "secrets.h" // Secrets file

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/interrupt.h" // Interrupt API
#include "driverlib/sysctl.h"    // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"

// Forward Declarations
int load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash
#define FW_TMP 0x20000 // temporary address of firmware in Flash without checking
#define MAX_ENC_ALG_SZ 32   // maximum bound on digest algorithm encoding around digest

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Device Metadata
uint16_t * fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

//RSA Constant
#define RSA_SIZE 2048

// Sha-256 Object and Buffer
unsigned char hash[WC_SHA256_DIGEST_SIZE];
Sha256 sha;

// Delay to allow time to connect GDB
// green LED as visual indicator of when this function is running
void debug_delay_led() {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // Turn on the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);

    // Wait
    SysCtlDelay(SysCtlClockGet() * 2);

    // Turn off the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0x0);
}


int main(void) {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // debug_delay_led();

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write_str(UART0, "U");
            if (load_firmware() == 1) {
                uart_write_str(UART0, "Failed to load firmware.\n");
                SysCtlReset();
            } else {
                uart_write_str(UART0, "Loaded new firmware.\n");
                nl(UART0);
            }
        } else if (instruction == BOOT) {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
    }
}


 /*
 * Load the firmware into flash.
 */
int load_firmware(void) {
    int frame_length = 0;
    int read = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_TMP;
    uint32_t page_addr2 = FW_BASE;
    uint32_t version = 0;
    uint32_t size = 0;

    

    // Get version.
    rcv = uart_read(UART0, BLOCKING, &read);
    version = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    version |= (uint32_t)rcv << 8;

    // Get size.
    rcv = uart_read(UART0, BLOCKING, &read);
    size = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    size |= (uint32_t)rcv << 8;

    // Compare to old version and abort if older (note special case for version 0).
    // If no metadata available (0xFFFF), accept version 1
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 1;
    }

    if (version != 0 && version < old_version) {
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return 1;
    } else if (version == 0) {
        // If debug firmware, don't change version
        version = old_version;
    }

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata), 4);

    uart_write(UART0, OK); // Acknowledge the metadata.

    // Get signature
    int signature_size;
    rcv = uart_read(UART0, BLOCKING, &read);
    signature_size = (int)rcv << 8;
    rcv = uart_read(UART0, BLOCKING, &read);
    signature_size += (int)rcv;
    unsigned char signature[signature_size * 2];
    for (int i = 0; i < signature_size; ++i) {
            signature[i] = uart_read(UART0, BLOCKING, &read);
    } // for
    uart_write(UART0, OK); // Acknowledge the signature.
    
    // Initialize Sha256 object
    if (wc_InitSha256(&sha) != 0) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return 1;
    }

    int total_frame_amt = 0;
    int frame_ctr = 0;

    /* Loop here until you can get all your characters and stuff */
    while (1) {

        // Get two bytes for the length.
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length = (int)rcv << 8;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length += (int)rcv;

        total_frame_amt +=frame_length;
        frame_ctr++;

        if(total_frame_amt > 31744){
            break;
        }

        // Get the number of bytes specified
        for (int i = 0; i < frame_length; ++i) {
            data[data_index] = uart_read(UART0, BLOCKING, &read);
            data_index += 1;
        } // for

        // If we filed our page buffer, program it
        if (data_index == FLASH_PAGESIZE || frame_length == 0) {
            
            // Try to write flash and check for error
            if (program_flash((uint8_t *) page_addr, data, data_index)) {
                uart_write(UART0, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return 0;
            }

            if (wc_Sha256Update(&sha, data, data_index) != 0) {
                uart_write(UART0, ERROR);
                SysCtlReset();
                return 1;
            }

            // Update to next page
            page_addr += FLASH_PAGESIZE;
            data_index = 0;

            // If at end of firmware, go to main
            if (frame_length == 0) {
                uart_write(UART0, OK);
                break;
            }
        } // if

        uart_write(UART0, OK); // Acknowledge the frame.
    } // while(1)

            
    if (wc_Sha256Final(&sha, hash) != 0) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return 1;
    }

    /*
    // Encode hash with algorithm information as per PKCS#1.5
    unsigned char enc_hash[WC_SHA256_DIGEST_SIZE + MAX_ENC_ALG_SZ];
    word32 enc_len = wc_EncodeSignature(enc_hash, hash, sizeof(hash), SHA256h);
    if ((int) enc_len < 0) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return 1;
    }
    */

    // Initialize RSA key and decode public key
    RsaKey rsa;
    word32 idx = 0;
    if (wc_InitRsaKey(&rsa, NULL) != 0) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return 1;
    }
            
    if (wc_RsaPublicKeyDecode(publicKey, &idx, &rsa, sizeof(publicKey)) != 0) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return 1;
    }

    // Verify the signature
    
    size_t SIGN_SIZE = 256;
    unsigned char *signed_hash = signature + SIGN_SIZE;
    word32 dec_len = wc_RsaSSL_VerifyInline(signature, SIGN_SIZE, &signed_hash, &rsa); //fix addressing here
    if ((int) dec_len < 0) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return 1;
    } else {
        uart_write(UART0, OK);
    }

    /*
    // Compare the two hashes
    if (enc_len != dec_len) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return 1;
    } else {
        uart_write(UART0, OK);
    }
    */

    if (memcmp(hash, signed_hash, dec_len) != 0) {
        uart_write(UART0, ERROR); // Reject the firmware
        SysCtlReset();            // Reset device
        return 1;
    } else {
        uart_write(UART0, OK);
    }
    
    page_addr = FW_TMP;

    for(int i = 0; i < frame_ctr; i++) {
        // Try to write flash and check for error
        if (program_flash((uint8_t *) page_addr2, (uint8_t *) page_addr, FLASH_PAGESIZE)) {
            SysCtlReset();            // Reset device
            return 1;
        }

        // Update to next page
        page_addr += FLASH_PAGESIZE;
        page_addr2 += FLASH_PAGESIZE;
    }

    return 0;
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of bytes to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void* page_addr, unsigned char * data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase((uint32_t) page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE) {
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, (uint32_t) page_addr, num_full_bytes);
        if (ret != 0) {
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++) {
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, (uint32_t) page_addr + num_full_bytes, 4);
    } else {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, (uint32_t) page_addr, data_len);
    }
}

void boot_firmware(void) {
    // Check if firmware loaded
    int fw_present = 0;
    for (uint8_t* i = (uint8_t*) FW_BASE; i < (uint8_t*) FW_BASE + 20; i++) {
        if (*i != 0xFF) {
            fw_present = 1;
        }
    }

    if (!fw_present) {
        uart_write_str(UART0, "No firmware loaded.\n");
        SysCtlReset();            // Reset device
        return;
    }

    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
    uart_write_str(UART0, (char *)fw_release_message_address);

    // Boot the firmware
    __asm("LDR R0,=0x10001\n\t"
          "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';

        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}
