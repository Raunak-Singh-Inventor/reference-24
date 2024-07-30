// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"
#include "secrets.h" // Import secrets file

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers
#include "inc/hw_flash.h" // Flash Registers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/interrupt.h" // Interrupt API
#include "driverlib/sysctl.h"    // System control API (clock/reset)
#include "driverlib/eeprom.h"    // EEPROM API

// Application Imports
#include "driverlib/gpio.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include <stdint.h>

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x20000      // base address of firmware in Flash
#define FW_TMP 0x10000       // temporary address of firmware in Flash before it is completely verified
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
unsigned char tag_and_data[FLASH_PAGESIZE+4*16];

//RSA Constant
#define RSA_SIZE 2048

// Sha-256 Object and Buffer
unsigned char hash[WC_SHA256_DIGEST_SIZE];
Sha256 sha;

int main(void) {
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0); // enable EEPROM module

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_EEPROM0)) {
    }

    // Initialize EEPROM
    EEPROMInit();
    EEPROMMassErase();

    // Write AES Key and Nonce to EEPROM
    EEPROMProgram((uint32_t *) AES_KEY, 0x0, 16);
    EEPROMProgram((uint32_t *) AES_NONCE, 0x0 + 16, 12);

    // Erase data from AES_KEY
    for(int i = 0; i < 16; i++) {
        AES_KEY[i] = 0;
    }

    // Erase data from AES_NONCE
    for(int i = 0; i < 12; i++) {
        AES_NONCE[i] = 0;
    }

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write_str(UART0, "U");
            load_firmware();
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
        } else if (instruction == BOOT) {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
    }
}

/*
*   Credits for this function: Amit Rana 
*/

// Delays program flow by ui32Ms seconds
void delay_ms(uint32_t ui32Ms) {
    SysCtlDelay(ui32Ms * (SysCtlClockGet() / 3 / 1000));
}

// Load the firmware into flash.
void load_firmware(void) {

    // Initialize variables for serial reading
    int frame_length = 0;
    int read = 0;
    uint32_t rcv = 0;

    // Initialize variables for flash programming
    uint32_t data_index = 0;
    uint32_t page_addr = FW_TMP;
    uint32_t real_page_addr = FW_BASE;

    // Initialize variables for metadata
    uint32_t version = 0;
    uint32_t size = 0;
    byte aad[4];

    // Get version.
    rcv = uart_read(UART0, BLOCKING, &read);
    version = (uint32_t)rcv;
    aad[0] = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    version |= (uint32_t)rcv << 8;
    aad[1] = (uint32_t)rcv;

    // Get size.
    rcv = uart_read(UART0, BLOCKING, &read);
    size = (uint32_t)rcv;
    aad[2] = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    size |= (uint32_t)rcv << 8;
    aad[3] = (uint32_t)rcv;

    // Compare to old version and abort if older (note special case for version 0).
    // If no metadata available (0xFFFF), accept version 1
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 1;
    }

    if (version != 0 && version < old_version) {
        delay_ms(4900);
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
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
    signature_size = (int) rcv << 8;
    rcv = uart_read(UART0, BLOCKING, &read);
    signature_size += (int) rcv;

    // Verify the signature size is correct
    if(signature_size!=256+16) {
        delay_ms(4900);
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    }

    // Load in signature frame from serial
    unsigned char signature_frame[signature_size];
    for (int i = 0; i < signature_size; ++i) {
        signature_frame[i] = uart_read(UART0, BLOCKING, &read);
    } // for

    // Initialize signature buffers for AES-GCM decryption
    unsigned char signature_tag[16];
    unsigned char signature_ct[256];
    unsigned char signature[(signature_size - 16) * 2];

    // Get signature tag and signature ciphertext from the signature frame
    for(int i = 0; i < 16; i++) {
        signature_tag[i] = signature_frame[i];
    } // for
    for(int i = 0; i < 256; i++) {
        signature_ct[i] = signature_frame[16 + i];
    } // for

    // Read Key & Nonce from EEPROM
    byte EEPROM_AES_KEY[16];
    byte EEPROM_AES_NONCE[12];
    EEPROMRead((uint32_t *) EEPROM_AES_KEY, 0x0, 16);
    EEPROMRead((uint32_t *) EEPROM_AES_NONCE, 0x0 + 16, 12);

    // Decrypt signature ciphertext with AES-GCM
    Aes dec;
    int res1 = wc_AesInit(&dec, NULL, INVALID_DEVID);

    // Exit if AES did not initialize properly
    if(res1!=0) {
        delay_ms(4900);
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    }

    int res2 = wc_AesGcmSetKey(&dec, EEPROM_AES_KEY, 16);

    // Exit if key failed to be set properly
    if(res2!=0) {
        delay_ms(4900);
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    }

    int res3 = wc_AesGcmDecrypt(&dec, signature, signature_ct, 256, EEPROM_AES_NONCE, 12, signature_tag, 16, aad, 4); 

    // Exit if signature failed to decrypt properly
    if(res3!=0) {
        delay_ms(4900);
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    }

    //Free AES object
    wc_AesFree(&dec);

    // Erase data from EEPROM_AES_Key
    for(int i = 0; i < 16; i++) {
        EEPROM_AES_KEY[i] = 0;
    } // for

    // Increment nonce for next decryption
    for(int i = 0; i < 12; i++) {
        if(++EEPROM_AES_NONCE[i]!=0) {
            break;
        }
    } // for

    // Erase data from EEPROM_AES_NONCE
    EEPROMProgram((uint32_t *) EEPROM_AES_NONCE, 0x0 + 16, 12);
    for(int i = 0; i < 12; i++) {
        EEPROM_AES_NONCE[i] = 0;
    } // for
    
    uart_write(UART0, OK); // Acknowledge the signature.
    
    // Initialize Sha256 object
    if (wc_InitSha256(&sha) != 0) {
        delay_ms(4900);
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    }

    // Initialize buffers for AES-GCM decryption
    unsigned char tag[16];
    unsigned char ct[256];
    unsigned char pt[FLASH_PAGESIZE]; // buffer to store decrypted firmware

    // Initialize counter variables
    int i = 0;
    int j = 0;

    // Initialize frame counting variables for length verification and firmware transfer
    int total_frame_amt = 0;
    int frame_ctr = 0;

    // Loop to receive frames, decrypt them, and store them in temporary flash
    while (1) {
        // Get two bytes for the length.
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length = (int)rcv << 8;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length += (int)rcv;

        // Verify that the frame length is valid
        if(frame_length!=256+16 && frame_length!=0) {
            delay_ms(4900);
            uart_write(UART0, ERROR); // Reject the metadata.
            SysCtlReset();            // Reset device
            return;
        }

        // Increment frame counting variables
        total_frame_amt += frame_length;
        frame_ctr++;

        // Break if the firmware being sent exceeds the maximum firmware length that the bootloader supports.
        if(total_frame_amt > 33728){
            break;
        }

        // Get the number of bytes specified in frame_length
        for (i = 0; i < frame_length; ++i) {
            tag_and_data[data_index] = uart_read(UART0, BLOCKING, &read);
            data_index++;
        } // for

        // If we filled our page buffer, program it
        if (data_index == FLASH_PAGESIZE+64 || frame_length == 0) {
            
            // Break if at zero length frame
            if(frame_length==0) {
                uart_write(UART0, OK);
                break;
            }

            // Loop through the 4 AES blocks in the 1024 bytes of FLASH_PAGESIZE
            for(i = 0; i < 4; i++) {

                // Get the tag and ciphertext from the frame data
                for(j = 0; j < 16; j++) {
                    tag[j] = tag_and_data[i*(256+16)+j];
                } // for
                for(j = 0; j < 256; j++) {
                    ct[j] = tag_and_data[i*(256+16)+j+16];
                } // for

                // Read Key & Nonce from EEPROM
                byte EEPROM_AES_KEY[16];
                byte EEPROM_AES_NONCE[12];
                EEPROMRead((uint32_t *) EEPROM_AES_KEY, 0x0, 16);
                EEPROMRead((uint32_t *) EEPROM_AES_NONCE, 0x0 + 16, 12);

                // Decrypt ciphertext with AES-GCM
                Aes dec;
                int res1 = wc_AesInit(&dec, NULL, INVALID_DEVID);

                // Exit if AES did not initialize properly
                if(res1!=0) {
                    delay_ms(4900);
                    uart_write(UART0, ERROR); // Reject the metadata.
                    SysCtlReset();            // Reset device
                    return;
                }

                int res2 = wc_AesGcmSetKey(&dec, EEPROM_AES_KEY, 16);

                // Exit if key failed to be set properly
                if(res2!=0) {
                    delay_ms(4900);
                    uart_write(UART0, ERROR); // Reject the metadata.
                    SysCtlReset();            // Reset device
                    return;
                }
                
                int res3 = wc_AesGcmDecrypt(&dec, pt+(i*256), ct, 256, EEPROM_AES_NONCE, 12, tag, 16, aad, 4); //Use the current block of plaintext

                // Exit if ciphertext failed to decrypt properly
                if(res3!=0) {
                    delay_ms(4900);
                    uart_write(UART0, ERROR); // Reject the metadata.
                    SysCtlReset();            // Reset device
                    return;
                }

                //Free AES object
                wc_AesFree(&dec);

                // Erase data from EEPROM_AES_KEY
                for(j = 0; j < 16; j++) {
                    EEPROM_AES_KEY[j] = 0;
                } // for

                // Increment nonce
                for(j = 0; j < 12; j++) {
                    if(++EEPROM_AES_NONCE[j]!=0) {
                        break;
                    }
                } // for

                // Reprogram incremented AES nonce in EEPROM and erase data from AES nonce
                EEPROMProgram((uint32_t *) EEPROM_AES_NONCE, 0x0 + 16, 12);
                for(j = 0; j < 12; j++) {
                    EEPROM_AES_NONCE[j] = 0;
                } // for

                // Update Sha256 hash with current block of plaintext
                if (wc_Sha256Update(&sha, pt+i*256, 256) != 0) {
                    delay_ms(4900);
                    uart_write(UART0, ERROR);
                    SysCtlReset();      
                    return;
                }
            } // for

             
            // Try to write flash and check for error
            if (program_flash((uint8_t *) page_addr, pt, FLASH_PAGESIZE)) {
                delay_ms(4900);
                uart_write(UART0, ERROR);
                SysCtlReset(); 
                return;
            }

            // Set firmware permissions in flash
            if((page_addr+FLASH_PAGESIZE-FW_BASE)%(2*FLASH_PAGESIZE)==0) {
                if(FlashProtectSet(page_addr-FLASH_PAGESIZE, FlashReadOnly)!=0) {
                    delay_ms(4900);
                    uart_write(UART0, ERROR);
                    SysCtlReset();
                    return;
                }
            }

            // Update to next page
            page_addr += FLASH_PAGESIZE;
            data_index = 0;
        } // if

        uart_write(UART0, OK); // Acknowledge the frame.
    } // while(1)
            
    // Finalize Sha256 hash
    if (wc_Sha256Final(&sha, hash) != 0) {
        delay_ms(4900);
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    }

    // Initialize RSA key and decode public key
    RsaKey rsa;
    word32 idx = 0;
    if (wc_InitRsaKey(&rsa, NULL) != 0) {
        delay_ms(4900);
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    }

    // Decode RSA Public Key
    if (wc_RsaPublicKeyDecode(RSA_PBK, &idx, &rsa, sizeof(RSA_PBK)) != 0) {
        delay_ms(4900);
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    }

    // Verify the signature
    size_t SIGN_SIZE = 256;
    unsigned char *signed_hash;
    int dec_len = wc_RsaPSS_VerifyInline(signature, SIGN_SIZE, &signed_hash, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &rsa); //fix addressing here
    if (dec_len < 0) {
        delay_ms(4900);
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    }
    
    // Check the hashes of the signature
    if (wc_RsaPSS_CheckPadding(hash, MAX_ENC_ALG_SZ, signed_hash, dec_len, WC_HASH_TYPE_SHA256) != 0){
        delay_ms(4900);
        uart_write(UART0, ERROR); // Reject the firmware
        SysCtlReset();            // Reset device
        return;
    }

    // Re-initialize page_addr to FW_TMP for firmware transfer
    page_addr = FW_TMP;
    for(i = 0; i < frame_ctr; i++) {
        // Try to transfer flash firmware from FW_TMP to FW_BASE and check for error
        if (program_flash((uint8_t *) real_page_addr, (uint8_t *) page_addr, FLASH_PAGESIZE)) {
            SysCtlReset();            // Reset device
            return;
        }

        // Set firmware permissions in flash
        if((page_addr+FLASH_PAGESIZE-FW_BASE)%(2*FLASH_PAGESIZE)==0) {
            if(FlashProtectSet(page_addr-FLASH_PAGESIZE, FlashExecuteOnly) != 0) {
                SysCtlReset();
                return;
            }
            if(FlashProtectSet(real_page_addr-FLASH_PAGESIZE, FlashExecuteOnly) != 0) {
                SysCtlReset();
                return;
            }
        }

        // Update to next page
        page_addr += FLASH_PAGESIZE;
        real_page_addr += FLASH_PAGESIZE;
    } // for

    return;
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
    __asm("LDR R0,=0x20001\n\t"
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
