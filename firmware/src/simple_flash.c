/**
 * @file "simple_flash.c"
 * @author Samuel Meyers
 * @brief Simple Flash Interface Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "simple_flash.h"
#include "host_messaging.h"
#include "kernel.h"


#if !ON_BOARD

KERNEL_CODE int flash_simple_erase_page(uint32_t address) {
    // In Renode's default MappedMemory, 'erasing' is just writing 0xFF
    // A standard page size is usually 1KB (0x400) 
    memset((void *)address, 0xFF, FLASH_PAGE_SIZE); 
    return 0;
}

KERNEL_CODE void flash_simple_read(uint32_t address, void* buffer, uint32_t size) {
    memcpy(buffer, (void *)address, size);
}

KERNEL_CODE int flash_simple_write(uint32_t address, void* buffer, uint32_t size) {
    // In Renode, we can write directly to the flash memory address
    memcpy((void *)address, buffer, size);
    return 0;
}

#else

/**
 * @brief Flash Simple Erase Page
 *
 * @param address: uint32_t, address of flash page to erase
 *
 * @return int: return negative if failure, zero if success
 *
 * This function erases a page of flash such that it can be updated.
 * Flash memory can only be erased in a large block size called a page (or sector).
 * Once erased, memory can only be written one way e.g. 1->0.
 * In order to be re-written the entire page must be erased.
*/
KERNEL_CODE int flash_simple_erase_page(uint32_t address) {

    volatile DL_FLASHCTL_COMMAND_STATUS cmdStatus;
    DL_FlashCTL_executeClearStatus(FLASHCTL);

    DL_FlashCTL_unprotectSector(FLASHCTL, address, DL_FLASHCTL_REGION_SELECT_MAIN);

    // Controller runs code from RAM; so allow execute briefly
    K_SRAM_EXECUTE(
        cmdStatus = DL_FlashCTL_eraseMemoryFromRAM(
            FLASHCTL, address, DL_FLASHCTL_COMMAND_SIZE_SECTOR);
    );
    
    if (cmdStatus == DL_FLASHCTL_COMMAND_STATUS_FAILED) {
        return -1;
    }
    // returns a boolean, so handle that accordingly
    bool ret = DL_FlashCTL_waitForCmdDone(FLASHCTL);

    if (ret == false) {
        return -1;
    }
    return 0;
}

/**
 * @brief Flash Simple Read
 *
 * @param address: uint32_t, address of flash page to read
 * @param buffer: void*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 *
 * This function reads data from the specified flash page into the buffer
 * with the specified amount of bytes
*/
KERNEL_CODE void flash_simple_read(uint32_t address, void* buffer, uint32_t size) {
    // flash is memory mapped, and the flash controller has no read functionality
    memcpy(buffer, (void *)address, size);
}

/**
 * @brief Flash Simple Write
 *
 * @param address: uint32_t, address of flash page to write
 * @param buffer: void*, pointer to buffer to write data from
 * @param size: uint32_t, number of bytes to write from flash
 *
 * @return int: return negative if failure, zero if success
 *
 * This function writes data to the specified flash page from the buffer passed
 * with the specified amount of bytes. Flash memory can only be written in one
 * way e.g. 1->0. To rewrite previously written memory see the
 * flash_simple_erase_page documentation.
*/
KERNEL_CODE int flash_simple_write(uint32_t address, void* buffer, uint32_t size) {
    volatile DL_FLASHCTL_COMMAND_STATUS cmdStatus;
    uint8_t *src = (uint8_t *)buffer;
    
    
    // 64-bit programming wants 8-byte alignment
    if (address & 0x7u) return -1;
    
    uint32_t write_data[512 / 4]; // doing 512 bytes at a time
    
    DL_FlashCTL_executeClearStatus(FLASHCTL);
    DL_FlashCTL_unprotectSector(FLASHCTL, address, DL_FLASHCTL_REGION_SELECT_MAIN);
    
    // Due to kernel stack limits, we do writes in 512 byte chunks
    while (size > 0) {
        uint32_t n = (size >= 512) ? 512 : size;
        
        // program function expects size to be the number of 32-bit words
        uint32_t size_32b = (n % 4 == 0) ? (n / 4) : (n / 4) + 1;
        // it also expects it to be an even number
        size_32b = (size_32b % 2 == 0) ? size_32b : size_32b + 1;
        
        memset(write_data, 0xff, size_32b*4);
        memcpy(write_data, src, n);
        
        // Controller runs code from RAM; so allow execute briefly
        K_SRAM_EXECUTE(
            // if memory section is corrected, make sure to write the ECC (you have been warned)
            cmdStatus = DL_FlashCTL_programMemoryBlockingFromRAM64WithECCGenerated(
                FLASHCTL, address, (uint32_t *)write_data, size_32b, DL_FLASHCTL_REGION_SELECT_MAIN
            );
        );
        
        if (cmdStatus == DL_FLASHCTL_COMMAND_STATUS_FAILED) {
            return -1;
        }
        // returns a boolean, so handle that accordingly
        bool ret = DL_FlashCTL_waitForCmdDone(FLASHCTL);
        if (ret == false) {
            return -1;
        }
        
        address += size_32b*4;
        src += n;
        size -= n;
    }

    return 0;
}

#endif
