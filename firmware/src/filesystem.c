/**
 * @file filesystem.c
 * @author Samuel Meyers
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>

#include "filesystem.h"
#include "simple_flash.h"
#include "host_messaging.h"

KERNEL_BSS filesystem_entry_t FILE_ALLOCATION_TABLE[MAX_FILE_COUNT];

KERNEL_CODE int load_fat() {
    flash_simple_read((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

KERNEL_CODE int store_fat() {
    flash_simple_erase_page(_FLASH_FAT_START);
    return flash_simple_write((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
}

/** @brief Initialize the filesystem
 *
 *
 * @return 0 upon success. A negative value on error.
*/
KERNEL_CODE int init_fs() {
    return load_fat();
}


/** @brief Create a new file object in memory
 *
 *  @param dest: the file object buffer
 *  @param group_id: file's group id
 *  @param name: file's name (max MAX_NAME_SIZE characters)
 *  @param contents_len: length of the file
 *  @param contents: buffer holding file's contents
 *
 * @return 0 upon success. A negative value otherwise.
*/
int create_file(
    file_t *dest,
    group_id_t group_id,
    char *name,
    uint16_t contents_len,
    uint8_t *contents
) {
    int i = 0;
    
    if (dest == NULL || name == NULL || contents == NULL) return -1;
    
    // Ensure lengths are within bound
    if (contents_len > MAX_CONTENTS_SIZE) return -1;
    for (i = 0; i < MAX_NAME_SIZE; i++) {
        if (name[i] == 0x0) break;
    }
    if (i == MAX_NAME_SIZE) return -1;
    
     
    memset(dest, 0, sizeof(file_t));

    dest->in_use = FILE_IN_USE;
    dest->group_id = group_id;
    dest->contents_len = contents_len;


    // Name is atmost MAX_NAME_SIZE bytes, and the contents are defined by a length
    strncpy(dest->name, name, MAX_NAME_SIZE);
    memcpy(dest->contents, contents, contents_len);
    return 0;
}


/** @brief Write a file to flash 
 *
 *  @param slot The slot to write the file to
 *  @param src The source file to store
 *  @param uuid The UUID to store in the FAT
 *
 * @return 0 upon success. A negative value otherwise.
*/
KERNEL_CODE int write_file(slot_t slot, file_t *src, uint8_t *uuid) {
    unsigned int file_size, flash_addr;

    if (src == NULL || uuid == NULL) return -1;
    
    
    flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    file_size = FILE_TOTAL_SIZE(src->contents_len);
    
    if (file_size > MAX_CONTENTS_SIZE) return -1;
    
    // Update the FAT for the new file
    memcpy(&FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
    FILE_ALLOCATION_TABLE[slot].length = file_size;
    store_fat();

    // Erase the pages that will store the file
    for (int i = 0; i < FILE_PAGE_COUNT; i++) {
        flash_simple_erase_page(flash_addr + (FLASH_PAGE_SIZE * i));
    }

    // Now write the file
    return flash_simple_write(flash_addr, src, file_size);
}

/** @brief Read a file from flash storage to scracthpad
 *
 *  @param slot The slot to read
 *  @param dest The destination address in flash to read into
 *
 * @return 0 upon success. A negative value otherwise.
*/
KERNEL_CODE int read_file(slot_t slot, file_t *dest) {
    int flash_addr, file_size;
    
    if (dest == NULL) return -1;
    
    flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;
    file_size = FILE_ALLOCATION_TABLE[slot].length;
    
    if (flash_addr < 0 || file_size < 0) {
        return -1;
    }

    // NOTE: this is a file read, but the destination is a location in 
    // flash
    
    // Erase the pages that will store the file
    for (int i = 0; i < FILE_PAGE_COUNT; i++) {
        flash_simple_erase_page((uint32_t)dest + (FLASH_PAGE_SIZE * i));
    }

    // Now read the file from flash storage and write to flash location
    return flash_simple_write((uint32_t)dest, (void *)flash_addr, file_size);
    
    return 0;
}

/** @brief Read a file's metadata from persistent storage into memory
 *
 *  @param slot The slot to read
 *  @param dest The destination address to store the file heaader
 *
 * @return 0 upon success. A negative value otherwise.
*/
KERNEL_CODE int read_file_metadata(slot_t slot, file_header_t *dest) {
    int flash_addr, file_size;

    if (dest == NULL) return -1;
    
    flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;

    if (flash_addr < 0 || file_size < 0) {
        return -1;
    }

    flash_simple_read(flash_addr, dest, sizeof(file_header_t));

    return 0;
}


