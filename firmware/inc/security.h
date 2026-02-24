/**
 * @file security.h
 * @author University of Denver team
 * @brief Secure handling of requests
 * @date 2026
 *
 */
#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>

#include "filesystem.h"
#include "kernel.h"
#include "host_messaging.h"

#define MAX_PERMS 8
#define PIN_LENGTH 6

#define PIN_HASH_LEN 32
#define PIN_SALT_LEN 16

typedef enum {
    PERM_READ = 'R',
    PERM_WRITE = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

typedef struct {
    uint16_t group_id;
    uint8_t read;
    uint8_t write;
    uint8_t receive;
} group_permission_t;

typedef enum {
    XFORM_COPY = 0,   // plain copy
    XFORM_ENC  = 1,   // encrypt
    XFORM_DEC  = 2,   // decrypt
} xform_mode_t;

typedef struct {
    uint8_t hash[PIN_HASH_LEN];
    uint8_t salt[PIN_SALT_LEN];
} pin_hash_t;



// Byte encoding for RWC permissions
#define R_PERMISSION 0xF0
#define W_PERMISSION 0xA5
#define C_PERMISSION 0x5A
#define X_PERMISSION 0x00

#define AESGCM_KEY_SIZE 16
#define AESGCM_TAG_SIZE 16
#define AESGCM_IV_SIZE  12
#define NONCE_SIZE      16
#define HMAC_SIZE       32
#define WOLFSSL_STATIC_MEM_SIZE 512


// Numeric values assigned to different capabilities
#define CAP_READ	    0x0F     // the capability to read a file
#define CAP_READ_META   0x33     // the capability to read file metadata
#define CAP_SEND        0x3C     // the capability to read a file for transfer
#define CAP_WRITE       0x55     // the capability to write a file
#define CAP_RECEIVE     0x5A     // the capability to write a file from transfer
#define CAP_FILTER_META 0x66     // the capability to filter file metadata

// Context labels
#define LOCAL_LABEL_FILE    "local_file"
#define TRANSFER_LABEL_FILE "transfer_file"

/** @brief Initialize security related structures
*/
KERNEL_CODE void init_security();


/** @brief Concatenate bytes and store in an output buffer
 * 
 * @param out: the output buffer 
 * @param ...: variable list of arguments of the sequence
 *             uint8_t *bytes1, uint32_t bytes1_len, uint8_t *bytes2, 
 *             uint32_t bytes2_len, ..., NULL
 *
*/
KERNEL_CODE void join_bytes(uint8_t *out, ...);

/** @brief Erase pages in the flash memory scratchpad
 *
 * @param address: start address in scratchpad
 * @param size: number of bytes
 *
 * @return 0 on success else -1
 *
 * @note although size is an input, erases happen in multiples of flash page size
 *
*/
KERNEL_CODE int erase_scratchpad_pages(uint32_t address, uint32_t size);


/** @brief  Copy data from in to out while performing encrypt/decrypt
 *
 * @param in_buffer: input buffer
 * @param out_buffer: output_buffer
 * @param key: encryption/decryption key
 * @param mode: XFORM_ENC (encrypt) or XFORM_DEC (decrypt)
 * @param tag: tag (encrypt write tag, decrypt uses provided value to 
 *             verify integrity)
 * @param iv: iv (encrypt writes new iv, decrypt uses provided value)
 * @param len: data length
 * @param clear_offset: number of bytes from in_buffer that should be 
 *                      plainly copied from in to out
 * @param is_dest_flash: boolean saying if out_buffer is in flash
 *
 * @note The function uses an internal buffer to perform the operations
 *       as wolfssl performs SRAM write; also we do the move in chunks
*/
KERNEL_CODE int copy_with_transform(uint8_t *in_buffer, uint8_t *out_buffer, 
                                uint8_t *key, xform_mode_t mode,
                                uint8_t *tag, uint8_t *iv,
                                uint32_t len, uint32_t clear_offset,
                                bool is_dest_flash);                               

/** @brief Derive a key (max 256 bit) using HMAC-SHA256
 *
 * @param secret: HMAC secret
 * @param nonce: the bytes to use as nonce in key derivation
 * @param nonce_len: size of nonce
 * @param key: buffer for output key (size if AESGCM_KEY_SIZE, 128 bit default)
 * 
 * @return 0 on success else -1
 *
*/
KERNEL_CODE int create_key(uint8_t *secret, uint8_t *nonce, uint32_t nonce_len, uint8_t *key);


///////////////////////////////////////////////


/** @brief Check pin and set active capability based on command
 *
 * @param cmd: the command
 * @param pin: the pin to check
 *
 * @return 0 on success, negative number on error
 *
 * @security_req pin hash must match stored hash
 *
*/
KERNEL_CODE int secure_check_pin(msg_type_t cmd, unsigned char *pin);


/** @brief Read a file, decrypt it, and provide to local user
 *
 * @param slot: the slot number
 * @param curr_file: user buffer to return the file
 *
 * @return 0 on success, negative number on error
 *
 * @note Runs for READ command
 *
 * @security_req active_cap = CAP_READ and R permission on file group
 *
*/
KERNEL_CODE int secure_read_file(slot_t slot, file_t *curr_file);


/** @brief Prepare a list of file metadata and provide to local user
 *
 * @param file_list_ptr: user buffer to return the file list
 *
 * @return 0 on success, negative number on error
 *
 * @note Runs for LIST command
 *
 * @security_req active_cap = CAP_READ_META
 *
*/
KERNEL_CODE int secure_read_file_meta(void *file_list_ptr);


/** @brief Write a file after encryption
 *
 * @param slot: the slot number to write at
 * @param src: user buffer with file data
 * @param uuid: the UUID to use for the file
 *
 * @return 0 on success, negative number on error
 *
 * @note Runs for WRITE command
 *
 * @security_req active_cap = CAP_WRITE and W permission on file group
 *
*/
KERNEL_CODE int secure_write_file(slot_t slot, file_t *src, uint8_t *uuid);


/** @brief Prepare a list of encrypted file metadata for remote user
 *
 * @param file_list_ptr: user buffer for encrypted file metadata
 *
 * @return 0 on success, negative number on error
 *
 * @note Runs for INTERROGATE command on responder side
 *
 * @security_req active_cap = CAP_SEND and W permission on reported files
 *
*/
KERNEL_CODE int secure_read_file_meta_for_transfer(void *file_list_ptr);


/** @brief Filter received list of encrypted file metadata and provide to local user
 *
 * @param file_list_ptr: user buffer with encrypted file metadata
 * @param nonce: this side's nonce used in transfer encryption
 *
 * @return 0 on success (user buffer will contain decrypted content), 
 *         negative number on error
 *
 * @note Runs for INTERROGATE command on initiator side
 *
 * @security_req active_cap = CAP_FILTER_META and C permission on reported files
 *
*/
KERNEL_CODE int secure_filter_file_meta(void *file_list_ptr, uint8_t *nonce);


/** @brief Prepare an encrypted file for remote user
 *
 * @param request_ptr: user buffer with request details (in/out slots, remote permissions)
 * @param response_ptr: user buffer for encrypted file data
 *
 * @return 0 on success, negative number on error
 *
 * @note Runs for RECEIVE command on responder side
 *
 * @security_req active_cap = CAP_SEND, local W permission and remote C permission on file
 *
*/
KERNEL_CODE int secure_read_file_for_transfer(void *request_ptr, void *response_ptr);


/** @brief Decrypt received file, re-encrypt and store 
 *
 * @param response_ptr: user buffer with encrypted file data
 * @param req_nonce: the nonce used during request
 * @param slot: slot number to write to
 *
 * @return 0 on success, negative number on error
 *
 * @note Runs for RECEIVE command on initiator side
 *
 * @security_req active_cap = CAP_RECEIVE and C permission on file
 *
*/
KERNEL_CODE int secure_write_file_from_transfer(void *response_ptr, uint8_t *req_nonce, slot_t slot);


#endif  // __SECURITY_H__



