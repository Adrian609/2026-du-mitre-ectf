/**
 * @file security.c
 * @author University of Denver team
 * @brief Secure handling of requests
 * @date 2026
 *
 */

#define SECRETS_DEFINE
#include "secrets.h"
#include "security.h"
#include "host_messaging.h"
#include "kernel.h"
#include "filesystem.h"
#include "simple_flash.h"
#include "commands.h"
#include "simple_random.h"
#include "user_settings.h"
#include <stdint.h>
#include <stdarg.h>
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/misc.h"


extern filesystem_entry_t FILE_ALLOCATION_TABLE[MAX_FILE_COUNT]; // from filesystem.c

extern uint32_t prng_counter; // from simple_random.c

// Checks if two values are same but using multiple steps
// NOTE: The function where this is placed returns with provided
// error code (err_code) on failure
#define EQ_CHECK_BARRIER(actual, expected, err_code)                                \
    do                                                                              \
    {                                                                               \
        volatile uint32_t _failed = 0x5A5A5A5A;                                     \
        volatile unsigned long long _a = (volatile unsigned long long)((actual));   \
        volatile unsigned long long _e = (volatile unsigned long long)((expected)); \
        if (_a != _e)                                                               \
        {                                                                           \
            _failed = 0xA5A5A5A5;                                                   \
            return ((err_code));                                                    \
        }                                                                           \
        if (_a == 0x0000000000000000ull)                                            \
        {                                                                           \
            _failed = 0xA5A5A5A5;                                                   \
            return ((err_code));                                                    \
        }                                                                           \
        if (_a == 0xFFFFFFFFFFFFFFFFull)                                            \
        {                                                                           \
            _failed = 0xA5A5A5A5;                                                   \
            return ((err_code));                                                    \
        }                                                                           \
        if ((_a ^ _e) != 0x0000000000000000ull)                                     \
        {                                                                           \
            _failed = 0xA5A5A5A5;                                                   \
            return ((err_code));                                                    \
        }                                                                           \
        if (_failed == 0xA5A5A5A5)                                                  \
        {                                                                           \
            return ((err_code));                                                    \
        }                                                                           \
    } while (0)

/*
 * A capability is about intent. It is given during pin check based on the
 * command. CMD_TO_CAP_MAP is a lookup table of the capability given for a
 * command. Functions require that a certain capability is active for them
 * to proceed. Functions also require that certain permissions are present
 * for file operations. We write these as two separate macros for reuse.
 *
 * NOTE: An active capability is one-time use
 */

// Checks if required capability (req_cap) is equal to active capability
// NOTE: active capability is erase irrespective of outcome
#define SECURE_CAP_CHECK(req_cap)                     \
    do                                                \
    {                                                 \
        volatile uint8_t _actual = active_cap;        \
        active_cap = 0x00;                            \
        __asm__ volatile("" ::: "memory");            \
        EQ_CHECK_BARRIER(_actual, req_cap, PERM_ERR); \
        active_cap = 0x00;                            \
        _actual = 0x00;                               \
        __asm__ volatile("" ::: "memory");            \
    } while (0)

// Checks if a permission (req_perm) is present for a given group (group id)
// in a permission structure (perms_structure)
// NOTE: only one of mr, mw or mc will be zero
#define SECURE_PERM_CHECK(gid, req_perm, perms_structure)                              \
    do                                                                                 \
    {                                                                                  \
        uint8_t volatile _have_perm = X_PERMISSION;                                    \
        for (int __i = 0; __i < MAX_PERMS; __i++)                                      \
        {                                                                              \
            if ((perms_structure)[__i].group_id == (gid))                              \
            {                                                                          \
                uint8_t volatile _mr = !((perms_structure)[__i].read ^ (req_perm));    \
                uint8_t volatile _mw = !((perms_structure)[__i].write ^ (req_perm));   \
                uint8_t volatile _mc = !((perms_structure)[__i].receive ^ (req_perm)); \
                _have_perm = _mr * (perms_structure)[__i].read +                       \
                             _mw * (perms_structure)[__i].write +                      \
                             _mc * (perms_structure)[__i].receive;                     \
                break;                                                                 \
            }                                                                          \
        }                                                                              \
        EQ_CHECK_BARRIER(_have_perm, req_perm, PERM_ERR);                              \
    } while (0)

// The internal capability state (set after pin check and reset
// by command functions)
KERNEL_DATA volatile uint8_t active_cap = 0x00;

// Lookup table to map a command to a capability
KERNEL_CONST uint8_t CMD_TO_CAP_MAP[256] = {
    [LIST_MSG] = CAP_READ_META,          // 'L'
    [READ_MSG] = CAP_READ,               // 'R'
    [WRITE_MSG] = CAP_WRITE,             // 'W'
    [RECEIVE_MSG] = CAP_RECEIVE,         // 'C'
    [INTERROGATE_MSG] = CAP_FILTER_META, // 'I'
    [LISTEN_MSG] = CAP_SEND,             // 'N'
};

// Kernel scratchpad for internal operations
KERNEL_STAGE file_t k_curr_file;
KERNEL_STAGE file_t k_curr_file_b;

// Copy of global permissions accessible by unprivileged code
group_permission_t global_permissions_u[MAX_PERMS];

// HMAC on global permissions structure
uint8_t global_permissions_sig[HMAC_SIZE];

// Wolfssl objects
KERNEL_DATA static Aes e_gcm;
KERNEL_DATA static Aes d_gcm;
KERNEL_DATA __attribute__((aligned(4))) uint8_t wolfssl_e_heap[WOLFSSL_STATIC_MEM_SIZE];
KERNEL_DATA __attribute__((aligned(4))) uint8_t wolfssl_d_heap[WOLFSSL_STATIC_MEM_SIZE];
KERNEL_DATA WOLFSSL_HEAP_HINT *p_e_hint = NULL;
KERNEL_DATA WOLFSSL_HEAP_HINT *p_d_hint = NULL;

/////////////////////////////////////////////////////////////////////////
//
// HELPER FUNCTIONS
//
/////////////////////////////////////////////////////////////////////////

/** @brief Initialize security related structures
 */
KERNEL_CODE void init_security()
{
    // Init encryption engine
    memset(&e_gcm, 0, sizeof(Aes));
    memset(wolfssl_e_heap, 0, WOLFSSL_STATIC_MEM_SIZE);

    if (wc_LoadStaticMemory(&p_e_hint, wolfssl_e_heap, WOLFSSL_STATIC_MEM_SIZE, WOLFMEM_GENERAL, 0) < 0)
    {
        print_debug("Encrypt LoadStaticMemory failed\n");
    }

    if (wc_AesInit(&e_gcm, p_e_hint, INVALID_DEVID) < 0)
    {
        print_debug("Encrypt AesInit failed\n");
    }

    // Init decryption engine
    memset(&d_gcm, 0, sizeof(Aes));
    memset(wolfssl_d_heap, 0, WOLFSSL_STATIC_MEM_SIZE);

    if (wc_LoadStaticMemory(&p_d_hint, wolfssl_d_heap, WOLFSSL_STATIC_MEM_SIZE, WOLFMEM_GENERAL, 0) < 0)
    {
        print_debug("Decrypt LoadStaticMemory failed\n");
    }

    if (wc_AesInit(&d_gcm, p_d_hint, INVALID_DEVID) < 0)
    {
        print_debug("Decrypt AesInit failed\n");
    }

    // Init prng counter
    generate_trng_block((uint8_t *)&prng_counter, 4);

    // Copy permission structure to user accessible placeholder
    memcpy((void *)global_permissions_u, (void *)global_permissions, sizeof(group_permission_t) * MAX_PERMS);

    // Compute HMAC on global permission structure and place it in user accessible memory
    Hmac hmac;
    wc_HmacSetKey(&hmac, WC_SHA256, (void *)aes_128_shared_key, AESGCM_KEY_SIZE);
    wc_HmacUpdate(&hmac, (void *)global_permissions, sizeof(group_permission_t) * MAX_PERMS);
    wc_HmacFinal(&hmac, (void *)global_permissions_sig);
}

/** @brief Concatenate bytes and store in an output buffer
 *
 * @param out: the output buffer
 * @param ...: variable list of arguments of the sequence
 *             uint8_t *bytes1, uint32_t bytes1_len, uint8_t *bytes2,
 *             uint32_t bytes2_len, ..., NULL
 *
 */
KERNEL_CODE void join_bytes(uint8_t *out, ...)
{
    va_list args;
    va_start(args, out);

    uint32_t len_sum = 0;
    uint8_t *next_bytes;

    // Iterate through pairs until a NULL pointer
    while ((next_bytes = va_arg(args, uint8_t *)) != NULL)
    {
        uint32_t next_len = va_arg(args, uint32_t);

        if (next_len > 0)
        {
            memcpy(out + len_sum, next_bytes, next_len);
            len_sum += next_len;
        }
    }

    va_end(args);
}

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
KERNEL_CODE int erase_scratchpad_pages(uint32_t address, uint32_t size)
{
    // Address must be page aligned
    if (address % FLASH_PAGE_SIZE != 0)
        return -1;

    // Address must be in kernel staging area
    if (address < START_KERNEL_STAGE)
        return -1;
    if (size > (END_KERNEL_STAGE - address + 1))
        return -1;

    // Calculate number of pages based on size
    uint32_t num_pages = (size + (FLASH_PAGE_SIZE - 1)) / FLASH_PAGE_SIZE;

    // Erase the pages
    for (uint32_t p = 0; p < num_pages; p++)
    {
        uint32_t page_addr = address + (p * FLASH_PAGE_SIZE);

        if (flash_simple_erase_page(page_addr) < 0)
            return -1;
    }

    return 0;
}

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
 *       as wolfssl performs SRAM write; also we do the move in chunks;
 *       tag size is assumed to be AESGCM_TAG_SIZE, iv size is assumed to
 *       be AESGCM_IV_SIZE
 *
 */
KERNEL_CODE int copy_with_transform(uint8_t *in_buffer, uint8_t *out_buffer,
                                    uint8_t *key, xform_mode_t mode,
                                    uint8_t *tag, uint8_t *iv,
                                    uint32_t len, uint32_t clear_offset,
                                    bool is_dest_flash)
{

    // Validate parameters
    if (in_buffer == NULL || out_buffer == NULL || key == NULL || tag == NULL || iv == NULL)
        return INTERNAL_ERR;
    if (mode != XFORM_ENC && mode != XFORM_DEC)
        return INTERNAL_ERR;

    // Length check
    if (len == 0) return 0;
    
    // Clamp clear_offset to len
    if (clear_offset > len)
        clear_offset = len;

    // Crypto init, if any
    if (mode == XFORM_ENC)
    {
        if (generate_random_bytes(iv, AESGCM_IV_SIZE) < 0) return INTERNAL_ERR;
        
        int ret = wc_AesGcmEncryptInit(&e_gcm, key, AESGCM_KEY_SIZE, iv, AESGCM_IV_SIZE);
        if (ret < 0)
            return AES_ENCRYPT_ERR;
    }
    else if (mode == XFORM_DEC)
    {
        int ret = wc_AesGcmDecryptInit(&d_gcm, key, AESGCM_KEY_SIZE, iv, AESGCM_IV_SIZE);
        if (ret < 0)
            return AES_DECRYPT_ERR;
    }

    // Initialize buffer with zeroes
    uint8_t sram_buffer[FLASH_PAGE_SIZE] = {0};

    for (int i = 0; i < len; i += FLASH_PAGE_SIZE)
    {

        // Clear sram_buffer
        memset(sram_buffer, 0x00, FLASH_PAGE_SIZE);

        // Figure out how many bytes to copy
        int n;
        if (i + FLASH_PAGE_SIZE < len)
        {
            n = FLASH_PAGE_SIZE;
        }
        else
        {
            n = len - i;
        }

        // How many bytes in this chunk are clear
        int clear_bytes = 0;
        if (clear_offset <= i)
        {
            clear_bytes = 0;
        }
        else if (clear_offset >= i + n)
        {
            clear_bytes = n;
        }
        else
        {
            clear_bytes = clear_offset - i;
        }

        // How many bytes in this chunk are to be encrypted or decrypted
        int remaining_bytes = n - clear_bytes;

        // Copy clear bytes
        if (clear_bytes > 0)
        {
            memcpy(sram_buffer, in_buffer + i, clear_bytes);
        }

        // Perform crypto operations
        if (remaining_bytes > 0)
        {
            if (mode == XFORM_ENC)
            {
                int ret = wc_AesGcmEncryptUpdate(&e_gcm, sram_buffer + clear_bytes, in_buffer + i + clear_bytes, remaining_bytes, NULL, 0);
                if (ret < 0)
                    return AES_ENCRYPT_ERR;
            }
            else if (mode == XFORM_DEC)
            {
                int ret = wc_AesGcmDecryptUpdate(&d_gcm, sram_buffer + clear_bytes, in_buffer + i + clear_bytes, remaining_bytes, NULL, 0);
                if (ret < 0)
                    return AES_DECRYPT_ERR;
            }
        }

        // write the page
        if (is_dest_flash)
        {
            flash_simple_erase_page((uint32_t)(out_buffer + i));
            flash_simple_write((uint32_t)(out_buffer + i), sram_buffer, n);
        }
        else
        {
            memcpy(out_buffer + i, sram_buffer, n);
        }
    }

    // Ensure sram memory is cleared
    memset(sram_buffer, 0x00, FLASH_PAGE_SIZE);
    __asm__ volatile("" ::: "memory");

    // Finalize encryption or verify decryption
    if (mode == XFORM_ENC)
    {
        int ret = wc_AesGcmEncryptFinal(&e_gcm, tag, AESGCM_TAG_SIZE);
        if (ret < 0)
            return AES_ENCRYPT_ERR;
    }
    else if (mode == XFORM_DEC)
    {
        int ret = wc_AesGcmDecryptFinal(&d_gcm, tag, AESGCM_TAG_SIZE);
        if (ret < 0)
            return AES_TAG_ERR;
    }

    return 0;
}

/** @brief Derive a key (max 256 bit) using HMAC-SHA256
 *
 * @param secret: HMAC secret
 * @param nonce: the bytes to use as nonce in key derivation
 * @param nonce_len: size of nonce
 * @param key: buffer for output key (size is AESGCM_KEY_SIZE, 128 bit default)
 *
 * @return 0 on success else -1
 *
 */
KERNEL_CODE int create_key(uint8_t *secret, uint8_t *nonce, uint32_t nonce_len, uint8_t *key)
{
    int ret = -1;


    // Validate inputs
    if (key == NULL || secret == NULL || nonce == NULL)
        return INTERNAL_ERR;
    if (nonce_len <= 0 || AESGCM_KEY_SIZE <= 0)
        return INTERNAL_ERR;
    if (nonce_len > 0 && nonce == NULL)
        return INTERNAL_ERR;
    if (AESGCM_KEY_SIZE > HMAC_SIZE)
        return INTERNAL_ERR;

    // Initialize hmac
    Hmac h;
    uint8_t digest[HMAC_SIZE]; // SHA-256 output size
    ret = wc_HmacInit(&h, NULL, INVALID_DEVID);
    if (ret != 0)
        return INTERNAL_ERR;

    // Set hmac key
    ret = wc_HmacSetKey(&h, WC_SHA256, secret, AESGCM_KEY_SIZE);
    if (ret != 0) return INTERNAL_ERR;
    
    // The message to hash, which should be the nonce data
    ret = wc_HmacUpdate(&h, nonce, (word32)nonce_len);
    if (ret != 0) return INTERNAL_ERR;

    // Calculate hmac digest
    ret = wc_HmacFinal(&h, digest);
    wc_HmacFree(&h);
    if (ret != 0)
    {
        memset(digest, 0x0, sizeof(digest));
        return INTERNAL_ERR;
    }

    // Copy the hmac digest to output, clear and sync memory
    memcpy(key, digest, AESGCM_KEY_SIZE);
    memset(digest, 0x0, sizeof(digest));
    __asm__ volatile("" ::: "memory");

    return 0;
}

/** @brief Copy file meta from source to destination if C permission available
 *         on file group
 *
 * @param dest: the destination file metadata object
 * @param src: the source file metadata object
 *
 * @return 0 on success, negative number otherwise
 *
 */
KERNEL_CODE int copy_meta_if_C_permitted(file_metadata_t *dest, file_metadata_t *src)
{
    group_id_t group_id = src->group_id; // the file's group id

    // Check if C permission is present on group
    SECURE_PERM_CHECK(group_id, C_PERMISSION, global_permissions);

    // Copy over the meta data
    memcpy(dest, src, sizeof(file_metadata_t));

    return 0;
}

/////////////////////////////////////////////////////////////////////////
//
// SECURITY FUNCTIONS
//
/////////////////////////////////////////////////////////////////////////

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
KERNEL_CODE int secure_check_pin(msg_type_t cmd, unsigned char *pin)
{
    if (cmd == LISTEN_MSG)
    { // pin not required for listen command
        active_cap = CMD_TO_CAP_MAP[LISTEN_MSG];
        return 0;
    }

    if (pin == NULL)
        return INTERNAL_ERR;

    active_cap = 0x00;                 // no capability
    __asm__ volatile("" ::: "memory"); // memory sync

    byte salted_pin[PIN_SALT_LEN + PIN_LENGTH];
    byte computed_hash[PIN_HASH_LEN];

    // Compute SHA256 hash of (salt | pin)
    memcpy(&salted_pin[0], (void *)pin_hash.salt, PIN_SALT_LEN);
    memcpy(&salted_pin[PIN_SALT_LEN], pin, PIN_LENGTH);

    int hc = wc_Sha256Hash((const byte *)salted_pin, (word32)(PIN_SALT_LEN + PIN_LENGTH), computed_hash);
    if (hc != 0)
    {
        return INTERNAL_ERR;
    }

    // Compare derived hash to expected (from secrets.h)
    int ret = ConstantCompare(computed_hash, (void *)pin_hash.hash, PIN_HASH_LEN) ^ 0xA5A5A5A5u;
    EQ_CHECK_BARRIER(ret & 0xFFFFFFFFu, 0xA5A5A5A5u, PIN_ERR);

    memset(computed_hash, 0x00, PIN_HASH_LEN); // scrub the hash

    // Lookup capability based on command and set as active
    active_cap = CMD_TO_CAP_MAP[cmd];

    return 0;
}


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
KERNEL_CODE int secure_read_file(slot_t slot, file_t *curr_file)
{
    int ret = -1;
    file_header_t f_header;
    uint32_t headers_len = offsetof(file_t, aes_gcm_iv);
    uint8_t key[AESGCM_KEY_SIZE] = {0};
    uint8_t iv_buffer[AESGCM_IV_SIZE] = {0};
    uint8_t tag_buffer[AESGCM_TAG_SIZE] = {0};
    uint8_t nonce[sizeof(file_header_t) + UUID_SIZE + 16] = {0};


    // Validate inputs
    if (curr_file == NULL)
        return INTERNAL_ERR;
    if (slot < 0 || slot > 7)
        return READ_ERR;

    // Read the file header, check permission
    ret = read_file_metadata(slot, &f_header);
    if (ret != 0) return READ_META_ERR;
        
    SECURE_CAP_CHECK(CAP_READ);
    SECURE_PERM_CHECK(f_header.group_id, R_PERMISSION, global_permissions);

    // Read file into scrathpad
    ret = erase_scratchpad_pages((uint32_t)&k_curr_file, sizeof(file_t));
    if (ret != 0) return INTERNAL_ERR;
    
    ret = read_file(slot, &k_curr_file);    
    if (ret != 0) return READ_ERR;
    
    // Prepare nonce bytes, derive key
    join_bytes((uint8_t *)nonce, (uint8_t *)&f_header, (uint32_t)headers_len,
               (uint8_t *)FILE_ALLOCATION_TABLE[slot].uuid, (uint32_t)UUID_SIZE,
               (uint8_t *)LOCAL_LABEL_FILE, (uint32_t)strlen(LOCAL_LABEL_FILE),
               NULL);
    ret = create_key((uint8_t *)aes_128_local_key,
                     (uint8_t *)nonce, sizeof(nonce),
                     (uint8_t *)key);
                     
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }


    // Decrypt and check integrity
    memcpy(iv_buffer, f_header.aes_gcm_iv, AESGCM_IV_SIZE);
    memcpy(tag_buffer, f_header.aes_gcm_tag, AESGCM_TAG_SIZE);
            
    ret = copy_with_transform((uint8_t *)&k_curr_file, (uint8_t *)curr_file,
                              (uint8_t *)key, XFORM_DEC,
                              (uint8_t *)tag_buffer, (uint8_t *)iv_buffer,
                              FILE_TOTAL_SIZE(k_curr_file.contents_len), sizeof(file_header_t),
                              false);


cleanup:
    // Clean up memory
    memset(iv_buffer, 0, AESGCM_IV_SIZE);
    memset(tag_buffer, 0, AESGCM_TAG_SIZE);
    memset(key, 0, AESGCM_KEY_SIZE);
    __asm__ volatile("" ::: "memory");
    erase_scratchpad_pages((uint32_t)&k_curr_file, sizeof(file_t));
            
    return ret;
}


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
KERNEL_CODE int secure_write_file(slot_t slot, file_t *src, uint8_t *uuid)
{
    int ret = -1;
    uint32_t headers_len = offsetof(file_t, aes_gcm_iv);
    uint8_t key[AESGCM_KEY_SIZE] = {0};
    uint8_t iv_buffer[AESGCM_IV_SIZE] = {0};
    uint8_t tag_buffer[AESGCM_TAG_SIZE] = {0};
    uint8_t nonce[sizeof(file_header_t) + UUID_SIZE + 16] = {0};


    // Validate inputs
    if (src == NULL || uuid == NULL)
        return INTERNAL_ERR;
    if (slot < 0 || slot > 7)
        return WRITE_ERR;

    SECURE_CAP_CHECK(CAP_WRITE);
    SECURE_PERM_CHECK(src->group_id, W_PERMISSION, global_permissions);


    // Clear enough memory for this file at k_curr_file (kernel memory reserved for file operations)
    ret = erase_scratchpad_pages((uint32_t)&k_curr_file, sizeof(file_t));
    if (ret != 0) return INTERNAL_ERR;
 
        
    // Create nonce by joining header bytes, UUID bytes, and context label
    join_bytes((uint8_t *)nonce, (uint8_t *)src, (uint32_t)headers_len,
               (uint8_t *)uuid, (uint32_t)UUID_SIZE,
               (uint8_t *)LOCAL_LABEL_FILE, (uint32_t)strlen(LOCAL_LABEL_FILE), NULL);


    // Derive key using nonce and local secret
    ret = create_key((uint8_t *)aes_128_local_key,
                     (uint8_t *)nonce, sizeof(nonce),
                     (uint8_t *)key);
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }


    // Encrypt for local storage (the resulting file header will be missing the iv and tag values)
    ret = copy_with_transform((uint8_t *)src, (uint8_t *)&k_curr_file,
                              (uint8_t *)key, XFORM_ENC,
                              (uint8_t *)tag_buffer, (uint8_t *)iv_buffer,
                              FILE_TOTAL_SIZE(src->contents_len), sizeof(file_header_t),
                              true);
                              
    if (ret != 0) goto cleanup;
    

    // Copy the first page from flash to ram
    uint8_t copy_buffer[FLASH_PAGE_SIZE] = {0};
    memcpy(copy_buffer, &k_curr_file, FLASH_PAGE_SIZE);

    // Store the iv and tag in the ram copy's file header
    memcpy(((file_header_t *)copy_buffer)->aes_gcm_iv, iv_buffer, AESGCM_IV_SIZE);
    memcpy(((file_header_t *)copy_buffer)->aes_gcm_tag, tag_buffer, AESGCM_TAG_SIZE);
    __asm__ volatile("" ::: "memory");

    // Write the modified first page back out to flash so that contents can be decrypted and verified later
    flash_simple_erase_page((uint32_t)&k_curr_file);
    flash_simple_write((uint32_t)&k_curr_file, copy_buffer, FLASH_PAGE_SIZE);
    
    // Write the file
    ret = write_file(slot, &k_curr_file, uuid);
    if (ret != 0) ret = WRITE_ERR;
    
    
cleanup:
    // Clean up
    memset(iv_buffer, 0, AESGCM_IV_SIZE);
    memset(tag_buffer, 0, AESGCM_TAG_SIZE);
    memset(key, 0, AESGCM_KEY_SIZE);
    __asm__ volatile("" ::: "memory");
    erase_scratchpad_pages((uint32_t)&k_curr_file, sizeof(file_t));
        
    return ret;
}


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
KERNEL_CODE int secure_read_file_meta(void *file_list_ptr)
{

    list_response_t *file_list = (list_response_t *)file_list_ptr;

    if (file_list_ptr == NULL)
        return INTERNAL_ERR;

    // No specific permissions checked here but active capability
    // must be equal to required capability
    SECURE_CAP_CHECK(CAP_READ_META);


    file_header_t header;
    file_list->n_files = 0;

    // Loop through all files on the system
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++)
    {

        // Read file metadata
        if (read_file_metadata(i, &header) < 0)
        {
            continue; // nothing in slot i
        }

        // If the file is in use, populate response
        if (header.in_use == FILE_IN_USE)
        {
            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = header.group_id;

            strncpy(file_list->metadata[file_list->n_files].name,
                    (char *)&header.name, MAX_NAME_SIZE);
            file_list->n_files++;
        }
    }

    return 0;
}


/** @brief Prepare a list of encrypted file metadata for remote user
 *
 * @param file_list_ptr: user buffer for encrypted file metadata
 *
 * @return 0 on success, negative number on error
 *
 * @note Runs for INTERROGATE command on responder side
 *
 * @security_req active_cap = CAP_SEND
 *
 */
KERNEL_CODE int secure_read_file_meta_for_transfer(void *file_list_ptr) {

    list_response_enc_t *file_list_transfer = (list_response_enc_t *)file_list_ptr;
    list_response_t k_file_list;
                
    int ret = -1;   
    
    if (file_list_ptr == NULL) return INTERNAL_ERR;
    
    uint8_t key[AESGCM_KEY_SIZE] = {0};

    // Active capability must be equal to required capability
    SECURE_CAP_CHECK(CAP_SEND);
    
    
    // Prepare metadata in internal buffer
    memset(&k_file_list, 0x0, sizeof(list_response_t));    
    k_file_list.n_files = 0;
    
    // Loop through all files on the system and create metadata array
    file_header_t header;

    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        // Read file metadata
        if (read_file_metadata(i, &header) < 0) {
            continue;  // no file in slot
        }
    
        // If the file is in use
        if (header.in_use == FILE_IN_USE) {	

            k_file_list.metadata[k_file_list.n_files].slot = i;
            k_file_list.metadata[k_file_list.n_files].group_id = header.group_id;
			
            strncpy(k_file_list.metadata[k_file_list.n_files].name, (char *)&header.name, MAX_NAME_SIZE);
            k_file_list.n_files++;
        }
            
    }

    //Get nonce A from passed file_list_ptr struct    
    uint8_t nonce_a[NONCE_SIZE] = {0};
    memcpy(nonce_a, file_list_transfer->nonce, NONCE_SIZE);
    
    //Create nonce B bytes   
    uint8_t nonce_b[NONCE_SIZE] = {0};
    ret = generate_random_bytes(nonce_b, NONCE_SIZE);
    
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }

    // Derive transfer key
    uint32_t kdf_len = (NONCE_SIZE + NONCE_SIZE + 16); 
    uint8_t kdf_nonce[NONCE_SIZE + NONCE_SIZE + 32] = {0};  

    // Create main KDF nonce nonce_A || nonce_B || label
    join_bytes((uint8_t *)kdf_nonce,
               (uint8_t *)nonce_a, (uint32_t)NONCE_SIZE,
               (uint8_t *)nonce_b, (uint32_t)NONCE_SIZE,
               (uint8_t *)TRANSFER_LABEL_FILE_M, (uint32_t)strlen(TRANSFER_LABEL_FILE_M),
               NULL);

    ret = create_key((uint8_t *)aes_128_shared_key,
                     (uint8_t *)kdf_nonce, kdf_len,
                     (uint8_t *)key);
                     
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }
    
    // Set data len and return nonce
    file_list_transfer->data_len = sizeof(uint32_t) + k_file_list.n_files * sizeof(file_metadata_t);
    memcpy(file_list_transfer->nonce, nonce_b, NONCE_SIZE);
        
    // Encrypt for transfer
    ret = copy_with_transform((uint8_t *)&k_file_list, (uint8_t *)&file_list_transfer->data,
                          (uint8_t *)key, XFORM_ENC,
                          (uint8_t *)&file_list_transfer->tag, (uint8_t *)&file_list_transfer->iv,
                          file_list_transfer->data_len, 0,
                          false);  


cleanup:    
    //Clean memory
    memset(key, 0, AESGCM_KEY_SIZE);
    memset(nonce_a, 0, NONCE_SIZE);
    memset(nonce_b, 0, NONCE_SIZE);
    memset(kdf_nonce, 0, kdf_len);
    memset(&k_file_list, 0, sizeof(list_response_t));
    __asm__ volatile("" ::: "memory");
        
	return ret;
    
}


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
KERNEL_CODE int secure_filter_file_meta(void *file_list_ptr, uint8_t *nonce)
{
    list_response_enc_t *file_list_transfer = (list_response_enc_t *)file_list_ptr;
    list_response_t k_file_list;

    uint8_t key[AESGCM_KEY_SIZE] = {0};
    uint8_t iv_buffer[AESGCM_IV_SIZE] = {0};
    uint8_t tag_buffer[AESGCM_TAG_SIZE] = {0};
    uint8_t local_nonce[NONCE_SIZE + NONCE_SIZE + 16] = {0};

    int ret = -1;

    if (file_list_ptr == NULL || nonce == NULL)
        return INTERNAL_ERR;

    SECURE_CAP_CHECK(CAP_FILTER_META);


    uint32_t kdf_len = (uint32_t)(NONCE_SIZE + NONCE_SIZE + 16);

    // Derive transfer key using nonce and shared secret
    join_bytes((uint8_t *)local_nonce,
               (uint8_t *)nonce, (uint32_t)NONCE_SIZE,
               (uint8_t *)file_list_transfer->nonce, (uint32_t)NONCE_SIZE,
               (uint8_t *)TRANSFER_LABEL_FILE_M, (uint32_t)strlen(TRANSFER_LABEL_FILE_M),
               NULL);

    ret = create_key((uint8_t *)aes_128_shared_key,
                     (uint8_t *)local_nonce, kdf_len,
                     (uint8_t *)key);

    if (ret != 0)
    {
        ret = INTERNAL_ERR;
        goto cleanup;
    }

    // Decrypt and check integrity
    memcpy(iv_buffer, file_list_transfer->iv, AESGCM_IV_SIZE);
    memcpy(tag_buffer, file_list_transfer->tag, AESGCM_TAG_SIZE);

    ret = copy_with_transform((uint8_t *)&file_list_transfer->data, (uint8_t *)&k_file_list,
                              (uint8_t *)key, XFORM_DEC,
                              (uint8_t *)tag_buffer, (uint8_t *)iv_buffer,
                              file_list_transfer->data_len, 0,
                              false);

    if (ret != 0) goto cleanup;
    

    // Check that file list isn't bigger than maximum size
    if (k_file_list.n_files > MAX_FILE_COUNT)
    {
        ret = INTERNAL_ERR;
        goto cleanup;
    }

    // Iterate through array of stored file metadata and determine which ones match permissions
    uint8_t out = 0;

    memset(&(file_list_transfer->data), 0, sizeof(list_response_t));
    
    for (uint8_t i = 0; i < k_file_list.n_files; i++)
    {
        ret = copy_meta_if_C_permitted(&(file_list_transfer->data.metadata[out]), &(k_file_list.metadata[i]));

        if (ret == 0) out++;        
    }

    file_list_transfer->data.n_files = out;
    ret = 0;


cleanup:
    // Clean memory
    memset(iv_buffer, 0, AESGCM_IV_SIZE);
    memset(tag_buffer, 0, AESGCM_TAG_SIZE);
    memset(key, 0, AESGCM_KEY_SIZE);
    memset(local_nonce, 0, sizeof(local_nonce));
    memset(&k_file_list, 0, sizeof(list_response_t));

    __asm__ volatile("" ::: "memory");

    return ret;
}


/** @brief Prepare an encrypted file for remote user
 *
 * @param request_ptr: user buffer with request details (in/out slots, remote permissions)
 * @param response_ptr: user buffer for encrypted file data
 *
 * @return 0 on success, negative number on error
 *
 * @note Runs for RECEIVE command on responder side
 *
 * @security_req active_cap = CAP_SEND and remote C permission on file
 *
*/
KERNEL_CODE int secure_read_file_for_transfer(void *request_ptr, void *response_ptr) {
    int ret = -1;
    receive_request_t *request = (receive_request_t *)request_ptr;
    receive_response_enc_t *response = (receive_response_enc_t *)response_ptr;        
    
    // Validate inputs
    if (request_ptr == NULL || response_ptr == NULL) return INTERNAL_ERR;
    slot_t slot = request->slot;       
    if (slot < 0 || slot > 7) return READ_ERR;

    // Calculate signature of the request permissions for verification
    uint8_t permissions_sig[HMAC_SIZE];
    Hmac hmac;
    wc_HmacSetKey(&hmac, WC_SHA256, (void *)aes_128_shared_key, AESGCM_KEY_SIZE);
    wc_HmacUpdate(&hmac, (void *)request->permissions, sizeof(group_permission_t) * MAX_PERMS);
    wc_HmacFinal(&hmac, (void *)permissions_sig);

    // Do the verification
    ret = ConstantCompare(permissions_sig, request->permissions_sig, HMAC_SIZE) ^ 0xA5A5A5A5;
    EQ_CHECK_BARRIER(ret&0xFFFFFFFFu, 0xA5A5A5A5u, HMAC_ERR);
    
    
    // Read the local file header, check against the verified permissions
    file_header_t f_header;
    if (read_file_metadata(slot, &f_header) < 0) {
        return READ_META_ERR;
    }
    SECURE_CAP_CHECK(CAP_SEND);
    SECURE_PERM_CHECK(f_header.group_id, C_PERMISSION, request->permissions);


    // Derive local_key for transfer
    uint8_t local_nonce[sizeof(file_header_t) + UUID_SIZE + 16] = {0};
    uint8_t key[AESGCM_KEY_SIZE] = {0};
    uint32_t headers_len = offsetof(file_t, aes_gcm_iv);

    join_bytes((uint8_t *)local_nonce, (uint8_t *)&f_header, (uint32_t)headers_len,
               (uint8_t *)FILE_ALLOCATION_TABLE[slot].uuid, (uint32_t)UUID_SIZE,
               (uint8_t *)LOCAL_LABEL_FILE, (uint32_t)strlen(LOCAL_LABEL_FILE),
               NULL);
               
               
    ret = create_key((uint8_t *)aes_128_local_key,
                     (uint8_t *)local_nonce, sizeof(local_nonce),
                     (uint8_t *)key);
                     
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }


    // Stage local key, uuid, and file header for transfer encrypt
    uint8_t p[AESGCM_KEY_SIZE + UUID_SIZE + sizeof(file_header_t)] = {0};
    join_bytes((uint8_t *)p, (uint8_t *)key, (uint32_t)AESGCM_KEY_SIZE,
               (uint8_t *)FILE_ALLOCATION_TABLE[slot].uuid, (uint32_t)UUID_SIZE,
               (uint8_t *)&f_header, (uint32_t)sizeof(file_header_t),
               NULL);

    // Derive temporary key for transfer encrypt (new nonce + request nonce + context)
    uint8_t temp_nonce[NONCE_SIZE * 2 + 16] = {0};

    uint8_t random_bytes[NONCE_SIZE]; // new nonce
    ret = generate_random_bytes(random_bytes, NONCE_SIZE);
    
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }

    // Combine with request nonce and derive transfer key
    join_bytes((uint8_t *)temp_nonce, (uint8_t *)random_bytes, (uint32_t)NONCE_SIZE,
               (uint8_t *)request->nonce, (uint32_t)NONCE_SIZE,
               (uint8_t *)TRANSFER_LABEL_FILE, (uint32_t)strlen(TRANSFER_LABEL_FILE),
               NULL); 
               
    ret = create_key((uint8_t *)aes_128_shared_key,
                     (uint8_t *)temp_nonce, sizeof(temp_nonce),
                     (uint8_t *)key);
                     
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    };

    // Perform transfer encrypt of key, uuid, file header
    uint8_t p_enc[AESGCM_KEY_SIZE + UUID_SIZE + sizeof(file_header_t)] = {0};
    uint8_t iv_buffer[AESGCM_IV_SIZE] = {0};
    uint8_t tag_buffer[AESGCM_TAG_SIZE] = {0};

    ret = copy_with_transform((uint8_t *)p, (uint8_t *)p_enc,
                              (uint8_t *)key, XFORM_ENC,
                              (uint8_t *)tag_buffer, (uint8_t *)iv_buffer,
                              sizeof(p), 0,
                              false);

    if (ret != 0) goto cleanup;


    // Read file into user buffer
    ret = erase_scratchpad_pages((uint32_t)&k_curr_file, sizeof(file_t));
    if (ret != 0)
    {
        ret = INTERNAL_ERR;
        goto cleanup;
    }
    
    ret = read_file(slot, (file_t *)&k_curr_file);
    if (ret != 0) 
    {
        ret = READ_ERR;
        goto cleanup;
    }
    
    memcpy((void *)(&(response->data.file_enc)), (void *)&k_curr_file, sizeof(file_t));
    
    // Set response fields
    memcpy((void *)(&(response->data.file_enc)), 
           (void *)(p_enc + AESGCM_KEY_SIZE + UUID_SIZE), 
           sizeof(file_header_t)); // encrypted file header
    
    memcpy(response->nonce, temp_nonce, NONCE_SIZE);
    memcpy(response->iv, iv_buffer, AESGCM_IV_SIZE);
    memcpy(response->tag, tag_buffer, AESGCM_TAG_SIZE);
    memcpy(response->key_enc, (uint8_t *)p_enc, AESGCM_KEY_SIZE);    
    response->data_len = FILE_TOTAL_SIZE(f_header.contents_len) + UUID_SIZE;
    memcpy(response->data.uuid, (void *)(p_enc + AESGCM_KEY_SIZE), UUID_SIZE);


cleanup:  
    // Clean up memory
    memset(local_nonce, 0, sizeof(local_nonce));
    memset(temp_nonce, 0, sizeof(temp_nonce));
    memset(random_bytes, 0, NONCE_SIZE);
    memset(iv_buffer, 0, AESGCM_IV_SIZE);
    memset(tag_buffer, 0, AESGCM_TAG_SIZE);
    memset(key, 0, AESGCM_KEY_SIZE);
    memset(p, 0, sizeof(p));
    memset(p_enc, 0, sizeof(p_enc));
    __asm__ volatile("" ::: "memory");
        
    erase_scratchpad_pages((uint32_t)&k_curr_file, sizeof(file_t));
    
    return ret;
}


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
KERNEL_CODE int secure_write_file_from_transfer(void *response_ptr, uint8_t *req_nonce, slot_t slot) {
    int ret = -1;
    receive_response_enc_t *response = (receive_response_enc_t *)response_ptr;

    // Validate inputs
    if (response_ptr == NULL || req_nonce == NULL) return INTERNAL_ERR;
    if (slot < 0 || slot > 7) return RECEIVE_ERR;
    
    // Derive temporary key for transfer decrypt (response nonce + request nonce + context)
    uint8_t temp_nonce[NONCE_SIZE * 2 + 16] = {0};
    uint8_t key[AESGCM_KEY_SIZE] = {0};
    
    join_bytes((uint8_t *)temp_nonce, (uint8_t *)response->nonce, (uint32_t)NONCE_SIZE,
               (uint8_t *)req_nonce, (uint32_t)NONCE_SIZE,
               (uint8_t *)TRANSFER_LABEL_FILE, (uint32_t)strlen(TRANSFER_LABEL_FILE),
               NULL);
               
    ret = create_key((uint8_t *)aes_128_shared_key,
                     (uint8_t *)temp_nonce, sizeof(temp_nonce),
                     (uint8_t *)key);
                     
    if (ret != 0) return INTERNAL_ERR;


    // Perform transfer decrypt to get sender's local key, uuid, and file header
    uint8_t p_enc[AESGCM_KEY_SIZE + UUID_SIZE + sizeof(file_header_t)] = {0};
    uint8_t p_dec[AESGCM_KEY_SIZE + UUID_SIZE + sizeof(file_header_t)] = {0};
    
    join_bytes((uint8_t *)p_enc, (uint8_t *)response->key_enc, (uint32_t)AESGCM_KEY_SIZE,
               (uint8_t *)response->data.uuid, (uint32_t)UUID_SIZE,
               (uint8_t *)(&(response->data.file_enc)), (uint32_t)sizeof(file_header_t),
               NULL);
               
    uint8_t iv_buffer[AESGCM_IV_SIZE] = {0};
    uint8_t tag_buffer[AESGCM_TAG_SIZE] = {0};
    memcpy(iv_buffer, response->iv, AESGCM_IV_SIZE);
    memcpy(tag_buffer, response->tag, AESGCM_TAG_SIZE);
    
    ret = copy_with_transform((uint8_t *)p_enc, (uint8_t *)p_dec, 
                              (uint8_t *)key, XFORM_DEC,
                              (uint8_t *)tag_buffer, (uint8_t *)iv_buffer,
                              sizeof(p_enc), 0,
                              false);
                              
    if (ret != 0) goto cleanup;


    // Stage key and decrypted file header before removing sender's local encryption
    memcpy(key, p_dec, AESGCM_KEY_SIZE);
    memcpy((void *)(&(response->data.file_enc)), p_dec + AESGCM_KEY_SIZE + UUID_SIZE, sizeof(file_header_t));   
    
    // Remove sender's local encryption
    ret = erase_scratchpad_pages((uint32_t)&k_curr_file, sizeof(file_t));
    if (ret != 0)
    {
        ret = INTERNAL_ERR;
        goto cleanup;
    }
    
    file_header_t *f_header = (file_header_t *)(&(response->data.file_enc));
    
    ret = copy_with_transform((uint8_t *)(&(response->data.file_enc)), 
                          (uint8_t *)&k_curr_file,
                          (uint8_t *)key, XFORM_DEC,
                          (uint8_t *)f_header->aes_gcm_tag, (uint8_t *)f_header->aes_gcm_iv,
                          response->data_len - UUID_SIZE, sizeof(file_header_t),
                          true);
     
    if (ret != 0) goto cleanup;
        
                                
    // Read the incoming file header, check permission
    file_t *file = (file_t *)&k_curr_file;
    SECURE_CAP_CHECK(CAP_RECEIVE);
    SECURE_PERM_CHECK(file->group_id, C_PERMISSION, global_permissions);


    // Derive local_key for encryption
    uint32_t headers_len = offsetof(file_t, aes_gcm_iv);
    uint8_t local_nonce[sizeof(file_header_t) + UUID_SIZE + 16] = {0};
    
    join_bytes((uint8_t *)local_nonce, (uint8_t *)file, (uint32_t)headers_len,
               (uint8_t *)(p_dec + AESGCM_KEY_SIZE), (uint32_t)UUID_SIZE,
               (uint8_t *)LOCAL_LABEL_FILE, (uint32_t)strlen(LOCAL_LABEL_FILE),
               NULL);
               
    ret = create_key((uint8_t *)aes_128_local_key,
                     (uint8_t *)local_nonce, sizeof(local_nonce),
                     (uint8_t *)key);
                     
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }


    // Clear enough memory for this file at k_curr_file_b
    ret = erase_scratchpad_pages((uint32_t)&k_curr_file_b, sizeof(file_t));
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }

    // Perform local encrypt
    ret = copy_with_transform((uint8_t *)file, (uint8_t *)&k_curr_file_b,
                              (uint8_t *)key, XFORM_ENC,
                              (uint8_t *)tag_buffer, (uint8_t *)iv_buffer,
                              response->data_len - UUID_SIZE, sizeof(file_header_t),
                              true);
    if (ret != 0) goto cleanup;


    // Delete plaintext
    ret = erase_scratchpad_pages((uint32_t)&k_curr_file, sizeof(file_t));
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }

    // Copy the first page of ciphertext from flash to ram
    uint8_t copy_buffer[FLASH_PAGE_SIZE] = {0};
    memcpy(copy_buffer, &k_curr_file_b, FLASH_PAGE_SIZE);

    // Store the iv and tag in the ram copy's file header
    memcpy(((file_header_t *)copy_buffer)->aes_gcm_iv, iv_buffer, AESGCM_IV_SIZE);
    memcpy(((file_header_t *)copy_buffer)->aes_gcm_tag, tag_buffer, AESGCM_TAG_SIZE);
    __asm__ volatile("" ::: "memory");

    // Write the modified first page back out to flash so that contents can be decrypted and verified later
    ret = flash_simple_erase_page((uint32_t)&k_curr_file_b);
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }
    ret = flash_simple_write((uint32_t)&k_curr_file_b, copy_buffer, FLASH_PAGE_SIZE);
    if (ret != 0) {
        ret = INTERNAL_ERR;
        goto cleanup;
    }

    // Write the file
    ret = write_file(slot, &k_curr_file_b, p_dec + AESGCM_KEY_SIZE);
    if (ret != 0) {
        ret = WRITE_ERR;
        goto cleanup;
    }


cleanup:
    // Clean up memory
    erase_scratchpad_pages((uint32_t)&k_curr_file, sizeof(file_t));
    erase_scratchpad_pages((uint32_t)&k_curr_file_b, sizeof(file_t));
    memset(local_nonce, 0, sizeof(local_nonce));
    memset(temp_nonce, 0, sizeof(temp_nonce));
    memset(iv_buffer, 0, AESGCM_IV_SIZE);
    memset(tag_buffer, 0, AESGCM_TAG_SIZE);
    memset(key, 0, AESGCM_KEY_SIZE);
    memset(p_dec, 0, sizeof(p_dec));
    __asm__ volatile("" ::: "memory");

    
    return ret;
}
