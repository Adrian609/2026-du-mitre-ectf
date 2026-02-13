/**
 * @file security.h
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>
#include "wolfssl/wolfcrypt/types.h"  // byte, word32
#include "host_messaging.h"

#define MAX_PERMS 8
#define PIN_LENGTH 6
#define HSM_HASH_LEN 32  //Num of bytes of pin hash
#define HSM_SALT 16 

typedef enum {
    PERM_READ = 'R',
    PERM_WRITE = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

typedef struct {
    uint16_t group_id;
    bool read;
    bool write;
    bool receive;
} group_permission_t;

typedef struct {
    uint8_t hash[HSM_HASH_LEN];
    uint8_t salt[HSM_SALT];
} pin_hash_t;


int ConstantCompare(const byte* a, const byte* b, size_t len);
int wc_Sha256Hash(const byte* data, word32 len, byte* hash);

/** @brief Validate a pin against the HSM's pin
 *
 *  @param pin Requested pin to validate.
 *
 *  @return True if the pin is valid. False if not.
*/
bool check_pin(msg_type_t cmd, unsigned char *pin);

/** @brief Ensure the HSM has the requested permission
 *
 *  @param group_id Group ID.
 *  @param perm Permission type.
 *
 *  @return True if the HSM has the correct permission. False if not.
*/
bool validate_permission(uint16_t group_id, permission_enum_t perm);

#endif  // __SECURITY_H__
