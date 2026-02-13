/**
 * @file security.c
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
//#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/misc.h"  //constant time function import

#include <strings.h>
#include "security.h"
#include "secrets.h"
#include "host_messaging.h"
#include "kernel.h"
#include "capabilities.h"


const uint8_t CMD_TO_CAP[] = {
    [LIST_MSG] = CAP_FILTER_META,
    [READ_MSG] = CAP_READ,
    [WRITE_MSG] = CAP_WRITE,
    [RECEIVE_MSG] = CAP_RECEIVE,
    [INTERROGATE_MSG] = CAP_FILTER_META,

};

KERNEL_CODE bool check_pin(msg_type_t cmd, unsigned char *pin) {
    print_debug("Checking PIN\n");
    byte salted_pin[HSM_SALT + PIN_LENGTH];
    byte computed_hash[HSM_HASH_LEN];

    memcpy(&salted_pin[0], pin_hash.salt, HSM_SALT);
    memcpy(&salted_pin[HSM_SALT], pin, PIN_LENGTH);
    int hc = wc_Sha256Hash((const byte*)salted_pin, (word32)(HSM_SALT + PIN_LENGTH), computed_hash);
    if (hc != 0) {
        print_debug("Error computing hash\n");
        return false;
    }
    /* Compare derived key to expected (from secrets.h) */
    int ret = ConstantCompare(computed_hash, pin_hash.hash, HSM_HASH_LEN) ^ 0xA5A5A5A5u;
    //EQ_CHECK_BARRIER(ret, 0, perm_error);

    //lookup capability based on command
    uint8_t active_cap = CMD_TO_CAP[cmd];

   return active_cap != 0;
}

KERNEL_CODE bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    char output_buf[128] = {0};

    sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm, group_id);
    print_debug(output_buf);

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    return true;
}
