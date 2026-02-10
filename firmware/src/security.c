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
#include "security.h"
#include "secrets.h"
#include "host_messaging.h"
#define SALT_LEN 1
#define ITERATIONS 1000
#define DK_LEN 32

/* Constant-time compare: returns 1 if equal, 0 otherwise */
static int consttime_memcomp(const byte* a, const byte* b, int n)
{
    byte diff = 0;
    for (int i = 0; i < n; i++) {
        diff |= (byte)(a[i] ^ b[i]);
    }
    return diff == 0;
}


bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");

    if (pin == NULL) return false;


    byte hash_buf[DK_LEN];

    //TODO: Figure out how we will implement salt generation
    static const byte pin_salt[SALT_LEN] = { 0x00 };

    //wolfssl pbkdf2 function call passing in the hash buffer, casting and passing in the pin, pin length, the salt, salt length, iteration amount, key length, hash function
    int ret = wc_PBKDF2(
        hash_buf,                /* output */
        (const byte*)pin,        /* password bytes (PIN) */
        PIN_LENGTH,              /* password length in bytes */
        pin_salt,                /* salt */
        SALT_LEN,                /* salt length */
        ITERATIONS,              /* iteration count */
        DK_LEN,                  /* derived key length */
        WC_SHA256                /* HMAC hash */
    );

    if (ret != 0) {
        /* PBKDF2 failed */
        return false;
    }

    /* Compare derived key to expected (from secrets.h) */
    if (!consttime_memcomp(hash_buf, (const byte*)HSM_PIN, DK_LEN)) {
        return false;
    }
    return true;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    char output_buf[128] = {0};

    sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm, group_id);
    print_debug(output_buf);

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    return true;
}
