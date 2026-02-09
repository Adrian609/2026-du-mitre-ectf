/**
 * @file systemcalls.h
 * @author University of Denver team
 * @brief eCTF supported system calls
 * @date 2026
 *
 */

#ifndef __SYSTEMCALLS__
#define __SYSTEMCALLS__

#include "kernel.h"
#include <stdint.h>

// SVC call IDs
#define SYS_PRINT		       0x01
#define SYS_START_USER_LOOP    0xFF

// Function prototypes

KERNEL_CODE void svc_handler_logic(uint32_t *stacked_args, uint8_t svc_id);
KERNEL_CODE int syscall_svc_print(char *msg);
KERNEL_CODE __attribute__((noinline)) void syscall_start_user_loop(void);

int svc_print(char *msg);

#endif