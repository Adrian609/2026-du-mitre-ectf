/**
 * @file kernel.h
 * @author University of Denver team
 * @brief Corext M0+ hardware setup for eCTF
 * @date 2026
 *
 */

#ifndef __KERNEL__
#define __KERNEL__

/**
 * Tag for kernel initialized globals (goes to RAM)
 * E.g. KERNEL_DATA int x = 5;
 */
#define KERNEL_DATA   __attribute__((section(".kernel_data"), retain))

/**
 * Tag for kernel uninitialized globals (goes to RAM)
 * E.g. KERNEL_BSS int x;
 */
#define KERNEL_BSS    __attribute__((section(".kernel_bss"), retain))

/** 
 * Tag for kernel constants (read-only; goes to flash)
 * E.g. KERNEL_CONST const uint8_t pin_hash[] = 
 *        "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
 */
#define KERNEL_CONST __attribute__((section(".kernel_const"), retain))

/** 
 * Tag for kernel variables in staging area of flash (read-write)
 * E.g. KERNEL_STAGE uint8_t decrypt_buff[9*1024];
 *
 * NOTE: since these are stored in flash, they can be read through usual C
 *  but need special functions to write
 */ 

#define KERNEL_STAGE  __attribute__((section(".kernel_stage"), retain))

/** 
 * Tag for kernel functions
 * E.g. KERNEL_CODE void func(int x) {...}
 * 
 * NOTE: internal funtion variable do not have to be tagged since
 * they will go to kernel stack
*/
#define KERNEL_CODE __attribute__((section(".kernel_code"), retain))


// User accessible areas (useful in checking bounds)
#define START_USER_SRAM   0x20200000
#define END_USER_SRAM     0x20205FFF
#define START_KERNEL_SRAM 0x20206000
#define END_KERNEL_SRAM   0x20207FFF
#define START_USER_FLASH  0x00024000
#define END_USER_FLASH    0x00037FFF
   

// Function prototypes
void print_current_mode(void);
void test_mpu_protection(void);

KERNEL_CODE __attribute__((noinline, noreturn)) void start_kernel(void);
KERNEL_CODE void init();
KERNEL_CODE void setup_mpu_layout(void);



#endif
