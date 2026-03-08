/**
 * @file kernel.c
 * @author University of Denver team
 * @brief Corext M0+ hardware setup for eCTF
 * @date 2026
 *
 */

#include <stdint.h>

#include "kernel.h"
#include "syscalls.h"
#include "filesystem.h"
#include "host_messaging.h"
#include "ti_msp_dl_config.h"
#include "security.h"



/** @brief Prints the current processor configuration
*/
void print_current_mode(void) {
	uint32_t ipsr;
	__asm volatile ("mrs %0, ipsr" : "=r"(ipsr));

	uint32_t control;
	__asm volatile ("mrs %0, control" : "=r"(control));

	uint32_t stack;
	__asm volatile ("mov %0, sp" : "=r"(stack));

	uint32_t setting = control & 0x1;

	char str[64];

	sprintf(str, "Mode: %s | %s | Current SP: 0x%08X\n",
               (ipsr != 0) ? "Handler" : "Thread",
               (setting == 0) ? "Privileged" : "Unprivileged",
               (uint32_t)stack);

	print_debug(str);
	
}



/** @brief Initializes hardware and switches to user mode
*/
KERNEL_CODE __attribute__((noinline, noreturn)) void start_kernel(void) {
    // Initialize the device
    init();

	// Set up and enable MPU regions
	setup_mpu_layout();

    // Boot delay to reach around 1 second
    uint32_t cycles_since_reset = 0xFFFFFF - SysTick->VAL;    
    delay_cycles(DELAY_1_SEC - cycles_since_reset - 3*DELAY_1_MSEC); // 3ms slack
    
	// Switch to user mode and run user loop
	__asm volatile ("svc %0\n" : : "i" (SYS_START_USER_LOOP));

	__builtin_unreachable();

}



/** @brief Initializes peripherals for system boot.
*/
KERNEL_CODE void init() {
    // Initialize all of the hardware components
	#if ON_BOARD
    SYSCFG_DL_init();
	#endif

    // Initialize file system
    init_fs();
    
    // Initialize security related objects
    init_security();
}


/** @brief Memory Protection Regions
 *
 * Default   0x0 - 0x3FFFF  Privileged Only
 *
 * Region 0: 0x0 - 0xFFFF (Kernel code and global data) Priv RX
 *           Bootloader: 0x0 - 0x5FFF (24KB)
 *           Kernel code: 0x6000 - 0xDFFF (32KB)
 *           Overriden by region 1: 0xE000 - 0xFFFF 
 *
 * Region 1: 0xE000 - 0xFFFF (8KB Secrets and other RO consts) Priv RO
 *
 * Region 2: 0x10000 - 0x3FFFF (Files + FAT + Kernel stage) Priv RW
 *           Files: 0x10000 - 0x21FFF (72KB = 8*9KB)
 *           Unused: 0x22000 - 0x23FFF
 *           Overriden by region 3: 0x24000 - 0x37FFF
 *           Unused: 0x38000 - 0x39FFF
 *           FAT: 0x3A000 - 0x3A3FF (1KB)
 *           Kernel stage: 0x3A400 - 0x3FFFF (23KB)
 *
 * Region 3: 0x24000 - 0x37FFF (80KB User code and global data) User RX
 * Region 4: 0x20200000 - 0x20205FFF (24KB User RAM) User RW
 * Region 5: 0x20206000 - 0x20207FFF (8KB Kernel RAM) Priv RW
 * Region 6: 0x40108000 - 0x4010BFFF (UART 0&1) User RW
 *
 * @note MPU RASR structure (32 bits)
 * https://arm-software.github.io/CMSIS_5/Core/html/structMPU__Type.html
 *
 * 31:29    Reserved (0)
 * 28       XN - block code execution? 1 yes, 0 no
 * 27       Reserved (make 0)
 * 26:24    AP - access permissions
 *          000    no access
 *          001    Priv RW
 *          010    Priv RW, User RO
 *          011    Priv RW, User RW (full access)
 *          101    Priv RO
 *          110    Priv RO, User RO
 * 23:22    Reserved (make 0)
 * 21:19    TEX - type extension
 * 18:16    SCB - shareable, cachecable, bufferable
 * 15:8     SRD - sub-region disable; 8 bits to mask 1/8th slices of the region.
 * 7:6      Reserved (make 0)
 * 5:1      SIZE - region size; calculated as 2^(SIZE+1).
 * 0        ENABLE - region enable; must be 1 for the region to exist.
*/
KERNEL_CODE void setup_mpu_layout(void) {

    MPU->CTRL = 0; // disable MPU during configuration

    // --------KERNEL-----------
    /* Region 0: Kernel code, handlers, IVT, etc. (0x0000 - 0xDFFF)
       Permission: Priv RX
       Size: 64KB (8KB sub-regions)
       SRD 0x80 (10000000b) disables the 8th slice (0xE000-0xFFFF)
    */
    MPU->RNR  = 0; 
    MPU->RBAR = 0x00000000;
    MPU->RASR = (0b00000101 << 24) | (0x80 << 8) | (0x0F << 1) | 1;


    /* Region 1: Secrets (0xE000 - 0xFFFF)
	   Permission: Priv RO
       Size: 8KB; higher index overrides Region 0
    */
    MPU->RNR  = 1; 
    MPU->RBAR = 0x0000E000;
    MPU->RASR = (0b00010101 << 24) | (0x00 << 8) | (0x0C << 1) | 1;

    /* Region 2: Files/FAT/Kernel-Stage (0x10000 - 0x3FFFF)
	   Permission: Priv RW
       Size: 256KB (32KB sub-regions)
       SRD 0x03 (00000011b) disables first two slices (0x0-0xFFFF)
    */
    MPU->RNR  = 2; 
    MPU->RBAR = 0x00000000;
    MPU->RASR = (0b00010001 << 24) | (0x03 << 8) | (0x11 << 1) | 1;

	// --------USER-----------
    /* Region 3: User App (0x24000 - 0x37FFF)
	   Permission: User RX
       Size: 128KB (16KB sub-regions)
       SRD 0xC1 (11000001b) disables first slice 0x20000-0x23FFF and 
         7-8th slices 0x38000-0x3FFFF; higher index overrides Region 2
    */
    MPU->RNR  = 3; 
    MPU->RBAR = 0x00020000;
    MPU->RASR = (0b00000110 << 24) | (0xC1 << 8) | (0x10 << 1) | 1;

	// --------SRAM-----------
    /* Region 4: User RAM (0x20200000 - 0x20205FFF)
	   Permission: User RW
       Size: 32KB
	   SRD 0xC0 (11000000b) disables 0x20206000-0x20207FFF
    */
    MPU->RNR  = 4; 
	MPU->RBAR = 0x20200000;
	MPU->RASR = (0b00010011 << 24) | (0xC0 << 8) | (0x0E << 1) | 1;
    
    /* Region 5: Kernel RAM (0x20206000 - 0x20207FFF)
	   Permission: Priv RW
       Size: 8KB
    */
	MPU->RNR  = 5; 
	MPU->RBAR = 0x20206000;
	MPU->RASR = (0b00010001 << 24) | (0x00 << 8) | (0x0C << 1) | 1;

	// --------USER Accessible Peripheral-----------
    /* Region 6: UARTs 0&1 (0x40108000 - 0x4010BFFF)
	   Permission: User RW
       Size: 16KB
    */
    MPU->RNR  = 6; 
    MPU->RBAR = 0x40108000;
    MPU->RASR = (0b00010011 << 24) | (0x00 << 8) | (0x0D << 1) | 1;

	// Enable MPU with unspecified regions as privileged only
	MPU->CTRL = MPU_CTRL_ENABLE_Msk | MPU_CTRL_PRIVDEFENA_Msk;

    __DSB(); __ISB();

}


