/**
 * @file systemcalls.c
 * @author University of Denver team
 * @brief eCTF supported system calls
 * @date 2026
 *
 */

#include <stdint.h>

#include "syscalls.h"
#include "kernel.h"
#include "host_messaging.h"



/** @brief Decide which system call has been invoked and process return
 *
 *  @param stacked_args points to stack top with stack frame
 *         stacked_args[0] = r0, [1] = r1, [2] = r2, [3] = r3
 *         access system call arguments accordingly and modify to 
 *         return values
 *
 *  @param svc_id system call identifier
 *
*/
KERNEL_CODE void svc_handler_logic(uint32_t *stacked_args, uint8_t svc_id) 
{
	print_current_mode();

    if (svc_id == SYS_PRINT) { // TODO: remove this if block later
        char *msg = (char *)stacked_args[0];
        stacked_args[0] = syscall_svc_print(msg); // return value in r0
    }
	else if (svc_id == SYS_START_USER_LOOP) {
		syscall_start_user_loop();
		// unreachable here; never returns
	}
}

/** @brief Print a message
 *
 *  @param msg pointer to message to print
 *
 *  @return just default 1
 *  TODO: remove later
*/
KERNEL_CODE int syscall_svc_print(char *msg) {
	print_debug(msg);

	return(1);	
}

/** @brief Start the start_user_loop function in unprivileged mode
 *
 *  @note This function does not return; it sets up a dummy
 *        stack frame on PSP, changes CONTROL register, and 
 *        triggers an exception return to switch to unprivileged
 *        thread mode (uses PSP thereafter)
 *
*/
extern int start_user_loop(void); // in HSM.c
extern unsigned long __STACK_END; // linker generated kernel stack end

KERNEL_CODE __attribute__((noinline)) void syscall_start_user_loop(void) {
	uint32_t control;
	__asm volatile ("mrs %0, control" : "=r"(control)); // get the CONTROL register
	
	if (control & 0x1) return; // do nothing if called from unprivileged

	print_debug("Starting user loop\n");

	// Create dummy stack frame using unprivileged stack area
	uint32_t *frame = (uint32_t *) END_USER_SRAM + 1 - 32; // frame is now top of a stack frame
	frame[0]=0; frame[1]=0; frame[2]=0; frame[3]=0; // r0, r1, r2, r3
    frame[4]=0; frame[5]=0; // r12, lr
    frame[6]=(uint32_t)start_user_loop | 1; // return address; the 1 ensures thumb address
    frame[7]=0x01000000u; // xPSR (setting thumb bit)

	 // Set PSP to the synthetic frame
    __asm volatile ("msr psp, %0\n" : : "r"(frame) : "memory");
    __asm volatile ("isb\n" ::: "memory");

	// Set Thread mode to unprivileged + PSP (takes effect on exception return)
    __asm volatile (
        "movs r0, #3        \n"
        "msr control, r0    \n"
        "isb                \n"
        :
        :
        : "r0", "memory"
    );

	// Reset the MSP
	__asm volatile(
        "msr msp, %0 \n"
        "isb         \n"
        :
        : "r" (&__STACK_END)
        : "memory"
    );

	__asm volatile ("msr msp, r0\n");               

	// Exception return to thread mode using PSP
    __asm volatile(
        "ldr r0, =0xFFFFFFFD \n"
        "mov lr, r0          \n"
        "bx  lr              \n"
        :
        :
        : "r0", "memory"
    );

	__builtin_unreachable();
}

////////////////////////////////////////////////////////////////
// The following are SVC call interfaces callable by user code


/** @brief Printing from the kernel side
 *         Just a test if it works
 *
 *  @param msg message to print
 *
 *  @return 0 on success else 1
 *  TODO: remove later
*/
int svc_print(char *msg) {
	int ret;

    // We pass the pointer in r0
    __asm volatile ("mov r0, %0\n" : : "r" (msg) : "r0");
    __asm volatile ("svc %0\n" : : "i" (SYS_PRINT));


	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return(ret);

}


