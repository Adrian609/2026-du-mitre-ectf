/**
 * @file    HSM.c
 * @author  Samuel Meyers
 * @brief   Boot code and main function for the HSM
 * @date    2026
 *
 * This source file is part of an example system for MITRE's 2026
 * Embedded CTF (eCTF). This code is being provided only for
 * educational purposes for the 2026 MITRE eCTF competition, and may not
 * meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

#include "simple_flash.h"
#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"
#include "syscalls.h"
#include "kernel.h"


/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

unsigned char uart_buf[MAX_MSG_SIZE];

int start_user_loop(void);


/** @brief Starts kernel which after init starts user loop
*/
KERNEL_CODE int main(void) {
	start_kernel();
	return 0;
}

/** @brief The command processing loop
 *
 * @note This code runs in unprivileged mode
 *
*/
int start_user_loop(void) {
    char output_buf[128] = {0};
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;


    // Process commands forever
    while (1) {        

        svc_led(true);

		print_debug("Ready\n"); 

        pkt_len = sizeof(uart_buf); // request must fit in uart_buf
        memset(uart_buf, 0x00, sizeof(uart_buf));
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);

        if (result != MSG_OK) {

			svc_led(false);

            switch (result)
            {
            case MSG_BAD_PTR:
                print_error("Bad cmd pointer\n");
                break;
            case MSG_NO_ACK:
                print_error("Failed to receive ACK from host\n");
                break;
            case MSG_BAD_LEN:
                print_error("Received bad length\n");
                break;
            default:
                print_error("Failed to receive cmd from host\n");
                break;
            }
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            svc_led(false);		
            list(pkt_len, uart_buf);
            break;

        // Handle read command
        case READ_MSG:
            svc_led(false);
            read(pkt_len, uart_buf);
            break;

        // Handle write command
        case WRITE_MSG:
            svc_led(false);
            write(pkt_len, uart_buf);
            break;

        // Handle receive command
        case RECEIVE_MSG:
            svc_led(false);
            receive(pkt_len, uart_buf);
            break;

        // Handle interrogate command
        case INTERROGATE_MSG:
            svc_led(false);
            interrogate(pkt_len, uart_buf);
            break;

        // Handle listen command
        case LISTEN_MSG:
            svc_led(false);
            listen(pkt_len, uart_buf);
            break;

        // Handle bad command
        default:
            svc_led(false);
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }

    }
}


