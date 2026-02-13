/**
 * @file capabilities.h
 * @author University of Denver team
 * @brief header file for capabilities management in the kernel
 * @date 2026
 *
 */
#define CAP_READ 0x0F
#define CAP_READ_META 0x33
#define CAP_SEND 0x3C
#define CAP_WRITE 0x55
#define CAP_RECEIVE 0x5A
#define CAP_FILTER_META 0x66


//void svc_check_pin(pin_input, out_capability_token);