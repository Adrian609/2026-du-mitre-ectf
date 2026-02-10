#ifndef __SECRETS_H__
#define __SECRETS_H__

#include "security.h"

#define HSM_PIN "7f08e505aa901ac78ce3db11ce38dbdea15cef7481f64d0113823d42a5bd3388"
#define AES_256_SHARED "beb2b9fc2818cbe16ce793c732a0c5f9d438a692ace9a4aaa8e95f4701759afb"
#define AES_256_LOCAL "b61db1815eb3f74e84a7ae88104fd755948d466929c67610094151d767a3cb62"

const static group_permission_t global_permissions[MAX_PERMS] = {
	{0x1234, true, true, true},
};

#endif  // __SECRETS_H__
