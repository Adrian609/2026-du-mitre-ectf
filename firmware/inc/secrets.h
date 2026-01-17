#ifndef __SECRETS_H__
#define __SECRETS_H__

#include "security.h"

#define HSM_PIN "abc123"

const static group_permission_t global_permissions[MAX_PERMS] = {
	{0x1, true, true, true},
	{0x2, true, true, true},
	{0x3, true, true, true},
	{0x1111, true, true, true},
};

#endif  // __SECRETS_H__
