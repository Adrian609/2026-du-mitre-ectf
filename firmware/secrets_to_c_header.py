"""
Author: Samuel Meyers
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import os
import json
import argparse
import hashlib
import time
from dataclasses import dataclass
from secrets import token_hex, randbelow


@dataclass
class Permission:
    """Represents a permission for one group
    """
    group_id: int=None
    read: bool=False
    write: bool=False
    receive: bool=False

    @classmethod
    def deserialize(cls, perms: str):
        """Create a Permission object from a string

        :param perm: A string representing a permission. The permission shall be a pair
            of group ID and permissions separated by an equal sign (e.g.,
            "<group_id>=<permission>"). The group ID shall be a 16-bit hexadecimal
            number padded with 0s to be a total of 4 characters with no preceding '0x'
            (e.g., 4b1d). The permission shall be a 3-character string where present
            permissions are represented by their opcode and absent permissions are
            represented by a '-' (e.g., "RWC", "RW-", "--C").
        """
        group_id, perm_string = perms.split('=')

        perm_obj = cls(
            int(group_id, 16),
            read = perm_string[0] == 'R',
            write = perm_string[1] == 'W',
            receive = perm_string[2] == 'C',
        )
        return perm_obj

    def serialize(self):
        ret = f'{self.group_id:04x}='
        for perm, shorthand in {'read': 'R', 'write': 'W', 'receive': 'C'}.items():
            ret += shorthand if getattr(self, perm) else "-"
        return ret

class PermissionList(list):
    """Represents a set of permissions that an HSM can be built with.
    """
    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        """Create a list of permission objects from a string
        representation

        :param perm: A string representing the permission set. The string shall be a
            colon-separated list of permissions (e.g., "<perm1>:<perm2>:<perm3>").

        :returns: An instance of `PermissionList`
        """
        ret = cls()
        permissions_strings = perms.split(":")
        for entry in permissions_strings:
            perm_obj = Permission.deserialize(entry)
            ret.append(perm_obj)
        return ret

    def serialize(self):
        return ':'.join(perm.serialize() for perm in self)


def secrets_to_c_header(
    permissions: PermissionList, path: str, hsm_pin: str, secrets: bytes
):
    # TODO: increase until execution time on the HSM begins to approach the list command timing requirement of 500ms
    number_of_iterations = 1000

    # Parse shared AES key
    aes_128_shared = json.loads(secrets.decode())['aes_128_shared']

    # Generate local AES key
    aes_128_local = token_hex(16)

    # Compute PIN hash (adding [2:] is to strip the leading 0x)

    #   iterations suffix
    num_iterations_hex = hex(number_of_iterations)[2:].rjust(8, '0') # pad to 4 bytes
    # print(num_iterations_hex)

    #   number of extra salt bytes to be added to starting point of 16 salt bytes
    num_extra_salt_bytes = randbelow(16)
    num_extra_salt_bytes_hex = hex(num_extra_salt_bytes)[2:] # no need to pad, always 4 bits
    # print(num_extra_salt_bytes_hex) 

    #   the extra salt bytes
    salt_bytes_hex = token_hex(16 + num_extra_salt_bytes) 
    # print(salt_bytes_hex)
    salt_bytes = bytes.fromhex(salt_bytes_hex)

    #   the hash output itself
    pin_hash_output_hex = hashlib.pbkdf2_hmac("sha256", hsm_pin.encode(), salt_bytes, number_of_iterations).hex()
    # print(pin_hash_output_hex)

    #   concat all values for final result
    pin_hash = pin_hash_output_hex + salt_bytes_hex + num_extra_salt_bytes_hex + num_iterations_hex
    #          |                     |                |                          |
    #           -> 32B                -> 16-31B        -> 4 bits                  -> 4B

            # now, to check a pin, do the C equivalent of the following line
            # hashlib.pbkdf2_hmac("sha256", hsm_pin.encode(), bytes.fromhex(pin_hash[-41 - int(pin_hash[-9],16)*2 : -9]), int(pin_hash[-8:], 16)).hex()
            #                                                 |                            |                              |
            #                                                  ->salt bytes                 ->salt len                     ->num iterations        

        # print(pin_hash)

        # output_check = hashlib.pbkdf2_hmac("sha256", hsm_pin.encode(), bytes.fromhex(pin_hash[-41 - int(pin_hash[-9],16)*2 : -9]), int(pin_hash[-8:], 16)).hex()
        # print(output_check)

    # write out to file
    with open(os.path.join(path, "secrets.h"), 'w') as f:
        f.write("#ifndef __SECRETS_H__\n")
        f.write("#define __SECRETS_H__\n\n")
        f.write('#include "security.h"\n\n')
        f.write(f'#define HSM_PIN 0x{pin_hash}\n')
        f.write(f'#define AES_128_SHARED 0x{aes_128_shared}\n')
        f.write(f'#define AES_128_LOCAL 0x{aes_128_local}\n\n')
        f.write("const static group_permission_t global_permissions[MAX_PERMS] = {\n")
        for i, perm in enumerate(permissions):
            f.write(
                (f"\t{{{hex(perm.group_id)}, {str(perm.read).lower()}, "
                 f"{str(perm.write).lower()}, {str(perm.receive).lower()}}},\n")
            )
        f.write("};\n")
        f.write("\n#endif  // __SECRETS_H__\n")

if __name__ == '__main__':
    def parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument("secrets", type=argparse.FileType("rb"), help="Path to secrets file")
        parser.add_argument("hsm_pin", type=str, help="User PIN for the HSM")
        parser.add_argument("permissions", type=str, help="List of colon-separated permissions. E.g., \"1234=R--:4321=RWC\"")

        return parser.parse_args()

    args = parse_args()
    perms = PermissionList.deserialize(args.permissions)
    secrets_to_c_header(perms, './inc/', args.hsm_pin, args.secrets.read())
