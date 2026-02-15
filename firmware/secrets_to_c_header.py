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


def macro(enabled: bool, name: str) -> str:
    return name if enabled else "X_PERMISSION"
    
def secrets_to_c_header(
    permissions: PermissionList, path: str, hsm_pin: str, secrets: bytes
):

    # Parse shared AES key
    aes_128_shared = json.loads(secrets.decode())['aes_128_shared']
    aes_128_shared_byte_list = ", ".join(f"0x{b:02x}" for b in bytes.fromhex(aes_128_shared))
    
    # Generate local AES key
    aes_128_local = token_hex(16)
    aes_128_local_byte_list = ", ".join(f"0x{b:02x}" for b in bytes.fromhex(aes_128_local))
    
    # Generate PRNG secret
    prng_secret = token_hex(32)
    prng_secret_byte_list = ", ".join(f"0x{b:02x}" for b in bytes.fromhex(prng_secret))
    
    # Compute PIN hash

    #   salt bytes
    salt_bytes_hex = token_hex(16) 
    salt_bytes_hex_bytes = [ "0x" + salt_bytes_hex[i:i+2] for i in range(0, len(salt_bytes_hex), 2) ]

    #   the hash output itself
    pin_hash_output_hex = hashlib.sha256(bytes.fromhex(salt_bytes_hex) + hsm_pin.encode()).hexdigest()
    pin_hash_output_hex_bytes = [ "0x" + pin_hash_output_hex[i:i+2] for i in range(0, len(pin_hash_output_hex), 2) ]

    # write out to file
    with open(os.path.join(path, "secrets.h"), 'w') as f:
        f.write("#ifndef __SECRETS_H__\n")
        f.write("#define __SECRETS_H__\n\n")
        f.write('#include "security.h"\n')
        f.write('#include "kernel.h"\n\n')
        f.write("extern const volatile uint8_t aes_128_shared_key[];\n")
        f.write("extern const volatile uint8_t aes_128_local_key[];\n")
        f.write("extern const volatile uint8_t prng_secret[];\n")
        f.write("extern const volatile group_permission_t global_permissions[MAX_PERMS];\n")
        f.write("extern const volatile pin_hash_t pin_hash;\n\n")
        f.write("#ifdef SECRETS_DEFINE\n\n")
        f.write("KERNEL_CONST uint8_t aes_128_shared_key[] = {\n")
        f.write(f"\t{aes_128_shared_byte_list}}};\n\n")
        f.write("KERNEL_CONST uint8_t aes_128_local_key[] = {\n")
        f.write(f"\t{aes_128_local_byte_list}}};\n\n")
        f.write("KERNEL_CONST uint8_t prng_secret[] = {\n")
        f.write(f"\t{prng_secret_byte_list}}};\n\n")
        f.write("KERNEL_CONST group_permission_t global_permissions[MAX_PERMS] = {\n")
        for i, perm in enumerate(permissions):
            f.write(
                (f"\t{{{hex(perm.group_id)}, "
                f"{macro(perm.read, 'R_PERMISSION')}, "
                f"{macro(perm.write, 'W_PERMISSION')}, "
                f"{macro(perm.receive, 'C_PERMISSION')}}},\n")
        )
        f.write("};\n")

        # pin hash struct
        f.write("\nKERNEL_CONST pin_hash_t pin_hash = {\n")
        f.write("\t{" + (", ").join(pin_hash_output_hex_bytes) + "},\n")
        f.write("\t{" + (", ").join(salt_bytes_hex_bytes) + "}\n")
        f.write("};\n")
        f.write("\n#endif  // SECRETS_DEFINE\n")
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
