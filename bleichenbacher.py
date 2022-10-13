#!/usr/bin/python3

# Run me like this:
# $ python3 bleichenbacher.py "eecs388+uniqname+100.00"
# or select "Bleichenbacher" from the VS Code debugger

from math import sqrt
from roots import *

import hashlib
import sys

from roots import _isqrt_fast_python
from roots import _sqrtrem_python


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} MESSAGE", file=sys.stderr)
        sys.exit(-1)
    message = sys.argv[1]

    #
    # TODO: Forge a signature
    #
    # 2048/8 = 256 bytes

    forged_signature = bytearray()
    # initial values
    forged_signature.append(0x00)
    forged_signature.append(0x01)
    forged_signature.append(0xFF)
    forged_signature.append(0x00)
    forged_signature.extend(
        b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20')
    # m = sha-256 digest of message
    m = hashlib.sha256()
    m.update(message.encode('utf-8'))
    forged_signature.extend(m.digest())
    # arbitrary values
    forged_signature.extend(bytes(201))

    # (floor(sqrt(signature)), bool)
    nthroot = integer_nthroot(
        bytes_to_integer(bytes(forged_signature)), 3)

    if nthroot[1] == False:
        signature = (nthroot[0] + 1)
    else:
        signature = nthroot[0]

    print(bytes_to_base64(integer_to_bytes(signature, 256)))


if __name__ == '__main__':
    main()
