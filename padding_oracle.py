#!/usr/bin/python3

# Run me like this:
# $ python3 padding_oracle.py "https://project1.eecs388.org/uniqname/paddingoracle/verify" "5a7793d3..."
# or select "Padding Oracle" from the VS Code debugger

import enum
import json
from pydoc import plain
import sys
from tarfile import BLOCKSIZE
import time
from typing import Union, Dict, List

import requests

from pymd5 import padding

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write(
                "It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write(
                "If this keeps happening, check the URL. Perhaps your uniqname is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue


def main():
    if len(sys.argv) != 3:
        print(
            f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)

    #
    # TODO: Decrypt the message
    #
    block_size = 16  # bytes
    hmac_size = 32  # bytes
    original_cipher = bytearray(message)
    cipher_text = bytearray(message)

    # The iv is given to us in the first block
    iv = original_cipher[:block_size]

    # initial PKCS padding value
    pkcs = 0x01
    # intermediate plaintext and plain_text plaintext
    decryption = bytearray(len(original_cipher) - block_size)
    plain_text = bytearray(len(original_cipher) - block_size)

    # Iterate backwards from the second to last block
    for i in reversed(range(len(original_cipher)-block_size)):
        # update previous bytes in ciphertext to accout for current padding length
        bytes_to_change = pkcs - 1
        for prev in range(bytes_to_change):
            offset = prev + 1
            cipher_text[i + offset] = pkcs ^ decryption[i + offset]


        # try every value from 0~255 to get C_n'
        C_prime = 0  # C_n'
        messages_to_try = []
        # Add all possible modified ciphertexts to a list
        for val in range(0x00, 0xFF+1):
            cipher_text[i] = val  # modify the ciphertext value
            messages_to_try.append(bytes(cipher_text))

        # look for the one value that returns valid padding (invalid mac)
        valid = -1
        invalid_mac = -1
        for count, value in enumerate(oracle(oracle_url, messages_to_try)):
            if value['status'] == 'invalid_mac':
                C_prime = count
                invalid_mac = count
            if value['status'] == 'valid':
                C_prime = count
                valid = count

        # edge case
        # if we encountered both
        if valid > -1 and invalid_mac > -1:
            # increment previous byte
            valid_cipher = bytearray(messages_to_try[valid])
            invalid_cipher = bytearray(messages_to_try[invalid_mac])
            valid_cipher[i - 1] = (valid_cipher[i - 1] + 1) % 0xFF
            invalid_cipher[i - 1] = (invalid_cipher[i - 1] + 1) % 0xFF

            if oracle(oracle_url, [valid_cipher])[0]['status'] == 'invalid_mac':
                C_prime = valid_cipher[i]
            elif oracle(oracle_url, [invalid_cipher])[0]['status'] == 'invalid_mac':
                C_prime = invalid_cipher[i]

        # XOR the modified byte and the padding value to get the decryption value
        D_val = C_prime ^ pkcs
        # store the value in decryption string
        decryption[i] = D_val
        # XOR the original ciphertext and the plaintext to find the decoded message
        plain_text[i] = decryption[i] ^ original_cipher[i]

        # update padding for next round
        if pkcs == block_size:
            pkcs = 0x01
            # chop off finished block
            original_cipher = original_cipher[:-block_size]
            cipher_text = original_cipher[:]
        else:
            pkcs += 1


    # Chop off IV from the beginning and MAC + padding from the end
    padding_size = plain_text[-1]
    plain_text = plain_text[:-(hmac_size+padding_size)]

    print(plain_text.decode('utf-8'))


if __name__ == '__main__':
    main()
