#!/usr/bin/python3

# Run me like this:
# $ python3 len_ext_attack.py "https://project1.eecs388.org/uniqname/lengthextension/api?token=...."
# or select "Length Extension" from the VS Code debugger

import sys
from urllib.parse import quote
from pymd5 import md5, padding


class URL:
    def __init__(self, url: str):
        # prefix is the slice of the URL from "https://" to "token=", inclusive.
        self.prefix = url[:url.find('=') + 1]
        self.token = url[url.find('=') + 1:url.find('&')]
        # suffix starts at the first "command=" and goes to the end of the URL
        self.suffix = url[url.find('&') + 1:]

    def __str__(self) -> str:
        return f'{self.prefix}{self.token}&{self.suffix}'

    def __repr__(self) -> str:
        return f'{type(self).__name__}({str(self).__repr__()})'


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} URL_TO_EXTEND", file=sys.stderr)
        sys.exit(-1)

    url = URL(sys.argv[1])

    #
    # TODO: Modify the URL
    #
    hash = url.token

    # message = "*******command=xxxx"
    msgLen = 8 + len(url.suffix)
    msgPad = len(padding(msgLen * 8))
    bits = (msgLen + msgPad) * 8

    h = md5(state=bytes.fromhex(hash), count=bits)
    append = "&command=UnlockSafes"
    h.update(append)

    url.token = h.hexdigest()
    url.suffix += (quote(padding(msgLen*8)) + append)
    print(url)


if __name__ == '__main__':
    main()
