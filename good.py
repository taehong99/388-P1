#!/usr/bin/python3
# coding: latin-1
blob = """
                Ȩʠ+R����i|diH���W�.(�8��@-��xf�K��ؙ�yfሣ�N-�K���J{�]7��x�w�X����4��(x��-	���i~U;1�1���Y�1���}�@M»#�ԕ x��4F
"""
from hashlib import sha256
result = sha256(blob.encode("latin-1")).hexdigest()
firstHex = result[0]

if firstHex=='9':
    print("Use SHA-256 instead!")
else:
    print("MD5 is perfectly secure!")