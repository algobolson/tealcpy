#!/usr/bin/env python3

import base64
import importlib
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tealc

byteConstantVariations = [
    "byte b32 MFRGGZDFMY",
    "byte base32 MFRGGZDFMY",
    "byte base32(MFRGGZDFMY)",
    "byte b32(MFRGGZDFMY)",
    "byte b32 MFRGGZDFMY======",
    "byte base32 MFRGGZDFMY======",
    "byte base32(MFRGGZDFMY======)",
    "byte b32(MFRGGZDFMY======)",
    "byte b64 YWJjZGVm",
    "byte base64 YWJjZGVm",
    "byte b64(YWJjZGVm)",
    "byte base64(YWJjZGVm)",
    "byte 0x616263646566",
]

hexresult = "0126010661626364656628"
result = base64.b16decode(hexresult)

retcode = 0

for text in byteConstantVariations:
    prog = tealc.AssembleString(text)
    if prog != result:
        sys.stderr.write("FAIL: {!r}, wanted %s got %s\n".format(text, hexresult, base64.b16encode(prog)))
        retcode = 1
sys.exit(retcode)
