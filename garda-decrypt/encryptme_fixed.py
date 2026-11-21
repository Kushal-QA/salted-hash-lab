#!/usr/bin/env python3
"""Python 3 port of original/encryptme.py with the damaged parts repaired.

The encoding logic is kept identical to the original. Every change from the
original is marked with a "CHANGE:" comment explaining what and why.

Usage:
    python3 encryptme_fixed.py [count] [secret]

    count   number of random encoding rounds (default 10)
    secret  message to encode (default: a test message)
"""

import string
import random
import sys
from base64 import b64encode, b64decode

# CHANGE: the original line was  secret = '&&&&&&&&&&&&&&'  (damaged). The real
# secret is the unknown we are trying to recover, so a test value is used here.
# It can be overridden from the command line.
secret = 'This is a test secret'

# CHANGE: the original call was  make_secret(secret, count=&&&)  (damaged). The
# real count is unknown and is NOT needed for decryption (each layer records
# its own step number), so it is a configurable default here.
DEFAULT_COUNT = 10

secret_encoding = ['step1', 'step2', 'step3']


def step1(s):
    # CHANGE: Python 3 removed string.maketrans and string.translate. The same
    # mapping is built with str.maketrans and applied with str.translate. The
    # two alphabets are copied verbatim from the original (this table is ROT13).
    _step1 = str.maketrans("zyxwvutsrqponZYXWVUTSRQPONmlkjihgfedcbaMLKJIHGFEDCBA",
                           "mlkjihgfedcbaMLKJIHGFEDCBAzyxwvutsrqponZYXWVUTSRQPON")
    return s.translate(_step1)


def step2(s):
    # CHANGE: in Python 2, str is a byte string and b64encode returned str. In
    # Python 3, b64encode needs bytes and returns bytes, so the text is encoded
    # to bytes first and the result decoded back to str. Layer strings are
    # always ASCII; UTF-8 is used so a plaintext with non-ASCII text still works.
    return b64encode(s.encode('utf-8')).decode('ascii')


def step3(plaintext, shift=4):
    loweralpha = string.ascii_lowercase
    shifted_string = loweralpha[shift:] + loweralpha[:shift]
    # CHANGE: string.maketrans -> str.maketrans (Python 3), same mapping.
    converted = str.maketrans(loweralpha, shifted_string)
    return plaintext.translate(converted)


def make_secret(plain, count):
    # CHANGE: b64encode(plain) -> step2(plain) for the same bytes/str reason
    # as in step2. The produced value is identical: '2' + base64(plain).
    a = '2{}'.format(step2(plain))
    # CHANGE: xrange -> range (xrange does not exist in Python 3). The loop
    # variable shadowing 'count' is kept as in the original; it is harmless.
    for count in range(count):
        r = random.choice(secret_encoding)
        si = secret_encoding.index(r) + 1
        _a = globals()[r](a)
        a = '{}{}'.format(si, _a)
    return a


if __name__ == '__main__':
    # CHANGE: count (and optionally the secret) come from the command line
    # instead of the damaged literal.
    count = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_COUNT
    if len(sys.argv) > 2:
        secret = sys.argv[2]
    # CHANGE: Python 2 print statement -> Python 3 print() function.
    print(make_secret(secret, count=count))
