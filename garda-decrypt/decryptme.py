#!/usr/bin/env python3
"""Decrypt ciphertext produced by encryptme.py / encryptme_fixed.py.

Every layer of the ciphertext starts with one digit naming the step that
produced the rest of the string (1 = ROT13, 2 = base64, 3 = Caesar +4 on
lowercase). Decryption peels the leading digit and applies the inverse of
that step, layer by layer, until the plaintext is reached.

Because make_secret always begins with  '2' + base64(plain), the plaintext
is always the output of a step-2 (base64) peel. The decoder therefore peels
greedily as far as it can, then takes the deepest step-2 output as the
plaintext. This handles secrets that themselves start with 1, 2 or 3.

Usage:
    python3 decryptme.py intercepted.txt
    python3 decryptme.py <ciphertext string>
    python3 decryptme.py -            (read from stdin)

Options:
    --trace FILE      also write the layer trace to FILE (UTF-8)
    --plaintext FILE  also write the recovered plaintext to FILE (UTF-8)
    --quiet           do not print the per-layer trace
"""

import argparse
import binascii
import os
import string
import sys
from base64 import b64decode

STEP_NAMES = {
    '1': 'step1 (ROT13)',
    '2': 'step2 (base64)',
    '3': 'step3 (Caesar +4, lowercase)',
}

_ROT13 = str.maketrans(
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM')
_LOWER = string.ascii_lowercase
_UNSHIFT4 = str.maketrans(_LOWER, _LOWER[-4:] + _LOWER[:-4])


class DecryptError(Exception):
    pass


def inv_step1(s):
    """ROT13 is its own inverse."""
    return s.translate(_ROT13)


def inv_step2(s):
    """Strict base64 decode; raises ValueError if s is not valid base64/UTF-8."""
    try:
        raw = b64decode(s, validate=True)
    except binascii.Error as e:
        raise ValueError('invalid base64: {}'.format(e))
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError as e:
        raise ValueError('base64 output is not valid text: {}'.format(e))


def inv_step3(s):
    """Shift lowercase letters back by 4."""
    return s.translate(_UNSHIFT4)


INVERSES = {'1': inv_step1, '2': inv_step2, '3': inv_step3}


def peel(ciphertext):
    """Peel layers greedily.

    Returns a list of (digit, result) tuples, one per layer peeled, plus the
    reason the peeling stopped.
    """
    layers = []
    current = ciphertext
    while True:
        if not current or current[0] not in INVERSES:
            reason = 'result does not start with 1/2/3'
            break
        digit, body = current[0], current[1:]
        try:
            result = INVERSES[digit](body)
        except ValueError as e:
            reason = 'step{} inverse failed: {}'.format(digit, e)
            break
        layers.append((digit, result))
        current = result
    return layers, reason


def decrypt(ciphertext):
    """Return (plaintext, layers) where layers is the list of (digit, result)
    peels from the outermost layer inwards, ending at the plaintext."""
    ciphertext = ''.join(ciphertext.split())
    if not ciphertext:
        raise DecryptError('ciphertext is empty')
    layers, reason = peel(ciphertext)
    # The plaintext is the output of a step-2 peel. Take the deepest one whose
    # output is non-empty. Tie-break: the scheme is not always uniquely
    # decodable. For example secret '2' with count 0 and secret '' with one
    # step-2 round both give '2Mg=='. An intercepted message is never empty,
    # so a non-empty plaintext is preferred.
    step2_at = [i for i, (digit, _) in enumerate(layers) if digit == '2']
    if not step2_at:
        raise DecryptError('no valid decoding: no base64 layer found ({})'.format(reason))
    non_empty = [i for i in step2_at if layers[i][1] != '']
    last2 = non_empty[-1] if non_empty else step2_at[-1]
    layers = layers[:last2 + 1]
    return layers[-1][1], layers


def forward_sequence(layers):
    """Step numbers in the order the encryptor applied them (excluding the
    initial '2' + base64(plain), which is the innermost layer)."""
    return [int(d) for d, _ in reversed(layers)][1:]


def format_trace(ciphertext, layers, width=60):
    ciphertext = ''.join(ciphertext.split())
    out = []
    out.append('Ciphertext length: {} characters'.format(len(ciphertext)))
    out.append('Ciphertext start : {}'.format(ciphertext[:width]))
    out.append('')
    out.append('{:>5}  {:<30} {:>7}  {}'.format('Layer', 'Step inverted', 'Length', 'Result (first {} chars)'.format(width)))
    out.append('-' * (5 + 2 + 30 + 1 + 7 + 2 + width))
    for n, (digit, result) in enumerate(layers, 1):
        out.append('{:>5}  {:<30} {:>7}  {!r}'.format(n, STEP_NAMES[digit], len(result), result[:width]))
    out.append('')
    peel_order = [d for d, _ in layers]
    out.append('Layers peeled: {}'.format(len(layers)))
    out.append('Peel order (outermost first)  : {}'.format(' '.join(peel_order)))
    fwd = forward_sequence(layers)
    out.append('Encryption rounds (count)     : {}'.format(len(fwd)))
    out.append('Forward step sequence (random rounds, in applied order): {}'.format(' '.join(map(str, fwd))))
    out.append('Step usage in rounds: step1={} step2={} step3={}'.format(fwd.count(1), fwd.count(2), fwd.count(3)))
    return '\n'.join(out)


def read_input(arg):
    if arg == '-':
        return sys.stdin.read()
    if os.path.isfile(arg):
        with open(arg, 'r', encoding='utf-8') as f:
            return f.read()
    return arg


def main(argv=None):
    p = argparse.ArgumentParser(description='Decrypt encryptme.py ciphertext.')
    p.add_argument('input', help='ciphertext file, ciphertext string, or - for stdin')
    p.add_argument('--trace', help='write the layer trace to this file')
    p.add_argument('--plaintext', help='write the recovered plaintext to this file')
    p.add_argument('--quiet', action='store_true', help='do not print the layer trace')
    args = p.parse_args(argv)

    try:
        ciphertext = read_input(args.input)
        plaintext, layers = decrypt(ciphertext)
    except (OSError, UnicodeDecodeError, DecryptError) as e:
        print('ERROR: {}'.format(e), file=sys.stderr)
        return 1

    trace = format_trace(ciphertext, layers)
    report = trace + '\n\nRecovered plaintext:\n' + plaintext
    if not args.quiet:
        print(report)
    else:
        print(plaintext)
    if args.trace:
        with open(args.trace, 'w', encoding='utf-8', newline='\n') as f:
            f.write(report + '\n')
    if args.plaintext:
        with open(args.plaintext, 'w', encoding='utf-8', newline='\n') as f:
            f.write(plaintext + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
