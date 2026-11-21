#!/usr/bin/env python3
"""Verification tests for the Garda decryption.

1. Unit checks that each inverse undoes its forward step.
2. Round-trip: N random secrets (varied length and character set) are
   encrypted with encryptme_fixed.make_secret using a random count 0-50,
   decrypted with decryptme.decrypt, and compared with the original.
3. Edge cases: empty secret, secrets that start with 1/2/3, non-ASCII text.
4. Exact reproduction: the forward step sequence recovered from
   intercepted.txt is re-applied to the recovered plaintext and must give
   intercepted.txt exactly.

Run:  python3 test_roundtrip.py          (or: python3 -m unittest -v test_roundtrip)
"""

import codecs
import os
import random
import string
import unittest

import encryptme_fixed as enc
import decryptme as dec

HERE = os.path.dirname(os.path.abspath(__file__))
INTERCEPTED = os.path.join(HERE, 'intercepted.txt')

N_RANDOM = 1000
SEED = 20261121
MAX_COUNT = 50

CHARSETS = {
    'lowercase': string.ascii_lowercase,
    'letters': string.ascii_letters,
    'digits': string.digits,
    'letters+digits': string.ascii_letters + string.digits,
    'letters+space': string.ascii_letters + ' ',
    'punctuation': string.punctuation,
    'printable': string.ascii_letters + string.digits + string.punctuation + ' ',
}


def random_secret(rng):
    name = rng.choice(sorted(CHARSETS))
    length = rng.randint(1, 200)
    return name, ''.join(rng.choice(CHARSETS[name]) for _ in range(length))


class TestSteps(unittest.TestCase):
    sample = 'The Quick brown FOX jumps over 13 lazy dogs! zZaA'

    def test_step1_is_rot13_and_self_inverse(self):
        self.assertEqual(enc.step1(self.sample), codecs.encode(self.sample, 'rot13'))
        self.assertEqual(enc.step1(enc.step1(self.sample)), self.sample)
        self.assertEqual(dec.inv_step1(enc.step1(self.sample)), self.sample)

    def test_step2_inverse(self):
        self.assertEqual(dec.inv_step2(enc.step2(self.sample)), self.sample)

    def test_step3_only_shifts_lowercase(self):
        self.assertEqual(enc.step3('abc xyz ABC 123'), 'efg bcd ABC 123')
        self.assertEqual(dec.inv_step3(enc.step3(self.sample)), self.sample)

    def test_inv_step2_rejects_bad_base64(self):
        with self.assertRaises(ValueError):
            dec.inv_step2('not base64!')


class TestRoundTrip(unittest.TestCase):

    def test_random_round_trips(self):
        rng = random.Random(SEED)
        random.seed(SEED + 1)  # encryptor uses the global random module
        failures = []
        counts = []
        lengths = []
        used = {k: 0 for k in CHARSETS}
        for i in range(N_RANDOM):
            name, secret = random_secret(rng)
            count = rng.randint(0, MAX_COUNT)
            used[name] += 1
            counts.append(count)
            lengths.append(len(secret))
            ct = enc.make_secret(secret, count)
            try:
                pt, layers = dec.decrypt(ct)
            except dec.DecryptError as e:
                failures.append((i, secret, count, 'error: {}'.format(e)))
                continue
            if pt != secret:
                failures.append((i, secret, count, 'got {!r}'.format(pt)))
            elif len(dec.forward_sequence(layers)) != count:
                failures.append((i, secret, count, 'wrong layer count {}'.format(len(layers))))
        print('\n  random round trips: {} cases, seed {}, counts {}-{} (mean {:.1f}), '
              'secret length {}-{}, failures {}'.format(
                  N_RANDOM, SEED, min(counts), max(counts), sum(counts) / len(counts),
                  min(lengths), max(lengths), len(failures)))
        print('  charset usage: ' + ', '.join('{}={}'.format(k, v) for k, v in sorted(used.items())))
        for f in failures[:10]:
            print('  FAIL', f)
        self.assertEqual(failures, [])

    def test_edge_cases(self):
        # The empty secret is covered separately in test_ambiguity_empty_vs_2.
        cases = [' ', '1', '2', '3', '123', '1hello', '2 be or not 2 be',
                 '3 blind mice', '=', 'a' * 500, 'Café €5 — naïve',
                 'line one\nline two\ttab']
        random.seed(SEED + 2)
        for secret in cases:
            for count in (0, 1, 5, 25, 50):
                with self.subTest(secret=secret, count=count):
                    pt, layers = dec.decrypt(enc.make_secret(secret, count))
                    self.assertEqual(pt, secret)
                    self.assertEqual(len(dec.forward_sequence(layers)), count)

    def test_ambiguity_empty_vs_2(self):
        # Secret '' followed by one step-2 round and secret '2' with no rounds
        # give the SAME ciphertext, so the scheme is not uniquely decodable.
        # The decoder prefers the non-empty reading.
        ct_empty_plus_step2 = '2' + enc.step2(enc.make_secret('', 0))
        ct_two = enc.make_secret('2', 0)
        print('\n  make_secret("", 0) then one step2 round -> {!r}; make_secret("2", 0) -> {!r}'
              .format(ct_empty_plus_step2, ct_two))
        self.assertEqual(ct_empty_plus_step2, ct_two)
        self.assertEqual(dec.decrypt(ct_two)[0], '2')
        # The empty secret with no rounds is still decoded correctly.
        self.assertEqual(dec.decrypt(enc.make_secret('', 0))[0], '')


class TestIntercepted(unittest.TestCase):

    def test_reproduce_intercepted_exactly(self):
        with open(INTERCEPTED, 'r', encoding='utf-8') as f:
            raw = f.read()
        ciphertext = ''.join(raw.split())
        plaintext, layers = dec.decrypt(ciphertext)
        seq = dec.forward_sequence(layers)
        steps = {1: enc.step1, 2: enc.step2, 3: enc.step3}
        a = '2' + enc.step2(plaintext)
        for s in seq:
            a = '{}{}'.format(s, steps[s](a))
        print('\n  recovered plaintext: {!r}'.format(plaintext))
        print('  re-applied {} forward steps; rebuilt length {}, intercepted length {}, identical: {}'
              .format(len(seq), len(a), len(ciphertext), a == ciphertext))
        self.assertEqual(a, ciphertext)


if __name__ == '__main__':
    unittest.main(verbosity=2)
