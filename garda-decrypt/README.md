# Garda intercepted message: decryption

Recovers the plaintext of an intercepted message (`intercepted.txt`) that was
produced by a partially damaged Python 2 program (`original/encryptme.py`).

**Recovered message:** `Why do elephants have big ears?`

## Contents

| Path | Purpose |
|---|---|
| `original/encryptme.py` | The damaged Python 2 encryptor, unchanged |
| `intercepted.txt` | The intercepted ciphertext (35,138 characters, one line) |
| `encryptme_fixed.py` | Python 3 port of the encryptor; damaged parts repaired, every change commented |
| `decryptme.py` | Decryptor: peels the layers and prints a trace and the plaintext |
| `test_roundtrip.py` | Round-trip tests plus exact reproduction of `intercepted.txt` |
| `output/decrypt_trace.txt` | Layer-by-layer trace from running `decryptme.py` on `intercepted.txt` |
| `output/plaintext.txt` | The recovered plaintext |
| `output/test_results.txt` | Output of the final test run (all passing) |
| `output/test_results_run1_failed.txt` | First test run, kept as evidence (one edge case failed; see below) |

## How the encoding works

The encryptor has three steps:

| Step | Code | What it does | Inverse |
|---|---|---|---|
| 1 | `step1` | `maketrans` table that is ROT13 on upper- and lowercase letters | ROT13 again (self-inverse) |
| 2 | `step2` | base64 encode | base64 decode |
| 3 | `step3` | Caesar shift +4 on lowercase letters only | Shift lowercase by -4 |

`make_secret(plain, count)` builds the ciphertext like this:

1. `a = '2' + base64(plain)`
2. `count` times: pick a random step, apply it to the **whole** string `a`, then
   **prepend** that step's number (`1`, `2` or `3`).

So the ciphertext describes itself: its first character always names the last
step applied. Decryption reads the leading digit, removes it, applies the
inverse of that step, and repeats. The plaintext is the result of the innermost
base64 decode, the `'2'` added in step 1. Neither the damaged `secret` nor the
damaged `count` is needed to decrypt.

### Edge case: one ciphertext can decode two ways

The first test run (`output/test_results_run1_failed.txt`) showed that the scheme
is not always uniquely decodable. `make_secret('2', 0)` and `make_secret('', 0)`
followed by one step-2 round both give `2Mg==`. When a ciphertext has more than
one valid reading, `decryptme.py` takes the deepest base64 layer that gives a
**non-empty** plaintext, because an intercepted message is never empty. This
does not affect the intercepted message: re-encoding the recovered plaintext
reproduces the ciphertext exactly (see Tests).

## How to run

Python 3 only, no third-party packages (tested with Python 3.12).

```bash
cd garda-decrypt
python3 decryptme.py intercepted.txt
```

Options: `--trace FILE` and `--plaintext FILE` also save the output to files,
and `--quiet` prints only the plaintext. Instead of a file you can pass a
ciphertext string, or `-` to read from stdin. The output files in `output/`
were produced with:

```bash
python3 decryptme.py intercepted.txt --trace output/decrypt_trace.txt --plaintext output/plaintext.txt
```

Fixed encryptor (count defaults to 10):

```bash
python3 encryptme_fixed.py                         # test secret, 10 rounds
python3 encryptme_fixed.py 25 "Hello Garda 123!"   # custom count and secret
python3 encryptme_fixed.py 7 "Hello" | python3 decryptme.py -
```

## Tests

```bash
python3 test_roundtrip.py          # or: python3 -m unittest -v test_roundtrip
```

The suite contains:

- **Step checks.** `step1` equals Python's `rot13` codec and is self-inverse.
  Each inverse undoes its step. `step3` leaves uppercase letters and digits unchanged.
- **Random round trips.** 1000 random secrets (seed 20261121) with lengths 1-199
  and seven character sets (lowercase, letters, digits, letters+digits,
  letters+space, punctuation, printable), each with a random count from 0 to 50.
  Each secret is encrypted with `encryptme_fixed.py`, decrypted with
  `decryptme.py`, and checked for the same plaintext and the same number of rounds.
- **Edge cases.** Secrets that start with 1/2/3, non-ASCII text, newlines and tabs,
  a 500-character secret, each with counts 0, 1, 5, 25 and 50. The empty-vs-`'2'`
  ambiguity is tested separately.
- **Exact reproduction.** Applies the recovered forward step sequence (67 rounds)
  to the recovered plaintext and checks the result equals `intercepted.txt`
  character for character.

Result of the final run (`output/test_results.txt`): 8 tests, all passing.
1000/1000 round trips succeeded. The rebuilt ciphertext is identical to
`intercepted.txt` (35,138 characters).

## Decryption summary

From `output/decrypt_trace.txt`:

- 68 layers peeled: 67 random rounds plus the initial `'2' + base64(plain)`
- Rounds by step: step1 = 22, step2 = 22, step3 = 23
- Forward step sequence (order applied):
  `1 1 1 1 1 3 1 1 2 2 3 2 2 3 2 3 3 2 1 2 1 3 1 1 2 1 2 3 1 1 2 2 3 3 1 2 2 3 1 1 2 3 3 3 3 3 3 3 2 2 2 3 2 1 3 2 2 1 1 3 2 2 1 3 3 1 3`
- Plaintext: `Why do elephants have big ears?`
