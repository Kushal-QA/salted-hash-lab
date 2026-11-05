# Lab 08 - Salted Hash Password Recovery

MSc Cybersecurity, SecureComm, Lab 08

A password-recovery exercise against a set of recovered user accounts stored as
salted SHA-1 hashes:

```
digest = SHA1( salt + password )
salt   = www.exploringsecurity.com   (site-wide, recovered from the case data)
```

Because the salt is site-wide, precomputed rainbow tables for plain SHA-1 do not
work. Each guess must be re-hashed with the salt. The attack narrows the search
space using the per-account "last modified" date and the recovered password
policy before brute forcing:

- Accounts modified before ~May 2010: digits only, 5 to 7 characters
- Accounts modified after ~May 2010: alphanumeric, 5 to 7 characters

## Files

| File | Description |
|------|-------------|
| salted_hash_cracker.py | Single-threaded lab solution (staged: digits, dictionary, lowercase, lowercase+digits). |
| salted_hash_cracker_fast.py | Parallel version. The charset brute-force stages run across all CPU cores with multiprocessing, a tight digest-bytes inner loop, and early termination once every account is recovered. |

## Usage

Requires Python 3.9 or newer (tested on 3.14).

```bash
python -u salted_hash_cracker_fast.py
```

The -u flag disables output buffering so cracking progress is shown live.

## Attack stages

1. Digits (pre-2010 policy): up to 10^7, trivial.
2. Common-password dictionary: weak passwords and username reuse.
3. Lowercase a-z: parallel brute force, length 5 to 6.
4. Lowercase plus digits: parallel brute force, length 5 to 6.
5. Full alphanumeric: parallel brute force, length 5 to 6 (heaviest tier).

## Note

This code and the included hashes are coursework for an authorized security lab.
It is for educational use within that lab only.
