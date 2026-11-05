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
| wordlist_attack.py | Dictionary attack against a wordlist (rockyou), with case variants. Takes the wordlist path as an argument. |
| rule_attack.py | Parallel rule-based attack: case variants plus numeric prefix/suffix mangling up to the policy length. Catches word-plus-digits passwords that plain dictionaries miss. |

## Usage

Requires Python 3.9 or newer (tested on 3.14).

```bash
python -u salted_hash_cracker_fast.py
python -u wordlist_attack.py path/to/rockyou.txt
python -u rule_attack.py path/to/rockyou.txt
```

The -u flag disables output buffering so cracking progress is shown live.

## Methodology

The accounts were recovered with an escalating attack. Each stage is cheaper
than the next, so the search stops as early as possible.

1. Identify the algorithm: 40 hex characters means a 20-byte digest, which is SHA-1.
2. Investigate first: the per-account last-modified date and the recovered policy
   decide the character set and length, shrinking the search space.
3. Digits: brute force the digit-only policy accounts (keyspace up to 10^7).
4. Dictionary: common and reused passwords, including the usernames themselves.
5. Wordlist plus rules: rockyou with case variants and numeric mangling, which
   recovers word-plus-digits passwords.
6. GPU mask brute force: a full alphanumeric mask for the remaining account,
   using hashcat mode 120 (sha1(salt.pass)) on the GPU.

The final account used a 7-character mixed-case alphanumeric password with no
dictionary root, so only the exhaustive mask reached it. This is the key lesson:
dictionary and rule attacks are fast but bounded, and a salted random password
of sufficient length forces full brute force, where every guess must still be
re-hashed with the salt.

### hashcat commands used for the last account

```bash
hashcat -m 120 -a 0 hashes.txt rockyou.txt -r rules/best64.rule -O -w 3
hashcat -m 120 -a 3 hashes.txt -1 ?l?u?d --increment --increment-min 6 --increment-max 7 ?1?1?1?1?1?1?1 -O -w 3
```

The hash file uses the `digest:salt` format that hashcat mode 120 expects.

## Results

All six accounts were recovered.

| Account | Password | Policy | Recovered by |
|---------|----------|--------|--------------|
| Tomtom | 54321 | digits | digit brute force |
| security | 121298 | digits | digit brute force |
| Mark123 | Mark123 | alnum | dictionary (username reuse) |
| superman | qwerty | alnum | dictionary (common password) |
| Sparky | Admin09 | alnum | rockyou plus rules |
| JillC | Q2w13sA | alnum | 7-char GPU mask |

## Note

This code and the included hashes are coursework for an authorized security lab.
It is for educational use within that lab only.
