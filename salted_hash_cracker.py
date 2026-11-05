#!/usr/bin/env python3
"""
Lab 08 - Salted Hashes: password recovery investigation
SecureComm / MSc Cybersecurity

Scenario
--------
A set of user accounts was recovered with SHA-1 *salted* hashes. The hash is
built as:  digest = SHA1( salt + password )
where the salt is the site domain found in the case data: www.exploringsecurity.com

Password policy recovered from the case notes:
  * Accounts last modified BEFORE ~May 2010 : digits only, 5-7 characters
  * Accounts last modified AFTER  ~May 2010 : alphanumeric, 5-7 characters

Strategy
--------
1. Identify the algorithm from the digest length (40 hex = 20 bytes = SHA-1).
2. Use the per-account "last modified" date to pick the correct charset/length,
   which massively shrinks the search space (this is the point of the lab:
   investigate first, brute force second).
3. Run a staged attack: cheap keyspaces first (digits, then common passwords,
   then lowercase, then lowercase+digits) before anything expensive.

Note on salting: because every hash uses the same site-wide salt, precomputed
rainbow tables for plain SHA-1 do not work -- the attacker must re-hash each
guess WITH the salt. A per-user random salt would have made this even harder.
"""

import hashlib
import itertools
import string
import time

SALT = "www.exploringsecurity.com"

# username -> (sha1 hex digest, last-modified date, policy)
ACCOUNTS = {
    "security": ("fafa4483874ec051989d53e1e432ba3a6c6b9143", "2010-01-11", "digits"),
    "Tomtom":   ("06f6fe0f73c6e197ee43eff4e5f7d10fb9e438b2", "2009-12-03", "digits"),
    "Mark123":  ("92e54f10103a3c511853c7098c04141f114719c1", "2010-06-03", "alnum"),
    "superman": ("437fbc6892b38db6ac5bdbe2eab3f7bc924527d9", "2011-01-01", "alnum"),
    "Sparky":   ("2834da08d58330d8dafbb2ac1c0f85f6b3b135ef", "2011-05-09", "alnum"),
    "JillC":    ("f44f3b09df53c1c11273def13cacd8922a86d48c", "2010-12-20", "alnum"),
}


def salted_sha1(password: str) -> str:
    """The exact construction used by the target system: SHA1(salt + password)."""
    return hashlib.sha1((SALT + password).encode()).hexdigest()


def try_password(password: str, remaining: dict, cracked: dict) -> None:
    digest = salted_sha1(password)
    for user in list(remaining):
        if digest == remaining[user]:
            cracked[user] = password
            del remaining[user]
            print(f"  [+] CRACKED {user:10s} = {password!r}")


def attack_digits(remaining, cracked, max_len=7):
    """Digit-only policy (pre-2010 accounts). Keyspace up to 10^7 -- trivial."""
    print("[*] Stage 1: digit-only brute force (5-7 digits)")
    for length in range(5, max_len + 1):
        if not remaining:
            return
        for combo in itertools.product(string.digits, repeat=length):
            try_password("".join(combo), remaining, cracked)
            if not remaining:
                return


def attack_common(remaining, cracked):
    """Common/weak passwords and username-derived guesses (cheap dictionary)."""
    print("[*] Stage 2: common-password dictionary")
    common = """
    qwerty password abc123 123abc letmein monkey dragon shadow master
    superman batman trustno1 iloveyou welcome sunshine princess football
    baseball hello freedom whatever jordan harley ranger buster hunter
    """.split()
    # include the usernames themselves (Mark123 reuses its username as password)
    common += list(ACCOUNTS.keys())
    for base in set(common):
        for variant in {base, base.lower(), base.capitalize()}:
            if 5 <= len(variant) <= 7:
                try_password(variant, remaining, cracked)
                if not remaining:
                    return


def attack_charset(remaining, cracked, charset, label, max_len=7):
    """Generic staged brute force over a charset, shortest length first."""
    print(f"[*] Stage: {label} brute force")
    for length in range(5, max_len + 1):
        if not remaining:
            return
        space = len(charset) ** length
        print(f"    len={length} keyspace={space:,}")
        t0 = time.time()
        for combo in itertools.product(charset, repeat=length):
            try_password("".join(combo), remaining, cracked)
            if not remaining:
                return
        print(f"    len={length} done in {time.time() - t0:.1f}s")


def main():
    remaining = {u: h for u, (h, _d, _p) in ACCOUNTS.items()}
    cracked = {}

    print(f"[*] Salt in use: {SALT}")
    print(f"[*] Algorithm: SHA-1 (digest length {len(next(iter(remaining.values())))} hex)\n")

    t0 = time.time()
    attack_digits(remaining, cracked)
    attack_common(remaining, cracked)
    # alphanumeric accounts: escalate charset only as needed
    attack_charset(remaining, cracked, string.ascii_lowercase, "lowercase a-z", max_len=6)
    attack_charset(remaining, cracked, string.ascii_lowercase + string.digits,
                   "lowercase + digits", max_len=6)
    # final (expensive) tier -- full alphanumeric; run with care
    # attack_charset(remaining, cracked,
    #                string.ascii_letters + string.digits, "full alphanumeric", max_len=6)

    print("\n" + "=" * 48)
    print("RESULTS")
    print("=" * 48)
    for user in ACCOUNTS:
        pw = cracked.get(user, "<not recovered>")
        print(f"  {user:10s} -> {pw}")
    print(f"\n[*] Total time: {time.time() - t0:.1f}s")
    if remaining:
        print(f"[!] Still uncracked: {list(remaining)} "
              f"(needs larger wordlist e.g. rockyou, or full-charset run)")


if __name__ == "__main__":
    main()
