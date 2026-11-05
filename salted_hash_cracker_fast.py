#!/usr/bin/env python3
"""
Lab 08 - Salted Hashes: password recovery investigation (OPTIMIZED)
SecureComm / MSc Cybersecurity

Same investigation logic as salted_hash_cracker.py, but the expensive
charset brute-force stages now run in parallel across all CPU cores using
multiprocessing, with a tight inner loop and early termination once every
account has been recovered.

Construction under attack:  digest = SHA1( salt + password )

Speed notes
-----------
* The keyspace for a given length is split into one task per leading
  character; a worker pool chews through those tasks across all cores.
* The inner loop binds hashlib.sha1 and the encoded salt locally and
  compares raw digest bytes (no hexdigest, no helper-function call per guess).
* As soon as `remaining` is empty, the pool is terminated instead of
  finishing the rest of the keyspace.
"""

import hashlib
import itertools
import string
import time
from multiprocessing import Pool, cpu_count

SALT = "www.exploringsecurity.com"
SALT_BYTES = SALT.encode()

# username -> (sha1 hex digest, last-modified date, policy)
ACCOUNTS = {
    "security": ("fafa4483874ec051989d53e1e432ba3a6c6b9143", "2010-01-11", "digits"),
    "Tomtom":   ("06f6fe0f73c6e197ee43eff4e5f7d10fb9e438b2", "2009-12-03", "digits"),
    "Mark123":  ("92e54f10103a3c511853c7098c04141f114719c1", "2010-06-03", "alnum"),
    "superman": ("437fbc6892b38db6ac5bdbe2eab3f7bc924527d9", "2011-01-01", "alnum"),
    "Sparky":   ("2834da08d58330d8dafbb2ac1c0f85f6b3b135ef", "2011-05-09", "alnum"),
    "JillC":    ("f44f3b09df53c1c11273def13cacd8922a86d48c", "2010-12-20", "alnum"),
}

# Use all but one core so the machine stays responsive; at least 1.
NUM_WORKERS = max(1, cpu_count() - 1)


def salted_sha1(password: str) -> str:
    """The exact construction used by the target system: SHA1(salt + password)."""
    return hashlib.sha1(SALT_BYTES + password.encode()).hexdigest()


def try_password(password: str, remaining: dict, cracked: dict) -> None:
    """Cheap single-guess check, used by the fast (non-parallel) stages."""
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
    common += list(ACCOUNTS.keys())
    for base in set(common):
        for variant in {base, base.lower(), base.capitalize()}:
            if 5 <= len(variant) <= 7:
                try_password(variant, remaining, cracked)
                if not remaining:
                    return


# --- Parallel charset brute force ------------------------------------------

# Module-level globals set in each worker process via the pool initializer,
# so large immutable data isn't pickled on every task.
_W_TARGETS = None      # set of target digest *bytes*
_W_CHARSET = None
_W_LENGTH = None


def _worker_init(targets_bytes, charset, length):
    global _W_TARGETS, _W_CHARSET, _W_LENGTH
    _W_TARGETS = targets_bytes
    _W_CHARSET = charset
    _W_LENGTH = length


def _worker_scan(first_char):
    """Scan every candidate of the configured length that starts with
    `first_char`. Returns a list of (hexdigest, password) matches."""
    sha1 = hashlib.sha1
    salt = SALT_BYTES
    targets = _W_TARGETS
    charset = _W_CHARSET
    rest = _W_LENGTH - 1
    prefix = first_char.encode()
    found = []
    if rest <= 0:
        pw = prefix
        d = sha1(salt + pw).digest()
        if d in targets:
            found.append((d.hex(), first_char))
        return found
    for combo in itertools.product(charset.encode(), repeat=rest):
        pw = prefix + bytes(combo)
        d = sha1(salt + pw).digest()
        if d in targets:
            found.append((d.hex(), pw.decode()))
    return found


def attack_charset_parallel(remaining, cracked, charset, label, max_len=7):
    """Parallel staged brute force over a charset, shortest length first."""
    print(f"[*] Stage: {label} brute force  ({NUM_WORKERS} workers)")
    for length in range(5, max_len + 1):
        if not remaining:
            return
        space = len(charset) ** length
        print(f"    len={length} keyspace={space:,}")
        t0 = time.time()

        targets_bytes = {bytes.fromhex(h) for h in remaining.values()}
        # Reverse map digest-hex -> user for reporting.
        hex_to_user = {h: u for u, h in remaining.items()}

        with Pool(processes=NUM_WORKERS,
                  initializer=_worker_init,
                  initargs=(targets_bytes, charset, length)) as pool:
            try:
                for matches in pool.imap_unordered(_worker_scan, list(charset)):
                    for hexdigest, password in matches:
                        user = hex_to_user.get(hexdigest)
                        if user and user in remaining:
                            cracked[user] = password
                            del remaining[user]
                            print(f"  [+] CRACKED {user:10s} = {password!r}")
                    if not remaining:
                        pool.terminate()   # stop the other workers immediately
                        break
            finally:
                pool.terminate()
                pool.join()

        print(f"    len={length} done in {time.time() - t0:.1f}s")
        if not remaining:
            return


def main():
    remaining = {u: h for u, (h, _d, _p) in ACCOUNTS.items()}
    cracked = {}

    print(f"[*] Salt in use: {SALT}")
    print(f"[*] Algorithm: SHA-1 (digest length {len(next(iter(remaining.values())))} hex)")
    print(f"[*] Workers: {NUM_WORKERS} (of {cpu_count()} logical CPUs)\n")

    t0 = time.time()
    attack_digits(remaining, cracked)
    attack_common(remaining, cracked)
    # alphanumeric accounts: escalate charset only as needed
    attack_charset_parallel(remaining, cracked, string.ascii_lowercase,
                            "lowercase a-z", max_len=6)
    attack_charset_parallel(remaining, cracked,
                            string.ascii_lowercase + string.digits,
                            "lowercase + digits", max_len=6)
    # final (expensive) tier -- full alphanumeric; uncomment to run
    attack_charset_parallel(remaining, cracked,
                            string.ascii_letters + string.digits,
                            "full alphanumeric", max_len=6)

    print("\n" + "=" * 48)
    print("RESULTS")
    print("=" * 48)
    for user in ACCOUNTS:
        pw = cracked.get(user, "<not recovered>")
        print(f"  {user:10s} -> {pw}")
    print(f"\n[*] Total time: {time.time() - t0:.1f}s")
    if remaining:
        print(f"[!] Still uncracked: {list(remaining)} "
              f"(needs larger wordlist e.g. rockyou, or length-7 / mixed-case run)")


if __name__ == "__main__":
    main()
