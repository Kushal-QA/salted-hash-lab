#!/usr/bin/env python3
import hashlib
import string
import sys
import time
from multiprocessing import Pool, cpu_count

SALT = b"www.exploringsecurity.com"
MAX_LEN = 7

TARGETS = {
    "2834da08d58330d8dafbb2ac1c0f85f6b3b135ef": "Sparky",
    "f44f3b09df53c1c11273def13cacd8922a86d48c": "JillC",
}

EXTRA_BASES = [
    b"security", b"Tomtom", b"Mark123", b"superman", b"Sparky", b"JillC",
]

NUM_WORKERS = max(1, cpu_count() - 1)

_TARGET_BYTES = None
_HEX_TO_USER = None


def _init(target_bytes, hex_to_user):
    global _TARGET_BYTES, _HEX_TO_USER
    _TARGET_BYTES = target_bytes
    _HEX_TO_USER = hex_to_user


def candidates(word):
    variants = {word, word.lower(), word.capitalize(), word.upper()}
    for v in variants:
        lv = len(v)
        if 1 <= lv <= MAX_LEN:
            yield v
        for k in range(1, MAX_LEN - lv + 1):
            for n in range(10 ** k):
                suf = str(n).zfill(k).encode()
                yield v + suf
                yield suf + v


def scan_chunk(words):
    sha1 = hashlib.sha1
    salt = SALT
    targets = _TARGET_BYTES
    found = []
    still = set(targets)
    for word in words:
        for cand in candidates(word):
            d = sha1(salt + cand).digest()
            if d in still:
                found.append((d.hex(), cand))
                still.discard(d)
                if not still:
                    return found
    return found


def main():
    if len(sys.argv) < 2:
        print("usage: python rule_attack.py <wordlist-path>")
        return
    path = sys.argv[1]

    target_bytes = {bytes.fromhex(h) for h in TARGETS}
    hex_to_user = dict(TARGETS)

    print(f"[*] Salt: {SALT.decode()}")
    print(f"[*] Targets: {list(TARGETS.values())}")
    print(f"[*] Rules: case variants + numeric prefix/suffix up to len {MAX_LEN}")
    print(f"[*] Workers: {NUM_WORKERS}\n")

    with open(path, "rb") as fh:
        words = [ln.rstrip(b"\r\n") for ln in fh if ln.strip()]
    words.extend(EXTRA_BASES)
    print(f"[*] Base words loaded: {len(words):,}")

    chunk = (len(words) + NUM_WORKERS - 1) // NUM_WORKERS
    chunks = [words[i:i + chunk] for i in range(0, len(words), chunk)]

    cracked = {}
    t0 = time.time()
    with Pool(processes=NUM_WORKERS, initializer=_init,
              initargs=(target_bytes, hex_to_user)) as pool:
        for found in pool.imap_unordered(scan_chunk, chunks):
            for hexdigest, cand in found:
                user = hex_to_user.get(hexdigest)
                if user and user not in cracked:
                    cracked[user] = cand
                    print(f"  [+] CRACKED {user:10s} = {cand.decode(errors='replace')!r}")

    print(f"\n[*] Done in {time.time() - t0:.1f}s")
    print("=" * 40)
    for user in TARGETS.values():
        pw = cracked.get(user)
        shown = pw.decode(errors="replace") if pw is not None else "<not recovered>"
        print(f"  {user:10s} -> {shown}")


if __name__ == "__main__":
    main()
