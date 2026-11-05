#!/usr/bin/env python3
import hashlib
import sys
import time

SALT = b"www.exploringsecurity.com"

TARGETS = {
    "2834da08d58330d8dafbb2ac1c0f85f6b3b135ef": "Sparky",
    "f44f3b09df53c1c11273def13cacd8922a86d48c": "JillC",
}


def variants(word):
    yield word
    yield word.lower()
    yield word.capitalize()
    yield word.upper()


def main():
    if len(sys.argv) < 2:
        print("usage: python wordlist_attack.py <wordlist-path>")
        return
    path = sys.argv[1]

    remaining = dict(TARGETS)
    cracked = {}
    sha1 = hashlib.sha1
    salt = SALT
    count = 0
    t0 = time.time()

    print(f"[*] Salt: {salt.decode()}")
    print(f"[*] Targets: {list(TARGETS.values())}")
    print(f"[*] Wordlist: {path}\n")

    with open(path, "rb") as fh:
        for line in fh:
            word = line.rstrip(b"\r\n")
            if not word:
                continue
            seen = set()
            for cand in variants(word):
                if cand in seen:
                    continue
                seen.add(cand)
                count += 1
                digest = sha1(salt + cand).hexdigest()
                if digest in remaining:
                    user = remaining.pop(digest)
                    cracked[user] = cand
                    print(f"  [+] CRACKED {user:10s} = {cand.decode(errors='replace')!r}")
            if not remaining:
                break

    print(f"\n[*] Tried ~{count:,} candidates in {time.time() - t0:.1f}s")
    print("=" * 40)
    for user in TARGETS.values():
        pw = cracked.get(user)
        shown = pw.decode(errors="replace") if pw is not None else "<not recovered>"
        print(f"  {user:10s} -> {shown}")


if __name__ == "__main__":
    main()
