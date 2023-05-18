#!/usr/bin/env python3

from Crypto.Random import get_random_bytes
from hashlib import sha256
from math import log2

"""
N The time parameter which we assume is of the form N = 2n+1 − 1 for
an integer n ∈ N.
H : {0, 1} ≤ w(n+1) → {0, 1}
w the hash function, which for the security proof
is modelled as a random oracle, and which takes as inputs strings of
length up to w(n + 1) bits.
t A statistical security parameter.
M Memory available to P, we assume it’s of the form
M = (t + n · t + 1 + 2m+1)w

"""

def H(b: bytes) -> bytes:

    m = sha256()
    #m.update(get_random_bytes(32))
    m.update(b"secret")
    m.update(b)

    return m.digest() 

def main():
    #n = int(input("depth n: "))
    n = 4
    #print("n:", n)

    #t = int(input("security t: "))
    #t = 0
    #print("t:", t)

    #w = 32
    #X = get_random_bytes(w)

    #N = (1 << n + 1) - 1

    h = compute_hash(n, 1, [])
    print(h)

def compute_hash(n: int, id: int, leaves):
    if n < 0:
        return b"";

    l = compute_hash(n - 1, id << 1, leaves)
    r = compute_hash(n - 1, (id << 1) + 1, leaves)

    print(str(bin(id)))

    s = l + r

    if n == 0:
        leaves.append(id)

    if id % 2 == 0:
        s += b''.join(list(map(H, map(bytes, leaves))))

    return H(s)

if __name__ == "__main__":
    main()
