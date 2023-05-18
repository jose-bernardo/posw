#!/usr/bin/env python3

from Crypto.Random import get_random_bytes
from hashlib import sha256

import json as mnel


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


def sha256H(chi: bytes, b: bytes) -> str:

    m = sha256()
    m.update(chi)
    m.update(b)

    return m.hexdigest() 

def printer(labels):
    return "|".join(map(lambda id : str(bin(id)[3:]), labels))

def main():
    n = int(input("depth n: "))
    chi = get_random_bytes(32)

    debug_tree = compute(n, chi, sha256H)
    print(mnel.dumps(debug_tree, indent=2))

def str_node(node : int):
    return str(bin(node))[3:]

def next_node(id : int, size : int, n : int):
    
    # 0001 -> 000

    # size = 1
    # n = 4

    # 0 -> 1000
    # 0 + 1 = 1
    # 1000

    # 1 << size ^ id

    # id -> 00000
    # id -> 0

    #print_node(id)
    #print_node(id + 1)
    #print(f"{id=} {n=} {size=}")
    #print_node(id + 1)
    #print()
    if id % 2 == 1:
        return (id >> 1, size - 1)
    else:
        return ((id + 1) << (n - size), n)
    #(id[:-1] + "1").ljust(n, '0')
        #return id[:-1] + "1" + "0" * (n - len(id))

def compute(n : int, chi : bytes, H=sha256H):
    debug_tree = {}
    id = 1 << n
    size = n

    parent_labels = []
    
    while (size >= 0):
        print(id)
        print(f"{parent_labels= }")

        to_hash = str(id) + ''.join(map(str_node, parent_labels))
        if (size < n):
            #parent_tables[-2]
            debug_tree[str_node(id)] = H(chi, to_hash.encode())
        else:
            #parent_tables
            debug_tree[str_node(id)] = H(chi, to_hash.encode())

        if (size < n):
            parent_labels.pop()
            parent_labels.pop()

        parent_labels.append(id)

        print(f"og node: {id=} {size=}")
        id, size = next_node(id, size, n)
        print(f"next node: {id=} {size=}")

    return debug_tree


if __name__ == "__main__":
    main()
