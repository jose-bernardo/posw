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


def sha256H(chi: bytes, node : str, labels : list[str]) -> str:

    m = sha256()
    m.update(chi)
    m.update(node.encode('utf-8'))
    m.update("".join(labels).encode('utf-8'))

    return m.hexdigest() 

def printer(chi : bytes, node : str, labels : list[str]) -> str:
    string = node + "|" if labels else node
    return string + "|".join([label.split("|", 1)[0] for label in labels])



def str_node(node : int) -> str:
    return str(bin(node))[3:]

def next_node(id : int, size : int, n : int) -> int:
    
    # 0001 -> 000

    # size = 1
    # n = 4

    # 0 -> 1000
    # 0 + 1 = 1
    # 1000

    # 1 << size ^ id

    # id -> 00000
    # id -> 0

    if id % 2 == 1:
        return (id >> 1, size - 1)
    else:
        return ((id + 1) << (n - size), n)

def compute(n : int, m : int, chi : bytes, H=sha256H) -> dict[str, str]:
    tree = {}
    id = 1 << n
    size = n

    label_stack = []
    
    while (size >= 0):
        print(str_node(id))
        print(f"{label_stack= }")

        #to_hash = str(id) + ''.join(map(str_node, label_stack))
        #print(f"{to_hash=}")
        if (size < n):
            label = H(chi, str_node(id), label_stack[-2:])
        else:
            label = H(chi, str_node(id), label_stack)

        if size <= m : 
            tree[str_node(id)] = label 

        if size < n:
            label_stack.pop()
            label_stack.pop()

        label_stack.append(label)

#        print(f"og node: {id=} {size=}")
        id, size = next_node(id, size, n)
#        print(f"next node: {id=} {size=}")
    
    return tree

def main():
    n = int(input("tree depth n: "))

    chi = get_random_bytes(32)

    m = int(input("memory tree depth m: "))

    if input("printer mode(Y/n): " ).casefold() == "y":
        f = printer
    else:
        f = sha256H
    
    tree = compute(n, m, chi, f)

    print(mnel.dumps(tree, indent=2))


if __name__ == "__main__":
    main()
