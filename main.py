#!/usr/bin/env python3

from Crypto.Random import get_random_bytes
from Crypto.Random.random import sample, randint
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
    
    if id % 2 == 1:
        return (id >> 1, size - 1)
    else:
        return ((id + 1) << (n - size), n)

def posw(n : int, m : int, chi : bytes, H=sha256H) -> dict[str, str]:
    tree = {}
    id = 1 << n
    size = n

    label_stack = []
    
    while (size >= 0):
        # print(str_node(id))
        # print(f"{label_stack= }")

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

def generate_challenge(N : int, t : int) -> list[int]:
    challenge = set()
    while len(challenge) < t:
         challenge.add(randint(0, N - 1))
    return challenge
    #return sample(range(0, N), t)

def open(tree: dict[str, str], challenge: list[int]) -> list[str]:
    labels = [] 
    for leaf in challenge:
        labels.append(tree[str(bin(leaf))[3:]])
    return labels

def verify():
    pass

def main():
    # change to args
    n = int(input("Tree depth n: "))
    N = 1 << (n + 1) - 1
    
    w = 256
    chi = get_random_bytes(w//8)
    
    t = int(input("Security parameter t: "))
    
    if ( t > 1 << n):
        print("** Security parameter t lowered to number of leafs 2**n")
        t = 1 << n
        print(f"** Updated t to: {t}", )

    m = int(input("Memory tree depth m: "))
    
    M =  (t + n * t + 1 + 1 << (m+1)) * w

    if input("printer mode(Y/n): " ).casefold() == "y":
        f = printer
    else:
        f = sha256H
    

    print("\nParameters: ")
    print(f"{n=}")
    print(f"{N=}")
    print(f"{t=}")
    print(f"{m=}")
    print(f"{M=}\n")

    #tree = compute_posw(n, m, chi, f)    
    
    #print(mnel.dumps(tree, indent=2))
    challenge = generate_challenge(N, t)
    print(challenge)
    print(len(challenge))


if __name__ == "__main__":
    main()