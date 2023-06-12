#!/usr/bin/env python3

from posw import Node, RandomOracleType
from posw import generate_challenge, open_nodes, verify, printer, sha256H

import json
import sys

from Crypto.Random import get_random_bytes

def posw(chi: bytes, n : int, m : int, H: RandomOracleType) -> dict[str, str]:
    tree = {}
    node = Node(0,n) # initial leaf {0}*n

    label_stack = []

    while (node.size > 0):

        if (node.size < n):
            label = H(chi, str(node), label_stack[-2:])
        else:
            label = H(chi, str(node), label_stack)

        if node.size <= m: # don't save if no memory
            tree[str(node)] = label

        if node.size < n:
            label_stack.pop()
            label_stack.pop()
        
        label_stack.append(label)

        node = node.next_node(n)

    label = H(chi, str(node), label_stack)
    tree[str(node)] = label
    
    return tree

"""
N The time parameter which we assume is of the form N = 2**(n+1) - 1 for
an integer n ∈ N.
H : {0, 1} ≤ w(n+1) → {0, 1}
w the hash function, which for the security proof
is modelled as a random oracle, and which takes as inputs strings of
length up to w(n + 1) bits.
t A statistical security parameter.
M Memory available to P, we assume it's of the form
M = (t + n · t + 1 + 2**(m+1))w
"""

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <tree depth \"n\"> <security parameter \"t\"> <memory depth \"m\"> [printer/sha256]")
        sys.exit(1)
    
    n = int(sys.argv[1]) # Tree depth    
    t = int(sys.argv[2]) # Security parameter (number of challenges)
    m = int(sys.argv[3]) # Memory Tree Depth

    if (t < 0 or n < 0 or m < 0):
        print(f"Parameters must be non negative integers")
        print(f"Usage: {sys.argv[0]} <tree depth \"n\"> <security parameter \"t\"> <memory depth \"m\"> [printer/sha256]")
        return 

    if (t > (1 << n)):
        print("** Security parameter t lowered to number of leafs 2**n")
        t = 1 << n
        print(f"** Updated t to: {t}", )
    
    if (m > n):
        print("** Memory depth m lowered to tree depth n")
        m = n
        print(f"** Updated m to: {n}", )

    w = 256
    N = 1 << (n + 1) - 1
    M =  (t + n * t + 1 + 1 << (m+1)) * w

    chi = get_random_bytes(w//8)

    if len(sys.argv) >= 5 and sys.argv[4].casefold() == "printer":
        hash_f = printer
    else:
        hash_f = sha256H

    print("\nUsing the following parameters: ")
    print(f"{n=}")
    print(f"{N=}")
    print(f"{t=}")
    print(f"{m=}")
    print(f"{M=}")
    print(f"{chi=}\n")

    tree = posw(chi, n, m, hash_f)

    print("DAG: " + json.dumps(tree, indent=2))
    print("Root computed!\n")

    challenge = generate_challenge(N, n, t)
    print(f"Generated challenge: {challenge}\n")

    reply = open_nodes(chi, n, m, tree, challenge, hash_f)

    print("Reply: " + json.dumps(reply, indent=2))
    print("Open computed!\n")

    ROOT = "e"
    result = verify(chi, n, tree[ROOT], challenge, reply, hash_f)
    
    if (result):
        print("Verify succeeded")
    else:
        print("Verify failed")

if __name__ == "__main__":
    main()