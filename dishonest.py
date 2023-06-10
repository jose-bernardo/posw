#!/usr/bin/env python3

from main import Node, RandomOracleType
from main import generate_challenge, open_nodes, verify, printer, sha256H

import json
import sys

from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

def dishonest_posw(chi: bytes, n : int, m : int, cheat_nodes : set[Node], H: RandomOracleType) -> dict[str, str]:
    tree = {}
    node = Node(0,n) # initial leaf {0}*n

    label_stack = []
    
    while (node.size > 0):

        for cheat_node in cheat_nodes:
            # dishonest
            if (node.is_child_of(cheat_node)):
                label = H(chi, "banana" + str(cheat_node), [])
                
                if cheat_node.size <= m: # don't save if no memory
                    tree[str(cheat_node)] = label
                
                label_stack.append(label)

                node = cheat_node.next_node(n)
                break
        else:
            # honest
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
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <tree depth \"n\"> <security parameter \"t\"> <memory depth \"m\"> <number of cheating nodes> [printer/sha256]")
        sys.exit(1)
    
    n = int(sys.argv[1]) # Tree depth    
    t = int(sys.argv[2]) # Security parameter (number of challenges)
    m = int(sys.argv[3]) # Memory Tree Depth
    num_cheat = int(sys.argv[4]) # Number Tree Depth

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

    if (num_cheat > (1 << m)):
        print("** Number of cheating nodes to lowered to 2**m")
        num_cheat = 1 << m

    w = 256
    N = 1 << (n + 1) - 1
    M =  (t + n * t + 1 + 1 << (m+1)) * w

    chi = get_random_bytes(w//8)

    cheat_nodes = set()
    while len(cheat_nodes) < num_cheat:
        cheat_nodes.add(Node(randint(0, (1 << m) - 1), m))
    
    if sys.argv[-1].casefold() == "printer":
        hash_f = printer
    else:
        hash_f = sha256H

    print("\nUsing the following parameters: ")
    print(f"{n=}")
    print(f"{N=}")
    print(f"{t=}")
    print(f"{m=}")
    print(f"{M=}")
    print(f"{chi=}")
    print(f"Cheating Nodes: {cheat_nodes}\n")

    tree = dishonest_posw(chi, n, m, cheat_nodes, hash_f)
    print("DAG: " + json.dumps(tree, indent=2))
    print("Root computed!\n")

    challenge = generate_challenge(N, n, t)
    print(f"Generated challenge: {challenge}\n")

    reply = open_nodes(chi, n, m, tree, challenge, hash_f)

    print("Reply: " + json.dumps(reply, indent=2))
    print("Open computed!\n")

    ROOT = "e"
    
    print(f"Cheating Nodes: {cheat_nodes}\n")
    result = verify(chi, n, tree[ROOT], challenge, reply, hash_f)
    
    if (result):
        print("Verify succeeded")
    else:
        print("Verify failed")

if __name__ == "__main__":
    main()