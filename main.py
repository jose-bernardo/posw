#!/usr/bin/env python3

from hashlib import sha256
from typing import Callable
import json as mnel

from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

RandomOracleType = Callable[[bytes, str, list[str]], str]

#ROOT = ""
ROOT = "0b1"

# class Node:
#     def __init__(self, value : int, size : int):
#         self.value = value
#         self.size = size
 
#     def __add__(self, n : int):
#         return self.value + n
    
#     def __sub__(self, n : int):
#         return self.value - n
    
#     def __lshift__(self, n : int):
#         return self.value - n
    
#     def __rshift__(self, n : int):
#         return self.value - n
    
#     def __mod__(self, n : int):
#         return self.value - n

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
    return str(bin(node)) #[3:]

def next_node(id : int, size : int, n : int) -> tuple:

    if id % 2 == 1:
        return (id >> 1, size - 1)
    else:
        return ((id + 1) << (n - size), n)

def posw(chi: bytes, n : int, m : int, H: RandomOracleType) -> dict[str, str]:
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
        
        tree[str_node(id)] = label # TODO TMP

        if id == 0b101:
            print(f"\n VAI DAR AQUI BARRACA {str_node(id)}\n label: {label}\n\
                  {label_stack = }\n\
                  {chi = } \n")
        
        if size < n:
            label_stack.pop()
            label_stack.pop()

        label_stack.append(label)

#        print(f"og node: {id=} {size=}")
        id, size = next_node(id, size, n)
#        print(f"next node: {id=} {size=}")

    return tree

def generate_challenge(N : int, n :int, t : int) -> list[int]:
    challenge = set()
    while len(challenge) < t:
        #challenge.add((1 << n) + randint(0, N - 1))
        challenge.add(randint(0, N - 1))
    return list(challenge)
    #return sample(range(0, N), t)

def outerspace_posw(chi : bytes, n : int, tree : dict[str, str], initial_stack: list[str], needed_labels : set[int], leaf : int, H: RandomOracleType) -> dict[str, str]:
    id = leaf
    size = n

    labels = {}
    #id >> (n - size) + 1
    label_stack = initial_stack

    while (needed_labels):
        
        # print(f"current node: {str_node(id)}")
        # print(f"{label_stack = }")
        # print(f"needed labels: {list(map(str_node, needed_labels))}")

        if (size < n):
            label = H(chi, str_node(id), label_stack[-2:])
            # label_stack.pop()
            # label_stack.pop()
        else:
            label = H(chi, str_node(id), label_stack)

 

        if str_node(id) in tree:
            print(f"\nBARRACA TOTAL {str_node(id)}\n prev: {tree[str_node(id)]} \nnew: {label}\n\
                  {label_stack = }\n \
                  {chi = }\n")
        
        if size < n:
            label_stack.pop()
            label_stack.pop()

        label_stack.append(label)

        
        
        tree[str_node(id)] = label

        if id in needed_labels:
            tree[str_node(id)] = label
            needed_labels.remove(id)
#        print(f"og node: {id=} {size=}")
        id, size = next_node(id, size, n)
#        print(f"next node: {id=} {size=}")
    
    # print("Tree: " + mnel.dumps(tree, indent=2))

    return tree

def open_nodes(chi: bytes, n : int , m : int, tree: dict[str, str], challenge: list[int], H: RandomOracleType) -> list[tuple[str,dict[str, str]]]:

    needed_labels = [set() for _ in range(1 << m)]
    dic = {}
    for og_id in challenge:
        
        bucket_id = og_id >> (n - m)

        og_id = (1 << n) + og_id
        id = og_id

        og_id = str_node(og_id)

        dic[og_id] = [id]       

        #bucket_id = (id ^ (1 << (n))) // (1 << m)
        # print(bucket_id)
        needed_labels[bucket_id].add(id)
        for i in range(n):
            id ^= 1
            if i <  (n - m):
                # print(str_node(id))
                needed_labels[bucket_id].add(id)
                #needed_labels[((id ^ (1 << (n - i))) >> (m - i))].add(id)
            dic[og_id].append(id)
            
            id = id >> 1
            
    print(f"path nodes: {dic}")
    
    initial_leaf = (1 << n)
    
    for i in range(len(needed_labels)):
        
        parent_node = i + (1 << m)
        initial_stack = []

        # if parent_node % 2 == 1:
        #     parent_node ^= 1
        #     initial_stack.append(tree[str_node(parent_node)])
        
        while(parent_node > 1): # not the empty number
            if parent_node % 2 == 1:
                parent_node ^= 1
                print(f"parent_node era impar: {str_node(parent_node)}")
                initial_stack.insert(0, tree[str_node(parent_node)])

            
            parent_node = parent_node >> 1
        
        print(f"{i = }\n {initial_stack = }\n \
              initial leaf = {str_node(initial_leaf)}\n\
              needed labels ={list(map(str_node, needed_labels[i]))}")
        
        outerspace_posw(chi, n, tree, initial_stack, needed_labels[i], initial_leaf, H)

        initial_leaf += 1 << ((n - m))
    
    print("Tree: " + mnel.dumps(tree, indent=2))

    reply = []
    for id in challenge:
        id = (1 << n ) + id
        label = tree[str_node(id)]
        path = {}
        
        for path_id in dic[str_node(id)]:
            if path_id != id:
                path[str_node(path_id)] = tree[str_node(path_id)]
        
        reply.append((label, path))
    
    return reply

def get_parents(leaf : int, n : int) -> list[str]:
    parents = []
    original_leaf = leaf
    for _ in range(n):
        if leaf % 2 == 1:
            parents.insert(0, str_node(leaf ^ 1))
        leaf = leaf >> 1
    
    print(f"Parents of {str_node(original_leaf)} : {parents}")
    return parents
    

def verify(chi : bytes, n : int, root : str, challenges : list[int], reply : list[tuple[str, dict[str, str]]], H) -> bool:

    for i in range(len(challenges)):
        leaf = (1 << n)  + challenges[i]
        parents = get_parents(leaf, n)
        label, path_labels = reply[i]
        
        # verify if leaf label is correct
        parent_labels = []
        for parent in parents:
            if parent not in path_labels:
                print(f"Parent {parent} of node {str_node(leaf)} not in reply: {path_labels.keys()}")
                return False
            parent_labels.append(path_labels[parent])
        
        if label != H(chi, str_node(leaf), parent_labels):
            print(f"Label of leaf  {str_node(leaf)} is incorrect.")
            print(f"Expected {label} computed {H(chi, str_node(leaf), parent_labels)}.")
            return False
        
        # verify if root is correct
        node = leaf
        for _ in range(n):
            sibling = node ^ 1
            if node % 2 == 0:
                parents = [label, path_labels[str_node(sibling)]]
            else:
                parents = [path_labels[str_node(sibling)], label]
            
            node = node >> 1
            label = H(chi, str_node(node), parents)

            # print(f"node = {str_node(node)} {label = }")
            
        if label != root:
            print(f"{label = } {root = }")
            print(f"Root is incorrect from leaf {str_node(leaf)}.")
            return False

    return True



def main():
    # change to args
    n = int(input("Tree depth n: "))
    N = 1 << (n + 1) - 1

    w = 256
    chi = get_random_bytes(w//8)
    # chi = b'\xb3\x81\xa5\xaf\xb1\xee$\xb8\xc7JE\xc3"o\x08\xc4\x17(]\'\x07i|*\xb1\x1bB\xf3\xa0\x82\x03\''
    #print(f"{chi}")
    #chi = b'"\x94\xd0%\xd1:\xd6\xf9\x9d\xc4B\xf1e\xed\xda\x1bV\x94\xfc\xad=\xf9\xf6\x01\xf7\x07N\x061\x84O\x1b'
    t = int(input("Security parameter t: "))
    if ( t > 1 << n):
        print("** Security parameter t lowered to number of leafs 2**n")
        t = 1 << n
        print(f"** Updated t to: {t}", )

    m = int(input("Memory tree depth m: "))
    
    M =  (t + n * t + 1 + 1 << (m+1)) * w

    if input("printer mode(Y/n): " ).casefold() == "y":
        hash_f = printer
    else:
        hash_f = sha256H

    print("\nParameters: ")
    print(f"{n=}")
    print(f"{N=}")
    print(f"{t=}")
    print(f"{m=}")
    print(f"{M=}\n")

    tree = posw(chi, n, m, hash_f)    

    print("Tree: " + mnel.dumps(tree, indent=2))
    challenge = generate_challenge(N, n, t)
    #challenge = [3]
    print(f"challenge: {list(map(bin, challenge))}")
    #print(f"{challenge=}")
    

    reply = open_nodes(chi, n, m, tree, challenge, hash_f)
    print(f"{reply=}")

    result = verify(chi, n, tree[ROOT], challenge, reply, hash_f)
    
    if (result):
        print("Verify succeeded")
    else:
        print("Verify failed")


if __name__ == "__main__":
    main()