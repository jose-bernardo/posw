#!/usr/bin/env python3

from hashlib import sha256
import json as mnel

from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint



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
    return str(bin(node))[3:]

def next_node(id : int, size : int, n : int) -> tuple:

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

def generate_challenge(N : int, n :int, t : int) -> list[int]:
    challenge = set()
    while len(challenge) < t:
        #challenge.add((1 << n) + randint(0, N - 1))
        challenge.add(randint(0, N - 1))
    return list(challenge)
    #return sample(range(0, N), t)

#
# 
# labels necessarios para folha n: 
# n ^ 1
# guardar
# n >> 1 
# repetir
#
# 0000 -> 0001 
# 01
# 0100

# while n != £
#     xor
#     guarda
#     shift

# 0000 -> precisa destes todos: 0001, 001, 01, 1
# 0001 -> 0000, 001, 01, 1

# 0010 -> rpecisa -> 0011, 000, 01, 1

# se o nó pertence ao set(001, 001, 01, 1, 0011, 000, 01, 1)
# se sim, entao guarda a hash para enviarmos depois
# se for uma caca
# compute a arvore: if label in needed_labels, guarda sff.

def outerspace_posw(n : int, m : int, chi : bytes, tree : dict[str, str], H=sha256H) -> dict[str, str]:
    id = 1 << m
    size = n

    #id >> (n - size) + 1
    label_stack = []

    while (size >= 0):
        # print(str_node(id))
        # print(f"{label_stack= }")

        if (size < n):
            label = H(chi, str_node(id), label_stack[-2:])
        else:
            label = H(chi, str_node(id), label_stack)

        if size < n:
            label_stack.pop()
            label_stack.pop()

        label_stack.append(label)

#        print(f"og node: {id=} {size=}")
        id, size = next_node(id, size, n)
#        print(f"next node: {id=} {size=}")

    return tree

def open_nodes(tree: dict[str, str], challenge: list[int], n : int, m : int) -> list[tuple[str,dict[str, str]]]:

    needed_labels = [set() for _ in range(1 << m)]
    dic = {}
    for og_id in challenge:
        
        bucket_id = og_id >> (n - m)

        og_id = (1 << n) + og_id
        id = og_id

        og_id = str_node(og_id)

        dic[og_id] = [id]       

        #bucket_id = (id ^ (1 << (n))) // (1 << m)
        print(bucket_id)
        for i in range(n):
            id ^= 1
            if i <  (n - m):
                print(str_node(id))
                needed_labels[bucket_id].add(id)
                #needed_labels[((id ^ (1 << (n - i))) >> (m - i))].add(id)
            dic[og_id].append(id)
            
            id = id >> 1
    
    print(dic)
    for bucket in needed_labels:
        print(list(map(str_node, bucket)))

    # m = n case only
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
    
    
    

def verify(chi : bytes, n : int, root : str, challenges : list[int], reply : list[tuple[str, dict[str, str]]], H=sha256H) -> bool:

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

            print(f"node = {str_node(node)} {label = }")
            
        
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

    tree = posw(n, m, chi, hash_f)    

    print("Tree: " + mnel.dumps(tree, indent=2))
    challenge = generate_challenge(N, n, t)

    print(list(map(bin, challenge)))
    #print(f"{challenge=}")
    

    reply = open_nodes(tree, challenge, n, m)
    print(f"{reply=}")

    result = verify(chi, n, tree[""], challenge, reply, hash_f)
    
    if (result):
        print("Verify succeeded")
    else:
        print("Verify failed")


if __name__ == "__main__":
    main()