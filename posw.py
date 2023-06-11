#!/usr/bin/env python3

from hashlib import sha256
from typing import Callable

from Crypto.Random.random import randint

RandomOracleType = Callable[[bytes, str, list[str]], str]

class Node:
    def __init__(self, value : int, size : int):
        assert (size == 0 and value == 0) or  value < (1 << size)
        self.value = value
        self.size = size

    def __add__(self, n : int):
        return Node(self.value + n, self.size)

    def __xor__(self, n : int):
        return Node(self.value ^ n, self.size)

    def __lshift__(self, n : int):
        return Node(self.value << n, self.size + n)

    def __rshift__(self, n : int):
        assert n <= self.size
        return Node(self.value >> n, self.size - n)

    def __mod__(self, n : int):
        assert n != 0
        return self.value % n

    def __eq__(self, other) -> bool:
         return type(other) == Node and self.value == other.value and self.size == other.size

    def __hash__(self) -> bool:
        return self.value

    def __str__(self):
        if self.size == 0:
            return "e"
        return bin(self.value)[2:2 + self.size].zfill(self.size)

    def __repr__(self):
        return str(self)

    def next_node(self, max_depth : int) -> tuple:
        if self.value % 2 == 1:
            return Node(self.value >> 1, self.size - 1)
        else:
            return Node((self.value + 1) << (max_depth - self.size), max_depth)

    def is_child_of(self, parent) -> bool:
        if self.size >= parent.size:
            return self.value >> (self.size - parent.size) == parent.value
        return False

def sha256H(chi: bytes, node : str, labels : list[str]) -> str:

    m = sha256()
    m.update(chi)
    m.update(node.encode('utf-8'))
    m.update("".join(labels).encode('utf-8'))

    return m.hexdigest()

def printer(chi : bytes, node : str, labels : list[str]) -> str:
    string = node + "|" if labels else node
    return string + "|".join([label.split("|", 1)[0] for label in labels])

def generate_challenge(N : int, n :int, t : int) -> list[int]:
    challenge = set()
    while len(challenge) < t:
        challenge.add(Node(randint(0, N - 1), n))
    return list(challenge)

def optimized_posw(chi : bytes, n : int, tree : dict[str, str], initial_stack: list[str], missing_labels : set[int], leaf : int, H: RandomOracleType) -> dict[str, str]:
    node = leaf
    label_stack = initial_stack

    # while labels in subtree are still needed
    while (missing_labels):

        if (node.size < n):
            label = H(chi, str(node), label_stack[-2:])
        else:
            label = H(chi, str(node), label_stack)
    
        if node.size < n:
            label_stack.pop()
            label_stack.pop()

        label_stack.append(label)
        
        
        # needed label computed, remove from missing labels
        if str(node) in missing_labels: 
            tree[str(node)] = label
            missing_labels.remove(str(node))

        node = node.next_node(n)
    
    return tree

def open_nodes(chi: bytes, n : int, m : int, tree: dict[str, str], challenge: list[Node], H: RandomOracleType) -> list[tuple[str,dict[str, str]]]:
    
    # nodes needed to answer challenge
    dependencies = {}
    
    # needed labels that are not in memory
    missing_labels = [set() for _ in range(1 << m)] 

    for leaf in challenge:
        subtree = leaf.value >> (n - m) # find which subtree the leaf belongs     
        
        # track node dependencies and missing labels in the depth robust graph
        dependencies[str(leaf)] = []
        
        node = leaf
        missing_labels[subtree].add(str(node))
        
        # discover the path to root for each challenge
        for i in range(n):
            node ^= 1
            
            dependencies[str(leaf)].append(str(node))

            # discover labels that were not saved in posw
            if i < (n - m):
                missing_labels[subtree].add(str(node)) 
                
            node = node >> 1
            
    initial_leaf = Node(0, n)
    
    for i in range(len(missing_labels)):

        if len(missing_labels[i]) == 0:
            if i < len(missing_labels) - 1:
                initial_leaf += 1 << (n - m)
            continue # sub tree not needed

        
        # node parent of the subtree
        parent_node = Node(i, m)
        
        initial_stack = []

        # get parents of first node of subtree
        while(parent_node.size != 0):

            if parent_node % 2 == 1:
                parent_node ^= 1
                initial_stack.insert(0, tree[str(parent_node)])

            parent_node = parent_node >> 1
        

        
        # computes missing labels in subtree
        optimized_posw(chi, n, tree, initial_stack, missing_labels[i], initial_leaf, H)

        if i < len(missing_labels) - 1:
            initial_leaf += 1 << (n - m)

    # constructs replies to challenges
    reply = []
    for leaf in challenge:
        label = tree[str(leaf)]
        path = {}
        
        for path_id in dependencies[str(leaf)]:
            #if path_id != leaf:
            path[path_id] = tree[str(path_id)]
                                    
        
        reply.append((label, path))
    
    return reply

def get_parents(leaf : int, n : int) -> list[str]:
    parents = []
    for _ in range(n):
        if leaf % 2 == 1:
            parents.insert(0, str(leaf ^ 1))
        leaf = leaf >> 1
    
    return parents
    

def verify(chi : bytes, n : int, root : str, challenges : list[Node], reply : list[tuple[str, dict[str, str]]], H) -> bool:

    # verify all replies
    for i in range(len(challenges)):
        leaf = challenges[i]
        parents = get_parents(leaf, n)
        label, root_path_labels = reply[i]

        print(f"Verifying challenge: {leaf}")

        # verify if leaf label is correct
        parent_labels = []
        for parent in parents:
            # check if parent is in reply
            if parent not in root_path_labels:
                print(f"!!!Parent {parent} of node {str(leaf)} not in reply: {root_path_labels.keys()}")
                return False
            parent_labels.append(root_path_labels[parent])
        
        # bad hash
        if label != H(chi, str(leaf), parent_labels):
            print(f"!!!Label of leaf  {str(leaf)} is incorrect.")
            print(f"!!!Expected {label} computed {H(chi, str(leaf), parent_labels)}.")
            return False
        
        # compute and verify if root is correct
        node = leaf
        for _ in range(n):
            sibling = node ^ 1

            # order siblings by the order of posw computation
            if node.value % 2 == 0:
                parents = [label, root_path_labels[str(sibling)]]
            else:
                parents = [root_path_labels[str(sibling)], label]
            
            node = node >> 1
            label = H(chi, str(node), parents)

        if label != root:
            print(f"Commited root: {root}\nComputed root: {label}\n")
            print(f"!!!Root is incorrect from leaf {str(leaf)}.")
            return False
        
        print(f"Verified challenge: {leaf}\n")

    return True 