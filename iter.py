import json as mnel

def printer(list):
    return "|".join(list)


def next_node(id : str, n : int):
    if id[-1] == '1':
        return id[:-1]
    else:
        return (id[:-1] + "1").ljust(n, '0')
        #return id[:-1] + "1" + "0" * (n - len(id))

def compute(id, n, hash_function = None):
    parent_labels = []

    while (id != ""):
        print(id)
        print(f"{parent_labels= }")

        if (len(id) < n):
            debug_tree[id] = hash_function([id] + parent_labels[-2:])
        else:
            debug_tree[id] = hash_function([id] + parent_labels)

        if (len(id) < n):
            parent_labels.pop()
            parent_labels.pop()

        parent_labels.append(id)

        id = next_node(id, n)

n = int(input("depth n: "))

debug_tree = {}

compute("0"*n, n, printer)

print (mnel.dumps(debug_tree, indent=2))

