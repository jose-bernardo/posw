# posw
Implementation of Proof of Sequential Work

### Setup

`pip install -r requirements.txt`

### Usage

honest.py refers to our normal implementation of proof of sequential work.

`./honest.py <tree depth n> <security parameter t> <memory depth m> [printer/sha256]`

dishonest.py refers to an intentional malicious version that tries to bypass the implemented protocol by computing only part of the DAG.

`./dishonest.py <tree depth n> <security parameter t> <memory depth m> <number of cheating nodes> [printer/sha256]`
