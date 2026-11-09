"""Off-chain Merkle tree builder for MerkleDistributor.

Uses exactly the same leaf definition as contracts/merkle_distributor.py:
  address: lowercase "0x" + 40 lowercase hex characters.
  amount: decimal integer wei, no leading zeros, as a string.
  leaf preimage: address + ":" + amount.
  leaf hash: SHA-256 hex of the UTF-8 bytes of the preimage.
  internal node: SHA-256 hex of (left_hex + right_hex) as a 128-char
      ASCII string. Proofs carry an explicit "left" bit per step.
  odd node on a level is promoted unchanged (never duplicated).
  single-leaf tree: root == leaf hash, empty proof.

This module uses hashlib (off-chain only). The contract uses a pure
Python SHA-256; tests/test_local.py checks both agree on every
vector, leaf, and internal node used here.
"""

import hashlib
import json


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_lower_address(address):
    if (
        not isinstance(address, str)
        or len(address) != 42
        or not address.startswith("0x")
        or address[2:] != address[2:].lower()
        or any(c not in "0123456789abcdef" for c in address[2:])
    ):
        raise ValueError("leaf_address_must_be_lowercase_0x_hex: " + repr(address))


def check_amount(amount):
    if not isinstance(amount, str) or not amount.isdigit():
        raise ValueError("amount_must_be_decimal_wei: " + repr(amount))
    if len(amount) > 1 and amount.startswith("0"):
        raise ValueError("amount_must_not_have_leading_zeros: " + repr(amount))
    if int(amount) <= 0:
        raise ValueError("amount_must_be_positive: " + repr(amount))


def leaf_hash(address, amount):
    """Leaf hash for one (address, amount) pair. Both are validated."""
    check_lower_address(address)
    check_amount(amount)
    return sha256_hex(address + ":" + amount)


def build_tree(leaves):
    """Build the tree levels from a list of (address, amount) pairs.

    Returns (levels, root) where levels[0] is the list of leaf hashes
    and levels[-1] == [root]. Raises on duplicate leaves.
    """
    if not leaves:
        raise ValueError("tree_needs_at_least_one_leaf")
    hashes = [leaf_hash(address, amount) for address, amount in leaves]
    if len(set(hashes)) != len(hashes):
        raise ValueError("duplicate_leaf_in_tree")
    levels = [hashes]
    current = hashes
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current) - 1, 2):
            nxt.append(sha256_hex(current[i] + current[i + 1]))
        if len(current) % 2 == 1:
            nxt.append(current[-1])
        levels.append(nxt)
        current = nxt
    return levels, levels[-1][0]


def proof_for(levels, index):
    """Merkle proof for the leaf at `index`, as a JSON string.

    Each step is {"sibling": <64 lowercase hex>, "left": <bool>};
    left=true means the sibling sits on the left of the running hash.
    """
    proof = []
    pos = index
    for level in levels[:-1]:
        if pos % 2 == 0:
            if pos + 1 < len(level):
                proof.append({"sibling": level[pos + 1], "left": False})
            # odd last node on this level: promoted unchanged, no step.
        else:
            proof.append({"sibling": level[pos - 1], "left": True})
        pos = pos // 2
    return json.dumps(proof)


def recompute_root(leaf, proof):
    """Recompute the root from a leaf hash and a proof (list of steps)."""
    current = leaf
    for step in proof:
        if step["left"]:
            current = sha256_hex(step["sibling"] + current)
        else:
            current = sha256_hex(current + step["sibling"])
    return current
