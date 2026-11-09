"""Local tests for MerkleDistributor (mock only, NOT consensus evidence).

Builds a stub `genlayer` module, imports the real contract file, and
drives it directly: pure-SHA-256 vectors vs hashlib, leaf/root
agreement with scripts/merkle_lib.py, and the full state machine
(create / claim / withdraw / reclaim / extend) including every
failure mode. On-chain evidence is produced separately by
scripts/flow.mjs against Stable Studionet.
"""

import hashlib
import json
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "contracts"))

# --- stub genlayer -----------------------------------------------------------
genlayer = types.ModuleType("genlayer")


class UserError(Exception):
    pass


class _VM:
    UserError = UserError


class _Write:
    def __call__(self, fn):
        return fn

    @property
    def payable(self):
        return lambda fn: fn


class _Public:
    write = _Write()

    @staticmethod
    def view(fn):
        return fn


class _EVM:
    @staticmethod
    def contract_interface(cls):
        return cls


class _Message:
    sender_address = ""
    value = 0


class _Contract:
    pass


class u256(int):
    pass


def Address(value):
    return value


class _GL:
    Contract = _Contract
    public = _Public()
    vm = _VM()
    message = _Message()
    evm = _EVM()


genlayer.gl = _GL()
genlayer.u256 = u256
genlayer.Address = Address
genlayer.__all__ = ["gl", "u256", "Address"]
sys.modules["genlayer"] = genlayer

import merkle_lib  # noqa: E402
import merkle_distributor as mod  # noqa: E402

GEN = 10 ** 18
CHECKS = [0]


def check(condition, label):
    CHECKS[0] += 1
    if not condition:
        raise AssertionError("CHECK FAILED: " + label)
    print("ok %3d  %s" % (CHECKS[0], label))


def expect_error(fn, code, label):
    CHECKS[0] += 1
    try:
        fn()
    except UserError as exc:
        if ("EXPECTED: " + code) in str(exc):
            print("ok %3d  %s (raised %s)" % (CHECKS[0], label, code))
            return
        raise AssertionError(
            "CHECK FAILED: %s (raised %r, expected %s)" % (label, str(exc), code)
        )
    raise AssertionError("CHECK FAILED: %s (no error raised)" % label)


# --- 1. pure SHA-256 vs hashlib ----------------------------------------------
VECTORS = [
    "",
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "a" * 55,
    "a" * 56,
    "a" * 63,
    "a" * 64,
    "a" * 65,
    "a" * 1000,
    "The quick brown fox jumps over the lazy dog",
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:5000000000000000000",
    "f" * 128,
    "0" * 128,
]
for i, text in enumerate(VECTORS):
    check(
        mod._sha256_hex(text) == hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "sha256 vector %d (len %d)" % (i, len(text)),
    )

# --- 2. merkle_lib agrees with the contract's pure SHA-256 -------------------
ALICE = "0x" + "a" * 40
BOB = "0x" + "b" * 40
CAROL = "0x" + "c" * 40
DAVE = "0x" + "d" * 40
EVE = "0x" + "e" * 40
FRANK = "0x" + "f" * 40
GRACE = "0x" + "1" * 40
CREATOR = "0x" + "9" * 40
STRANGER = "0x" + "2" * 40


def leaves(amounts):
    return [(addr, str(amt * GEN)) for addr, amt in amounts]


for size, members in [
    (1, [(ALICE, 5)]),
    (2, [(ALICE, 5), (BOB, 10)]),
    (3, [(ALICE, 5), (BOB, 10), (CAROL, 15)]),
    (5, [(ALICE, 5), (BOB, 10), (CAROL, 15), (DAVE, 4), (EVE, 10)]),
    (7, [(ALICE, 5), (BOB, 10), (CAROL, 15), (DAVE, 4), (EVE, 10), (FRANK, 10), (GRACE, 1)]),
]:
    lv = leaves(members)
    levels, root = merkle_lib.build_tree(lv)
    check(len(levels[0]) == size, "tree size %d leaf level" % size)
    for idx, (addr, amt) in enumerate(lv):
        lib_leaf = merkle_lib.leaf_hash(addr, amt)
        check(
            mod._leaf_hash(addr, amt) == lib_leaf,
            "tree size %d leaf %d contract==lib" % (size, idx),
        )
        proof = json.loads(merkle_lib.proof_for(levels, idx))
        check(
            mod._recompute_root(lib_leaf, proof) == root,
            "tree size %d leaf %d proof recomputes root" % (size, idx),
        )
        check(
            merkle_lib.recompute_root(lib_leaf, proof) == root,
            "tree size %d leaf %d lib recompute agrees" % (size, idx),
        )

# --- 3. contract state machine ----------------------------------------------
transfers = []
mod._pay = lambda address, amount: transfers.append((address, int(amount)))

contract = mod.MerkleDistributor()
contract.balance = 0
fake_balance = [0]

FAKE_NOW = [1_800_000_000]
mod._now_seconds = lambda: FAKE_NOW[0]


def set_sender(address, value=0):
    genlayer.gl.message.sender_address = address
    genlayer.gl.message.value = value


def totals_ok(label):
    totals = json.loads(contract.get_totals())
    contract.balance = fake_balance[0]
    totals = json.loads(contract.get_totals())
    check(totals["invariant_ok"] is True, label + " invariant_ok")
    check(
        totals["balance_matches_held"] is True,
        label + " balance_matches_held",
    )
    return totals


def credit_of(address):
    return int(json.loads(contract.get_credit(address))["credit_wei"])


# create: bad inputs fail before any write
set_sender(CREATOR, 30 * GEN)
expect_error(
    lambda: contract.create_distribution("A" * 64, str(FAKE_NOW[0] + 3600), "main"),
    "root_must_be_64_lowercase_hex",
    "create rejects uppercase root",
)
expect_error(
    lambda: contract.create_distribution("a" * 64, str(FAKE_NOW[0] - 10), "main"),
    "expiry_must_be_in_the_future",
    "create rejects past expiry",
)
set_sender(CREATOR, 0)
expect_error(
    lambda: contract.create_distribution("a" * 64, str(FAKE_NOW[0] + 3600), "main"),
    "create_requires_positive_value",
    "create rejects zero value",
)
check(
    json.loads(contract.get_count())["distribution_count"] == 0,
    "failed creates wrote nothing",
)

# D0: 3 leaves (Alice 5, Bob 10, Carol 15), funded 30 GEN
levels0, root0 = merkle_lib.build_tree(leaves([(ALICE, 5), (BOB, 10), (CAROL, 15)]))
set_sender(CREATOR, 30 * GEN)
created = json.loads(
    contract.create_distribution(root0, str(FAKE_NOW[0] + 3600), "main")
)
fake_balance[0] += 30 * GEN
check(created["id"] == "0", "D0 id is 0")
check(created["funded_wei"] == str(30 * GEN), "D0 funded 30 GEN")
check(created["creator"] == CREATOR, "D0 creator recorded lowercase")
totals_ok("after D0 create")

# claim Alice (correct proof, from Alice)
proof_alice = merkle_lib.proof_for(levels0, 0)
set_sender(ALICE, 0)
receipt = json.loads(
    contract.claim("0", ALICE, str(5 * GEN), proof_alice)
)
check(receipt["amount_wei"] == str(5 * GEN), "Alice claim credits 5 GEN")
check(credit_of(ALICE) == 5 * GEN, "Alice credit is 5 GEN")
check(
    json.loads(contract.is_claimed("0", receipt["leaf_hash"]))["claimed"] is True,
    "Alice leaf marked claimed",
)
totals_ok("after Alice claim")

# double claim fails, state unchanged
expect_error(
    lambda: contract.claim("0", ALICE, str(5 * GEN), proof_alice),
    "leaf_already_claimed",
    "double claim fails",
)
check(credit_of(ALICE) == 5 * GEN, "double claim credited nothing extra")

# tampered proof fails
bad_proof = json.loads(proof_alice)
bad_proof[0]["sibling"] = ("0" if bad_proof[0]["sibling"][0] != "0" else "1") + bad_proof[0]["sibling"][1:]
set_sender(BOB, 0)
expect_error(
    lambda: contract.claim("0", BOB, str(10 * GEN), json.dumps(bad_proof)),
    "proof_does_not_match_root",
    "tampered proof fails",
)

# wrong amount fails (leaf hash changes, root no longer matches)
proof_bob = merkle_lib.proof_for(levels0, 1)
expect_error(
    lambda: contract.claim("0", BOB, str(11 * GEN), proof_bob),
    "proof_does_not_match_root",
    "wrong amount fails",
)

# checksummed address fails (no normalization)
expect_error(
    lambda: contract.claim("0", "0x" + "B" * 40, str(10 * GEN), proof_bob),
    "leaf_address_must_be_lowercase_0x_hex",
    "checksummed address fails",
)

# proof too long fails
expect_error(
    lambda: contract.claim(
        "0", BOB, str(10 * GEN),
        json.dumps([{"sibling": "a" * 64, "left": False}] * 33),
    ),
    "proof_too_long",
    "33-step proof fails",
)

# Bob claim submitted by a stranger relayer: credit still goes to Bob
set_sender(STRANGER, 0)
receipt = json.loads(contract.claim("0", BOB, str(10 * GEN), proof_bob))
check(receipt["address"] == BOB, "relayed claim credits leaf address")
check(credit_of(BOB) == 10 * GEN, "Bob credit is 10 GEN")
check(credit_of(STRANGER) == 0, "relayer got no credit")

# Carol claim
proof_carol = merkle_lib.proof_for(levels0, 2)
set_sender(CAROL, 0)
contract.claim("0", CAROL, str(15 * GEN), proof_carol)
dist0 = json.loads(contract.get_distribution("0"))
check(dist0["claimed_count"] == 3, "D0 all 3 leaves claimed")
check(dist0["remaining_wei"] == "0", "D0 remaining 0")
totals_ok("after D0 fully claimed")

# verify_proof view: match and mismatch
view = json.loads(
    contract.verify_proof(root0, ALICE, str(5 * GEN), proof_alice)
)
check(view["matches"] is True, "verify_proof matches for good proof")
view = json.loads(
    contract.verify_proof(root0, ALICE, str(6 * GEN), proof_alice)
)
check(view["matches"] is False, "verify_proof mismatches for wrong amount")
leaf_view = json.loads(contract.get_leaf_hash(ALICE, str(5 * GEN)))
check(
    leaf_view["leaf_hash"] == merkle_lib.leaf_hash(ALICE, str(5 * GEN)),
    "get_leaf_hash agrees with lib",
)

# withdraw: Alice pulls her own 5 GEN; second withdraw and stranger fail
set_sender(ALICE, 0)
out = json.loads(contract.withdraw_payout())
check(out["withdrawn_wei"] == str(5 * GEN), "Alice withdraws 5 GEN")
fake_balance[0] -= 5 * GEN
check(transfers[-1] == (ALICE, 5 * GEN), "transfer recorded to Alice")
check(credit_of(ALICE) == 0, "Alice credit zeroed after withdraw")
expect_error(
    lambda: contract.withdraw_payout(),
    "no_credit_to_withdraw",
    "second Alice withdraw fails",
)
set_sender(STRANGER, 0)
expect_error(
    lambda: contract.withdraw_payout(),
    "no_credit_to_withdraw",
    "stranger withdraw fails",
)
# Bob and Carol withdraw
set_sender(BOB, 0)
contract.withdraw_payout()
fake_balance[0] -= 10 * GEN
set_sender(CAROL, 0)
contract.withdraw_payout()
fake_balance[0] -= 15 * GEN
totals_ok("after D0 withdrawals")

# D1: short expiry (Dave 4 GEN, funded 4 GEN)
levels1, root1 = merkle_lib.build_tree(leaves([(DAVE, 4)]))
set_sender(CREATOR, 4 * GEN)
contract.create_distribution(root1, str(FAKE_NOW[0] + 100), "short")
fake_balance[0] += 4 * GEN
check(
    json.loads(contract.get_distribution("1"))["expiry"] == str(FAKE_NOW[0] + 100),
    "D1 expiry recorded",
)
# single-leaf tree: empty proof
proof_dave = merkle_lib.proof_for(levels1, 0)
check(proof_dave == "[]", "single-leaf proof is empty")
FAKE_NOW[0] += 200  # past D1 expiry, D0 still active
set_sender(DAVE, 0)
expect_error(
    lambda: contract.claim("1", DAVE, str(4 * GEN), proof_dave),
    "distribution_expired",
    "expired claim fails",
)
check(
    json.loads(
        contract.is_claimed("1", merkle_lib.leaf_hash(DAVE, str(4 * GEN)))
    )["claimed"]
    is False,
    "expired leaf still unclaimed",
)
# stranger reclaim fails; creator reclaim succeeds
set_sender(STRANGER, 0)
expect_error(
    lambda: contract.reclaim_distribution("1"),
    "only_creator_can_reclaim",
    "stranger reclaim fails",
)
set_sender(CREATOR, 0)
reclaimed = json.loads(contract.reclaim_distribution("1"))
check(reclaimed["reclaimed_wei"] == str(4 * GEN), "creator reclaims 4 GEN")
check(reclaimed["status"] == "RECLAIMED", "D1 status RECLAIMED")
check(credit_of(CREATOR) == 4 * GEN, "creator credited 4 GEN")
expect_error(
    lambda: contract.reclaim_distribution("1"),
    "distribution_not_active",
    "second reclaim fails",
)
expect_error(
    lambda: contract.extend_distribution("1", str(FAKE_NOW[0] + 1000)),
    "distribution_not_active",
    "extend after reclaim fails",
)
totals_ok("after D1 reclaim")

# D2: underfunded (Eve 10 + Frank 10, funded 12 GEN)
levels2, root2 = merkle_lib.build_tree(leaves([(EVE, 10), (FRANK, 10)]))
set_sender(CREATOR, 12 * GEN)
contract.create_distribution(root2, str(FAKE_NOW[0] + 100), "underfunded")
fake_balance[0] += 12 * GEN
set_sender(EVE, 0)
contract.claim("2", EVE, str(10 * GEN), merkle_lib.proof_for(levels2, 0))
check(credit_of(EVE) == 10 * GEN, "Eve claims 10 GEN from underfunded D2")
set_sender(FRANK, 0)
expect_error(
    lambda: contract.claim("2", FRANK, str(10 * GEN), merkle_lib.proof_for(levels2, 1)),
    "insufficient_escrow",
    "late claim fails on underfunded escrow",
)
check(
    json.loads(
        contract.is_claimed("2", merkle_lib.leaf_hash(FRANK, str(10 * GEN)))
    )["claimed"]
    is False,
    "Frank leaf still unclaimed after escrow failure",
)
FAKE_NOW[0] += 200
set_sender(CREATOR, 0)
reclaimed = json.loads(contract.reclaim_distribution("2"))
check(reclaimed["reclaimed_wei"] == str(2 * GEN), "D2 reclaim returns 2 GEN")
check(credit_of(CREATOR) == 6 * GEN, "creator credit now 6 GEN (4 + 2)")
totals_ok("after D2 reclaim")

# D3: extend flow (Grace 1 GEN, funded 1 GEN)
levels3, root3 = merkle_lib.build_tree(leaves([(GRACE, 1)]))
set_sender(CREATOR, 1 * GEN)
contract.create_distribution(root3, str(FAKE_NOW[0] + 100), "extendable")
fake_balance[0] += 1 * GEN
set_sender(STRANGER, 0)
expect_error(
    lambda: contract.extend_distribution("3", str(FAKE_NOW[0] + 500)),
    "only_creator_can_extend",
    "stranger extend fails",
)
set_sender(CREATOR, 0)
expect_error(
    lambda: contract.extend_distribution("3", str(FAKE_NOW[0] + 50)),
    "new_expiry_must_be_later_than_old_expiry",
    "extend to earlier expiry fails",
)
extended = json.loads(
    contract.extend_distribution("3", str(FAKE_NOW[0] + 500))
)
check(
    extended["expiry"] == str(FAKE_NOW[0] + 500),
    "creator extend moves expiry later",
)
set_sender(GRACE, 0)
contract.claim("3", GRACE, str(1 * GEN), merkle_lib.proof_for(levels3, 0))
check(credit_of(GRACE) == 1 * GEN, "Grace claims 1 GEN after extend")
FAKE_NOW[0] += 600
set_sender(CREATOR, 0)
reclaimed = json.loads(contract.reclaim_distribution("3"))
check(reclaimed["reclaimed_wei"] == "0", "fully claimed D3 reclaims 0")
check(reclaimed["status"] == "RECLAIMED", "D3 status RECLAIMED")

# final withdrawals and money check
set_sender(EVE, 0)
contract.withdraw_payout()
fake_balance[0] -= 10 * GEN
set_sender(GRACE, 0)
contract.withdraw_payout()
fake_balance[0] -= 1 * GEN
set_sender(CREATOR, 0)
out = json.loads(contract.withdraw_payout())
check(out["withdrawn_wei"] == str(6 * GEN), "creator withdraws reclaimed 6 GEN")
fake_balance[0] -= 6 * GEN
totals = totals_ok("final")
check(totals["total_received_wei"] == str(47 * GEN), "final received 47 GEN")
check(totals["total_withdrawn_wei"] == str(47 * GEN), "final withdrawn 47 GEN")
check(totals["credits_outstanding_wei"] == "0", "final credits 0")
check(totals["escrow_locked_wei"] == "0", "final escrow 0")
check(totals["contract_balance_wei"] == "0", "final contract balance 0")
check(
    [t for t in transfers] == [
        (ALICE, 5 * GEN), (BOB, 10 * GEN), (CAROL, 15 * GEN),
        (EVE, 10 * GEN), (GRACE, 1 * GEN), (CREATOR, 6 * GEN),
    ],
    "transfer log is exactly the six pull payments",
)
listed = json.loads(contract.list_distributions("0", "20"))
check(len(listed) == 4, "list_distributions returns 4")
check(
    [d["status"] for d in listed] == ["ACTIVE", "RECLAIMED", "RECLAIMED", "RECLAIMED"],
    "final distribution statuses",
)
expect_error(
    lambda: contract.get_distribution("99"),
    "distribution_not_found",
    "unknown distribution fails",
)
expect_error(
    lambda: contract.list_distributions("0", "21"),
    "limit_must_be_1_to_20",
    "list limit 21 fails",
)

print("ALL %d CHECKS PASSED" % CHECKS[0])
