# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""MerkleDistributor: a deterministic Merkle-proof payout primitive.

A creator funds a distribution with real GEN and publishes one Merkle
root on-chain. Each leaf commits to exactly one (address, amount) pair.
A claim carries the leaf data and a Merkle proof; the contract
recomputes the root from the leaf and the proof and compares it with
the stored root, byte for byte. A match credits the exact leaf amount
to the leaf address, once. A mismatch fails before any state is
written. Payouts are pull payments only. After expiry the creator can
reclaim the unclaimed remainder (or extend the window while active);
no funds are ever locked without an exit.

There is no LLM verdict and no external evidence surface. Consensus
decides one deterministic question only: does this leaf + proof
recompute to the stored root? Every comparison is exact, so the
worst-case spread between two passing inputs is 0 wei and 0 seconds.

Leaf construction (exact, shared with the off-chain generator):
  address: lowercase "0x" + 40 lowercase hex characters (42 chars).
      Any other spelling is rejected, never normalized.
  amount: decimal integer wei, no leading zeros, as a string.
  leaf preimage: address + ":" + amount.
  leaf hash: SHA-256 hex of the UTF-8 bytes of the preimage.
  internal node: SHA-256 hex of (left_hex + right_hex) as a 128-char
      ASCII string. The proof carries an explicit "left" bit per step.
  odd node on a level is promoted unchanged (never duplicated).
  single-leaf tree: root == leaf hash, empty proof.
  maximum proof length: 32 steps.

SHA-256 inside this contract is pure Python (no assumption that
GenVM provides hashlib). It is checked against hashlib test vectors
locally before deployment.

Money invariant, readable at any time with get_totals:
    total_received_wei == total_withdrawn_wei
                         + credits_outstanding_wei
                         + escrow_locked_wei
and the contract balance equals credits outstanding plus escrow
locked (every wei the contract still holds is owed to someone or
locked for an active distribution).
"""

import json
from datetime import datetime, timezone

from genlayer import *

MAX_PROOF_LENGTH = 32
MAX_LABEL_LENGTH = 120
_HEX_DIGITS = "0123456789abcdef"

# ---------------------------------------------------------------------------
# Pure-Python SHA-256 (FIPS 180-4). No stdlib hashlib is assumed.
# ---------------------------------------------------------------------------

_SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _rotr32(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF


def _sha256_hex(text):
    """SHA-256 of the UTF-8 bytes of `text`, as 64 lowercase hex chars."""
    data = bytearray(text.encode("utf-8"))
    bit_length = len(data) * 8
    data.append(0x80)
    while (len(data) % 64) != 56:
        data.append(0x00)
    for shift in (56, 48, 40, 32, 24, 16, 8, 0):
        data.append((bit_length >> shift) & 0xFF)
    state = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]
    for block_start in range(0, len(data), 64):
        words = [0] * 64
        for i in range(16):
            j = block_start + i * 4
            words[i] = (
                (data[j] << 24)
                | (data[j + 1] << 16)
                | (data[j + 2] << 8)
                | data[j + 3]
            )
        for i in range(16, 64):
            s0 = (
                _rotr32(words[i - 15], 7)
                ^ _rotr32(words[i - 15], 18)
                ^ (words[i - 15] >> 3)
            )
            s1 = (
                _rotr32(words[i - 2], 17)
                ^ _rotr32(words[i - 2], 19)
                ^ (words[i - 2] >> 10)
            )
            words[i] = (words[i - 16] + s0 + words[i - 7] + s1) & 0xFFFFFFFF
        a, b, c, d, e, f, g, h = state
        for i in range(64):
            big_s1 = (
                _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
            )
            ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
            temp1 = (h + big_s1 + ch + _SHA256_K[i] + words[i]) & 0xFFFFFFFF
            big_s0 = (
                _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
            )
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (big_s0 + maj) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        state = [
            (state[0] + a) & 0xFFFFFFFF,
            (state[1] + b) & 0xFFFFFFFF,
            (state[2] + c) & 0xFFFFFFFF,
            (state[3] + d) & 0xFFFFFFFF,
            (state[4] + e) & 0xFFFFFFFF,
            (state[5] + f) & 0xFFFFFFFF,
            (state[6] + g) & 0xFFFFFFFF,
            (state[7] + h) & 0xFFFFFFFF,
        ]
    out = []
    for word in state:
        for shift in (28, 24, 20, 16, 12, 8, 4, 0):
            out.append(_HEX_DIGITS[(word >> shift) & 0xF])
    return "".join(out)


# ---------------------------------------------------------------------------
# Deterministic helpers (pure functions; no floats anywhere).
# ---------------------------------------------------------------------------


def _fail(code):
    raise gl.vm.UserError("EXPECTED: " + code)


def _ws(number):
    """Wei integer -> decimal string (exact; JSON numbers would round)."""
    return str(int(number))


def _wn(text):
    return int(text)


def _now_seconds():
    # The documented clock path: the stdlib clock is pinned to the
    # transaction datetime, identical for every validator.
    return int(datetime.now(timezone.utc).timestamp())


def _is_lower_hex(text, length):
    if type(text) is not str or len(text) != length:
        return False
    for ch in text:
        if ch not in _HEX_DIGITS:
            return False
    return True


def _is_lower_address(text):
    return (
        type(text) is str
        and len(text) == 42
        and text[0] == "0"
        and text[1] == "x"
        and _is_lower_hex(text[2:], 40)
    )


def _is_decimal(text):
    if type(text) is not str or len(text) == 0:
        return False
    for ch in text:
        if ch < "0" or ch > "9":
            return False
    if len(text) > 1 and text[0] == "0":
        return False
    return True


def _leaf_hash(address, amount):
    if not _is_lower_address(address):
        _fail("leaf_address_must_be_lowercase_0x_hex")
    if not _is_decimal(amount):
        _fail("amount_must_be_decimal_wei_without_leading_zeros")
    if int(amount) <= 0:
        _fail("amount_must_be_positive")
    return _sha256_hex(address + ":" + amount)


def _parse_proof(proof_json):
    if type(proof_json) is not str:
        _fail("proof_must_be_json_string")
    try:
        proof = json.loads(proof_json)
    except Exception:
        _fail("proof_must_be_json_array")
    if type(proof) is not list:
        _fail("proof_must_be_json_array")
    if len(proof) > MAX_PROOF_LENGTH:
        _fail("proof_too_long")
    steps = []
    for step in proof:
        if type(step) is not dict:
            _fail("proof_step_must_be_object")
        if set(step.keys()) != {"sibling", "left"}:
            _fail("proof_step_keys_must_be_sibling_and_left")
        if not _is_lower_hex(step["sibling"], 64):
            _fail("proof_sibling_must_be_64_lowercase_hex")
        if type(step["left"]) is not bool:
            _fail("proof_left_must_be_boolean")
        steps.append({"sibling": step["sibling"], "left": step["left"]})
    return steps


def _recompute_root(leaf_hash, proof):
    current = leaf_hash
    for step in proof:
        if step["left"]:
            current = _sha256_hex(step["sibling"] + current)
        else:
            current = _sha256_hex(current + step["sibling"])
    return current


def _sender_lower():
    return str(gl.message.sender_address).lower()


def _pay(address, amount):
    _Recipient(Address(address)).emit_transfer(value=u256(amount))


@gl.evm.contract_interface
class _Recipient:
    class View:
        pass

    class Write:
        pass


class MerkleDistributor(gl.Contract):
    distributions_json: str
    credits_json: str
    total_received_wei: u256
    total_withdrawn_wei: u256
    next_id: u256

    def __init__(self):
        self.distributions_json = "{}"
        self.credits_json = "{}"
        self.total_received_wei = u256(0)
        self.total_withdrawn_wei = u256(0)
        self.next_id = u256(0)

    # -- state plumbing ------------------------------------------------------

    def _load_distributions(self):
        return json.loads(self.distributions_json)

    def _save_distributions(self, distributions):
        self.distributions_json = json.dumps(distributions, sort_keys=True)

    def _load_credits(self):
        return json.loads(self.credits_json)

    def _save_credits(self, credits):
        self.credits_json = json.dumps(credits, sort_keys=True)

    def _get_distribution(self, distributions, dist_id):
        if not _is_decimal(dist_id):
            _fail("distribution_id_must_be_decimal")
        record = distributions.get(dist_id)
        if record is None:
            _fail("distribution_not_found")
        return record

    def _credit(self, credits, address, amount):
        credits[address] = _ws(_wn(credits.get(address, "0")) + amount)

    # -- writes --------------------------------------------------------------

    @gl.public.write.payable
    def create_distribution(self, root: str, expiry: str, label: str) -> str:
        if not _is_lower_hex(root, 64):
            _fail("root_must_be_64_lowercase_hex")
        if not _is_decimal(expiry):
            _fail("expiry_must_be_decimal_unix_seconds")
        expiry_seconds = int(expiry)
        if expiry_seconds <= _now_seconds():
            _fail("expiry_must_be_in_the_future")
        if type(label) is not str or len(label) == 0 or len(label) > MAX_LABEL_LENGTH:
            _fail("label_must_be_1_to_120_chars")
        if label != label.strip():
            _fail("label_must_not_have_surrounding_whitespace")
        value = int(gl.message.value)
        if value <= 0:
            _fail("create_requires_positive_value")
        creator = _sender_lower()
        dist_id = _ws(int(self.next_id))
        record = {
            "id": dist_id,
            "creator": creator,
            "root": root,
            "expiry": _ws(expiry_seconds),
            "label": label,
            "status": "ACTIVE",
            "funded_wei": _ws(value),
            "remaining_wei": _ws(value),
            "claimed_count": 0,
            "claimed_total_wei": "0",
            "claimed": {},
        }
        distributions = self._load_distributions()
        distributions[dist_id] = record
        self._save_distributions(distributions)
        self.next_id = self.next_id + u256(1)
        self.total_received_wei = self.total_received_wei + u256(value)
        return json.dumps({
            "id": dist_id,
            "creator": creator,
            "root": root,
            "expiry": _ws(expiry_seconds),
            "label": label,
            "status": "ACTIVE",
            "funded_wei": _ws(value),
            "remaining_wei": _ws(value),
        }, sort_keys=True)

    @gl.public.write
    def claim(self, dist_id: str, address: str, amount: str, proof: str) -> str:
        distributions = self._load_distributions()
        record = self._get_distribution(distributions, dist_id)
        if record["status"] != "ACTIVE":
            _fail("distribution_not_active")
        if _now_seconds() >= int(record["expiry"]):
            _fail("distribution_expired")
        leaf = _leaf_hash(address, amount)
        if leaf in record["claimed"]:
            _fail("leaf_already_claimed")
        steps = _parse_proof(proof)
        computed = _recompute_root(leaf, steps)
        if computed != record["root"]:
            _fail("proof_does_not_match_root")
        amount_wei = int(amount)
        remaining = int(record["remaining_wei"])
        if amount_wei > remaining:
            _fail("insufficient_escrow")
        # Every check passed; only now mutate state.
        record["claimed"][leaf] = True
        record["claimed_count"] = int(record["claimed_count"]) + 1
        record["claimed_total_wei"] = _ws(
            int(record["claimed_total_wei"]) + amount_wei
        )
        record["remaining_wei"] = _ws(remaining - amount_wei)
        distributions[dist_id] = record
        self._save_distributions(distributions)
        credits = self._load_credits()
        self._credit(credits, address, amount_wei)
        self._save_credits(credits)
        return json.dumps({
            "distribution_id": dist_id,
            "address": address,
            "amount_wei": _ws(amount_wei),
            "leaf_hash": leaf,
            "computed_root": computed,
            "claimed_count": int(record["claimed_count"]),
            "claimed_total_wei": record["claimed_total_wei"],
            "remaining_wei": record["remaining_wei"],
        }, sort_keys=True)

    @gl.public.write
    def withdraw_payout(self) -> str:
        sender_raw = str(gl.message.sender_address)
        sender = sender_raw.lower()
        credits = self._load_credits()
        amount = _wn(credits.get(sender, "0"))
        if amount <= 0:
            _fail("no_credit_to_withdraw")
        # Pull payment: zero the credit before the transfer, so a
        # failed or re-entered transfer can never pay twice.
        credits[sender] = "0"
        self._save_credits(credits)
        self.total_withdrawn_wei = self.total_withdrawn_wei + u256(amount)
        _pay(sender_raw, amount)
        return json.dumps({
            "address": sender,
            "withdrawn_wei": _ws(amount),
            "total_withdrawn_wei": _ws(int(self.total_withdrawn_wei)),
        }, sort_keys=True)

    @gl.public.write
    def reclaim_distribution(self, dist_id: str) -> str:
        distributions = self._load_distributions()
        record = self._get_distribution(distributions, dist_id)
        if _sender_lower() != record["creator"]:
            _fail("only_creator_can_reclaim")
        if record["status"] != "ACTIVE":
            _fail("distribution_not_active")
        if _now_seconds() < int(record["expiry"]):
            _fail("distribution_not_expired")
        remaining = int(record["remaining_wei"])
        if remaining > 0:
            credits = self._load_credits()
            self._credit(credits, record["creator"], remaining)
            self._save_credits(credits)
        record["remaining_wei"] = "0"
        record["status"] = "RECLAIMED"
        distributions[dist_id] = record
        self._save_distributions(distributions)
        return json.dumps({
            "distribution_id": dist_id,
            "creator": record["creator"],
            "reclaimed_wei": _ws(remaining),
            "status": "RECLAIMED",
        }, sort_keys=True)

    @gl.public.write
    def extend_distribution(self, dist_id: str, new_expiry: str) -> str:
        distributions = self._load_distributions()
        record = self._get_distribution(distributions, dist_id)
        if _sender_lower() != record["creator"]:
            _fail("only_creator_can_extend")
        if record["status"] != "ACTIVE":
            _fail("distribution_not_active")
        if not _is_decimal(new_expiry):
            _fail("expiry_must_be_decimal_unix_seconds")
        new_expiry_seconds = int(new_expiry)
        if new_expiry_seconds <= int(record["expiry"]):
            _fail("new_expiry_must_be_later_than_old_expiry")
        if new_expiry_seconds <= _now_seconds():
            _fail("new_expiry_must_be_in_the_future")
        record["expiry"] = _ws(new_expiry_seconds)
        distributions[dist_id] = record
        self._save_distributions(distributions)
        return json.dumps({
            "distribution_id": dist_id,
            "expiry": _ws(new_expiry_seconds),
            "status": "ACTIVE",
        }, sort_keys=True)

    # -- views ---------------------------------------------------------------

    @gl.public.view
    def get_distribution(self, dist_id: str) -> str:
        distributions = self._load_distributions()
        return json.dumps(
            self._get_distribution(distributions, dist_id), sort_keys=True
        )

    @gl.public.view
    def get_count(self) -> str:
        return json.dumps(
            {"distribution_count": int(self.next_id)}, sort_keys=True
        )

    @gl.public.view
    def list_distributions(self, offset: str, limit: str) -> str:
        if not _is_decimal(offset) or not _is_decimal(limit):
            _fail("offset_and_limit_must_be_decimal")
        if int(limit) < 1 or int(limit) > 20:
            _fail("limit_must_be_1_to_20")
        distributions = self._load_distributions()
        total = int(self.next_id)
        start = int(offset)
        if start >= total:
            return json.dumps([], sort_keys=True)
        end = start + int(limit)
        if end > total:
            end = total
        out = []
        index = start
        while index < end:
            out.append(distributions[_ws(index)])
            index += 1
        return json.dumps(out, sort_keys=True)

    @gl.public.view
    def verify_proof(self, root: str, address: str, amount: str, proof: str) -> str:
        if not _is_lower_hex(root, 64):
            _fail("root_must_be_64_lowercase_hex")
        leaf = _leaf_hash(address, amount)
        steps = _parse_proof(proof)
        computed = _recompute_root(leaf, steps)
        return json.dumps({
            "leaf_hash": leaf,
            "computed_root": computed,
            "stored_root": root,
            "matches": computed == root,
            "proof_length": len(steps),
        }, sort_keys=True)

    @gl.public.view
    def get_leaf_hash(self, address: str, amount: str) -> str:
        leaf = _leaf_hash(address, amount)
        return json.dumps({
            "address": address,
            "amount_wei": amount,
            "leaf_preimage": address + ":" + amount,
            "leaf_hash": leaf,
        }, sort_keys=True)

    @gl.public.view
    def is_claimed(self, dist_id: str, leaf_hash: str) -> str:
        if not _is_lower_hex(leaf_hash, 64):
            _fail("leaf_hash_must_be_64_lowercase_hex")
        distributions = self._load_distributions()
        record = self._get_distribution(distributions, dist_id)
        return json.dumps({
            "distribution_id": dist_id,
            "leaf_hash": leaf_hash,
            "claimed": leaf_hash in record["claimed"],
        }, sort_keys=True)

    @gl.public.view
    def get_credit(self, address: str) -> str:
        if not _is_lower_address(address):
            _fail("leaf_address_must_be_lowercase_0x_hex")
        credits = self._load_credits()
        return json.dumps({
            "address": address,
            "credit_wei": _ws(_wn(credits.get(address, "0"))),
        }, sort_keys=True)

    @gl.public.view
    def get_totals(self) -> str:
        distributions = self._load_distributions()
        credits = self._load_credits()
        credits_outstanding = 0
        for key in credits:
            credits_outstanding += _wn(credits[key])
        escrow_locked = 0
        for key in distributions:
            if distributions[key]["status"] == "ACTIVE":
                escrow_locked += _wn(distributions[key]["remaining_wei"])
        received = int(self.total_received_wei)
        withdrawn = int(self.total_withdrawn_wei)
        accounted = withdrawn + credits_outstanding + escrow_locked
        balance = int(self.balance)
        return json.dumps({
            "total_received_wei": _ws(received),
            "total_withdrawn_wei": _ws(withdrawn),
            "contract_balance_wei": _ws(balance),
            "credits_outstanding_wei": _ws(credits_outstanding),
            "escrow_locked_wei": _ws(escrow_locked),
            "accounted_wei": _ws(accounted),
            "invariant_ok": received == accounted,
            "balance_matches_held": balance == credits_outstanding + escrow_locked,
            "distribution_count": int(self.next_id),
        }, sort_keys=True)
