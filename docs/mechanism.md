# MerkleDistributor — mechanism

A deterministic Merkle-proof payout primitive (Track A Intelligent
Contract, no frontend). A creator funds a distribution with real GEN
and publishes one Merkle root on-chain. Each leaf commits to exactly
one `(address, amount)` pair. Claims carry the leaf data and a Merkle
proof; the contract recomputes the root and compares it with the stored
root, byte for byte. A match credits the exact leaf amount to the leaf
address; a mismatch fails before any state is written. Each leaf can
be claimed exactly once. Payouts are pull payments only. After expiry,
the creator can reclaim the unclaimed remainder (or extend the
distribution); no funds are ever locked without an exit.

## Opening five lines

- **Category:** deterministic cryptographic primitive — distribution
  infrastructure (Track A Intelligent Contract, no frontend). Same
  quality class as TokenWeave / CoPack (deterministic, hash-bound, no
  LLM judge, no external evidence surface), different mechanism.
- **Mechanism:** there is no LLM verdict. Consensus decides one thing
  only, deterministically: does the submitted leaf + proof recompute to
  the on-chain root? If yes, the exact leaf amount (wei) is credited to
  the leaf address; if no, the call fails before any write. The
  consequence is real GEN movement (pull-payment withdrawal); after
  expiry the creator reclaims the unclaimed remainder.
- **Interaction model:** no frontend. Call examples + scripts:
  create distribution → build tree / proof off-chain → claim → withdraw;
  after expiry → reclaim or extend.
- **Evolving state:** per-leaf claimed bit, claimed count / claimed
  total, remaining escrow, distribution status ACTIVE → RECLAIMED
  (or extended while ACTIVE); the money invariant
  `received == paid_out + locked + credits` holds after every step.
- **Anchor:** the on-chain Merkle root (immutable once published) +
  the Merkle proof (cryptographic binding). A beneficiary cannot write
  their own good result: to be paid they must present a proof path
  that recomputes to the stored root; changing the address or the
  amount by 1 wei changes the leaf hash and the root no longer matches.
  The creator sets the root, but a claim credits only the leaf
  address, the root can never be overwritten, and reclaim is possible
  only after expiry.

## De-duplication vs existing primitives

- **TokenWeave** (token-flow reachability): decides whether a token can
  flow from A to B through a graph — a graph-reachability verdict, no
  money moves, no time dimension.
- **CoPack** (exact co-packing): decides whether a set of items fits a
  set of bins exactly — a combinatorial feasibility verdict, no money
  moves, no per-item one-time state.
- **MerkleDistributor** (this): decides membership of a committed
  (address, amount) pair by cryptographic proof, and moves real GEN
  exactly once per leaf, with a time-bounded lifecycle (expiry →
  reclaim / extend). Different on mechanism (proof-of-membership vs
  reachability / packing), on consequence (money moves vs verdict
  record), and on state (per-leaf claimed bits + escrow lifecycle vs
  a single verdict).
- **Sealed-vote tally** (parallel Track A build): commit-reveal +
  deterministic tally of votes. Different mechanism (tally of hidden
  votes vs proof-of-membership payout), different consequence (a tally
  result vs GEN transfers), no shared code or state.

## Leaf construction (exact)

- Address: lowercase `0x` + 40 lowercase hex characters (42 chars).
  Any other spelling (checksummed mixed case, missing `0x`) is
  rejected, not normalized — one address has exactly one leaf spelling.
- Amount: decimal integer wei, no leading zeros, as a string.
- Leaf preimage: `address + ":" + str(amount_wei)` (`:` separator).
- Leaf hash: SHA-256 hex of the UTF-8 bytes of the preimage.
- Internal node: SHA-256 hex of `(left_hex + right_hex)` as a 128-char
  ASCII string. The proof carries an explicit `left` bit per step, so
  ordering is never ambiguous.
- Odd node on a level is promoted unchanged (never duplicated).
- Single-leaf tree: root == leaf hash, empty proof.
- Proof: JSON array of `{"sibling": <64 lowercase hex>, "left": <bool>}`;
  `left=true` means the sibling sits on the left of the running hash.
  Maximum proof length is 32 (up to 2^32 leaves).
- SHA-256 inside the contract is pure Python (no assumption that
  GenVM provides hashlib); it is checked against hashlib test vectors
  locally before deploy, and the off-chain generator
  (`scripts/merkle_lib.py`) uses the identical definition.

## Operations and who can call them

| operation | who | sender check | irreversible effect |
|---|---|---|---|
| `create_distribution(root, expiry, label)` payable | anyone (the funder) | none — the caller funds their own distribution | escrows the caller's GEN; root can never be overwritten |
| `claim(dist, address, amount, proof)` | anyone (relayer-friendly) | none — but the credit goes to the **leaf address only**, never to the caller | credits the exact leaf amount once; sets the leaf's claimed bit |
| `withdraw_payout()` | the credited address | credit is keyed by sender; a stranger has no credit to withdraw | transfers the caller's own credit, once (credit zeroed first) |
| `reclaim_distribution(dist)` | creator only | `sender == creator`, and only when `now >= expiry` | credits the unclaimed remainder to the creator; status → RECLAIMED |
| `extend_distribution(dist, new_expiry)` | creator only | `sender == creator`; new expiry must be later than the old one and in the future | moves the expiry later; distribution stays ACTIVE |
| views (`get_distribution`, `verify_proof`, `get_leaf_hash`, `is_claimed`, `get_credit`, `get_totals`, `list_distributions`) | anyone | none (read-only) | none |

No stranger can trigger an irreversible consequence: a stranger's
`claim` can only pay the rightful leaf owner; `reclaim`/`extend`
reject non-creators; `withdraw_payout` pays only the caller's own
credit. No state is locked: ACTIVE → (claims) → RECLAIMED after
expiry; a fully claimed distribution reclaims 0 and still closes;
`extend` re-opens the window before reclaim.

## Failure behaviour

Every failure raises `UserError` **before any write**: a failed claim
sets no claimed bit, credits nothing, and leaves the leaf claimable.
A failed payable call writes no state, but the platform keeps the
attached value in the contract balance (proven on-chain by the
failed-payable probe in `evidence.json`: a `create_distribution`
with an invalid root and 1 wei failed, and the 1 wei stayed in the
contract; `total_received_wei` does not count it and it is credited
to nobody — `get_totals` exposes the difference between
`contract_balance_wei` and `credits_outstanding_wei +
escrow_locked_wei`). The only payable failure modes are creator
input errors (bad root, past expiry, zero value), which the
off-chain tooling validates before sending. There are no ghost states.

## Worst-case spread table

There is no tolerance, no score, no threshold anywhere in this
contract. Every comparison is exact. The table below is the proof.

| quantity | rule | edge values | spread between two passing values | changes the business result? |
|---|---|---|---|---|
| leaf amount (wei) | exact integer inside the leaf hash; root equality is 256-bit hash equality | amount `N` passes; amount `N+1` wei (same address, same proof) fails — the leaf hash changes, the recomputed root no longer matches | **0 wei.** Two proofs that both pass for the same leaf must carry the identical amount, because the amount is committed inside the leaf hash. | No. A payout is either the exact committed amount or nothing. |
| proof length | 0–32 steps; 33 rejected | length 32 passes (2^32-leaf tree); length 33 fails with `proof_too_long` | 0 — length is an exact bound, not a tolerance. | No. |
| root comparison | byte-for-byte equality of 64-char lowercase hex | any single hex digit different fails | 0 — one bit different is a different root. | No. |
| expiry boundary | claim requires `now < expiry` (strict) | `now = expiry - 1` passes; `now = expiry` fails with `distribution_expired` | **0 seconds.** `now` is the transaction datetime, identical for every validator (per GenLayer docs, the stdlib clock is pinned to the transaction datetime). Two validators cannot see different `now` values for the same transaction. | No. A claim straddling expiry is either in or out; a failed claim credits 0 and leaves no state. |
| address spelling | lowercase `0x` + 40 lowercase hex only | `0xab...` passes; `0xAB...` (checksummed) fails with `leaf_address_must_be_lowercase_0x_hex` | 0 — one spelling per address, enforced by rejection, not normalization. | No. |
| escrow vs leaf sum | the contract never sees the leaves, so it cannot verify `total == sum(leaves)` | creator funds less than the leaf sum: early claims succeed, late claims fail with `insufficient_escrow` | Not a spread — a visible creator error. `get_distribution` shows `remaining_wei` vs `claimed_total_wei` to everyone before any claim. The shortfall is public, and no leaf can be paid twice to cover it. | No verdict is affected (there is no verdict); the failure mode is a failed claim, not a wrong payout. |

**Worst-case spread: 0 wei, 0 seconds.** No two different passing
inputs can produce different payouts for the same leaf, and no
passing input can produce a payout different from the committed leaf
amount.

## Time source — the one thing to prove on-chain

Expiry uses `int(datetime.now(timezone.utc).timestamp())`. The
GenLayer docs state the stdlib clock is pinned to the transaction
datetime and identical across validators. One independent field report
(an older pinned runner) found `gl.message.datetime` absent, which is
why this contract reads the clock through `datetime.now()` (the
documented path) and never through `gl.message`. The deploy flow
exercises the expiry branch on-chain (an expired claim must fail, an
expired reclaim must succeed); if validators ever disagree on time,
that flow fails loudly at deploy time and the design falls back to a
creator-closed window instead of a timestamp. See
`KNOWN_LIMITATIONS.md`.
