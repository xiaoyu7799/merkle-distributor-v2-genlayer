# Reviewer fast path

Start here: [README.md](../README.md) (one page: what it is, the
decision rule, the verified flow, call examples), then
[mechanism.md](mechanism.md) (state, money rules, worst-case spread
calculation — 0 wei, 0 seconds).

## Shortest recheck (about 5 minutes, no keys needed)

1. Confirm the deployed code is the repo code:
   - Contract: `0x062E5A1ee60fc61Bc37aCEC24A5fB23F350968ea` (see
     `deployment.json`)
   - `gen_getContractCode` on that address, base64-decode it, SHA-256 it,
     compare with the SHA-256 of `contracts/merkle_distributor.py` at
     HEAD (see `deployment.json` / `evidence.json`).
2. Re-run the independent check (needs only `npm install`, no keys):
   `node scripts/verify.mjs` — checks: code hash, all receipts
   FINALIZED + MAJORITY_AGREE, every read-back against `evidence.json`,
   the adversarial leaves still unclaimed, plus the GEN invariant and
   final EOA balances.
3. Spot-check one read-back by hand:
   `get_distribution(0)` → `ACTIVE` with 3 of 3 leaves claimed,
   `remaining_wei` 0 (D0 is fully claimed; it is never reclaimed);
   `get_totals()` → received 47 GEN, paid out 47 GEN, locked 0,
   credits 0, contract balance 1 wei (the stranded failed-payable
   probe wei, see `evidence.json`).
4. Spot-check the adversarial cases: `is_claimed(1, <Dave D1 leaf>)`
   → `claimed: false` (expired claim failed);
   `is_claimed(2, <Frank D2 leaf>)` → `claimed: false` (underfunded
   claim failed); `get_distribution(1)` → `RECLAIMED`.
5. Spot-check the money: `get_totals()` → received 47 GEN, paid out
   47 GEN, locked 0, credits 0, contract balance 1 wei; creator EOA
   9958999999999999999999 wei (9959 GEN less the 1 probe wei),
   Alice 10005, Bob 10010, Carol 10015, Dave 10000, Eve 10010,
   Frank 10000, Grace 10001, stranger 10000 (all GEN).

## Where the mechanism lives

- Leaf + proof rules: `contracts/merkle_distributor.py`,
  `_leaf_hash` / `_recompute_root` / `_parse_proof` (exact SHA-256
  recomputation, explicit left/right bits, max proof length 32,
  single-leaf empty proof).
- Money rules: `create_distribution` (payable, GEN locked),
  `claim` (credits the exact leaf amount once; claimed bit set before
  crediting), `withdraw_payout` (zeroes the credit before
  transferring), `reclaim_distribution` (creator only, after expiry),
  `extend_distribution` (creator only, later expiry), `get_totals`
  (the invariant).
- Worst-case spread proof: [mechanism.md](mechanism.md) — 0 wei,
  0 seconds, with the edge cases (amount ±1 wei, proof length 32/33,
  expiry boundary, address spelling, underfunded escrow).
- Local mock tests (mock only, not consensus evidence):
  `python3 tests/test_local.py` (147 checks).

## Two runner quirks to know before rechecking

- Reads via `gen_call` fail on this runner when the serialized
  calldata is long: a proof argument longer than ~90 characters
  fails with an RLP error, while shorter reads succeed. So do not
  recheck proofs through the `verify_proof` view with a real
  multi-step proof; verify them off-chain with
  `scripts/merkle_lib.py` (same leaf definition) or through the
  claim transactions themselves. Writes are not affected.
- A read immediately after a FINALIZED write can lag the node's read
  view; re-read after a few seconds if a value looks stale.
