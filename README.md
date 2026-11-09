# MerkleDistributor

A deterministic Merkle-proof payout primitive for GenLayer (Intelligent Contract, no frontend).

A creator funds a distribution with real GEN and publishes one Merkle root on-chain. Each leaf commits to exactly one `(address, amount)` pair. A claim carries the leaf data and a Merkle proof; the contract recomputes the root and compares it with the stored root, byte for byte. A match credits the exact leaf amount to the leaf address, once. A mismatch fails before any state is written. Payouts are pull payments only. After expiry the creator can reclaim the unclaimed remainder (or extend the window while active). No funds are ever locked without an exit.

There is no LLM verdict and no external evidence surface. Consensus decides one deterministic question only: does this leaf + proof recompute to the stored root? Every comparison is exact — the worst-case spread between two passing inputs is **0 wei and 0 seconds** (see `docs/mechanism.md`).

- **Network:** Stable Studionet (Chain ID 61999), https://studio.genlayer.com/api
- **Contract:** `0x062E5A1ee60fc61Bc37aCEC24A5fB23F350968ea`
- **Deploy transaction:** `0xbc3fd29add69d23b92d54edddcede064346af57a265619bf7b0aac20fbf1a989` (FINALIZED)
- **Explorer:** https://explorer-studio.genlayer.com/address/0x062E5A1ee60fc61Bc37aCEC24A5fB23F350968ea
- **Studio:** https://studio.genlayer.com/?import-contract=0x062E5A1ee60fc61Bc37aCEC24A5fB23F350968ea
- **Evidence:** [`evidence.json`](evidence.json) (every transaction, read-back and balance), [`docs/live-verification.md`](docs/live-verification.md)

## Leaf construction (exact)

- Address: lowercase `0x` + 40 lowercase hex characters. Any other spelling (checksummed mixed case, missing `0x`) is rejected, never normalized.
- Amount: decimal integer wei, no leading zeros, as a string.
- Leaf preimage: `address + ":" + amount`.
- Leaf hash: SHA-256 hex of the UTF-8 bytes of the preimage.
- Internal node: SHA-256 hex of `(left_hex + right_hex)` as a 128-char ASCII string. Proofs carry an explicit `left` bit per step, so ordering is never ambiguous.
- Odd node on a level is promoted unchanged (never duplicated). Single-leaf tree: root == leaf hash, empty proof. Maximum proof length: 32.
- SHA-256 inside the contract is pure Python (no assumption that GenVM provides hashlib); it is checked against hashlib test vectors locally before deployment. The off-chain generator (`scripts/merkle_lib.py`) uses the identical definition.

## Operations

| operation | who | sender check | effect |
|---|---|---|---|
| `create_distribution(root, expiry, label)` payable | anyone (the funder) | none — the caller funds their own distribution | escrows the caller's GEN; root can never be overwritten |
| `claim(dist, address, amount, proof)` | anyone (relayer-friendly) | none — but the credit goes to the **leaf address only**, never to the caller | credits the exact leaf amount once; sets the leaf's claimed bit |
| `withdraw_payout()` | the credited address | credit is keyed by sender; a stranger has no credit to withdraw | transfers the caller's own credit, once (credit zeroed first) |
| `reclaim_distribution(dist)` | creator only | `sender == creator`, and only when `now >= expiry` | credits the unclaimed remainder to the creator; status → RECLAIMED |
| `extend_distribution(dist, new_expiry)` | creator only | `sender == creator`; new expiry must be later than the old one and in the future | moves the expiry later; distribution stays ACTIVE |
| views (`get_distribution`, `verify_proof`, `get_leaf_hash`, `is_claimed`, `get_credit`, `get_totals`, `list_distributions`) | anyone | none (read-only) | none |

Every failure raises before any write: a failed claim sets no claimed bit, credits nothing, and leaves the leaf claimable. A failed payable call keeps its value in the contract (platform behaviour, proven on-chain by the failed-payable probe in `evidence.json`: a `create_distribution` with an invalid root and 1 wei failed, and the 1 wei stayed in the contract balance). No state is written for a failed call, so the kept value is credited to nobody; `get_totals` exposes it as the difference between `contract_balance_wei` and `credits_outstanding_wei + escrow_locked_wei`. The only payable failure modes are creator input errors (bad root, past expiry, zero value), which the off-chain tooling validates before sending.

Money invariant, readable at any time with `get_totals`:

```
total_received_wei == total_withdrawn_wei
                     + credits_outstanding_wei
                     + escrow_locked_wei
```

## Call examples

```js
import { createClient, createAccount } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

const client = createClient({ chain: studionet, account });
const address = "0x062E5A1ee60fc61Bc37aCEC24A5fB23F350968ea";

// Build the tree off-chain (scripts/merkle_lib.py) and publish the root.
await client.writeContract({
  address,
  functionName: "create_distribution",
  args: ["<64-char lowercase hex root>", "<expiry unix seconds>", "main"],
  value: 30n * 10n ** 18n, // real GEN escrow
});

// Claim leaf 0 with its proof (proof is a JSON string).
await client.writeContract({
  address,
  functionName: "claim",
  args: ["0", "<lowercase leaf address>", "<amount wei as string>", '[{"sibling": "<64 hex>", "left": false}]'],
});

// Pull the credited GEN to the leaf address.
await client.writeContract({ address, functionName: "withdraw_payout", args: [] });

// Read back (FINALIZED state only).
await client.readContract({ address, functionName: "get_distribution", args: ["0"] });
await client.readContract({ address, functionName: "get_totals", args: [] });
```

## Verified flow (live, Stable Studionet)

Four distributions, 47 GEN in total, every step FINALIZED and read back — see `docs/live-verification.md` and `evidence.json`:

- **D0 "main"** (30 GEN): Alice 5, Bob 10, Carol 15 GEN — all three claimed (Bob's claim relayed by a stranger; the credit still went to Bob) and withdrawn.
- **D1 "short"** (4 GEN): Dave's claim after expiry failed; a stranger reclaim failed; the creator reclaimed 4 GEN and withdrew it.
- **D2 "underfunded"** (12 GEN for 20 GEN of leaves): Eve claimed 10 GEN; Frank's claim failed with `insufficient_escrow`; the creator reclaimed the 2 GEN remainder.
- **D3 "extendable"** (1 GEN): a stranger extend failed; the creator extended the window; Grace claimed 1 GEN; the creator reclaimed the 0 GEN remainder after expiry.
- **Adversarial cases, all failed on-chain with the expected error and no state change:** double claim, tampered proof, wrong amount, checksummed address, 33-step proof, stranger withdraw, stranger reclaim, stranger extend, expired claim, underfunded claim.
- **Final:** received 47 GEN, withdrawn 47 GEN, credits 0, escrow 0, contract balance 0 (+ probe result, see `evidence.json`).

## Tests

```bash
python3 tests/test_local.py   # 147 checks (mock only, not consensus evidence)
npm install
node scripts/verify.mjs      # independent re-check: source hash, all receipts,
                              # every read-back, invariant, EOA balances (read-only)
```

## Layout

- `contracts/merkle_distributor.py` — the contract (pure-Python SHA-256, deterministic, no LLM).
- `scripts/merkle_lib.py` — off-chain tree builder (same leaf definition).
- `scripts/deploy.mjs` — deploy + read-back source verification.
- `scripts/flow.mjs` — full on-chain evidence flow (writes `evidence.json`).
- `scripts/verify.mjs` — independent read-only re-check of the evidence.
- `tests/test_local.py` — local mock tests.
- `docs/mechanism.md` — the full mechanism, worst-case spread table, time source.
- `docs/live-verification.md` — every live transaction and read-back.
- `docs/REVIEWER.md` — the 5-minute reviewer fast path.
- `KNOWN_LIMITATIONS.md` — real limits, stated plainly.
- `deployment.json`, `evidence.json` — deployment record and evidence package.
