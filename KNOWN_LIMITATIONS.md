# Known limitations

- All distribution money is real testnet GEN on Stable Studionet
  (Chain ID 61999), funded from the Studionet faucet at zero cash
  cost. The GEN has no cash value and the contract is not connected
  to any mainnet.
- The contract never sees the leaves, so it cannot verify that the
  funded total equals the sum of the leaf amounts. A creator who
  underfunds a distribution leaves late claims failing with
  `insufficient_escrow`; the shortfall is visible to everyone via
  `get_distribution` (`remaining_wei` vs `claimed_total_wei`) before
  anyone claims, and no leaf can be paid twice to cover it.
- Expiry uses the transaction datetime
  (`int(datetime.now(timezone.utc).timestamp())`). Per the GenLayer
  docs the stdlib clock is pinned to the transaction datetime, so
  every validator sees the same value; the deploy flow exercises the
  expiry branch on-chain (an expired claim must fail, an expired
  reclaim must succeed). If the runner ever stopped pinning the
  clock, expiry comparisons could fail to reach consensus.
- The root is set once at creation and can never be corrected. A
  creator who publishes a wrong root must create a new distribution;
  the old one can only be reclaimed after its expiry.
- A leaf address is accepted only in lowercase `0x` + 40 lowercase
  hex characters. Checksummed (mixed-case) addresses are rejected
  rather than normalized; integrators must lowercase addresses
  before building the tree.
- Proofs are capped at 32 steps (up to 2^32 leaves). Larger
  distributions must be split across multiple distributions.
- Claims are permissionless by design: anyone may submit a valid
  proof, but the credit always goes to the leaf address, never to
  the caller. A relayer cannot redirect a payout.
- A failed payable call keeps its value in the contract. This is
  platform behaviour, proven on-chain by the failed-payable probe
  in `evidence.json` (a `create_distribution` with an invalid root
  and 1 wei failed with `root_must_be_64_lowercase_hex`, and the
  1 wei stayed in the contract balance). The contract writes no
  state for a failed call, so the kept value is not credited to
  anyone; `get_totals` shows it as the difference between
  `contract_balance_wei` and `credits_outstanding_wei +
  escrow_locked_wei`, and the evidence flow carries it explicitly
  as `stranded_wei` (measured, never assumed). In practice the only
  payable failure modes are creator input errors (bad root, past
  expiry, zero value), which the off-chain tooling validates before
  sending, so a failed create should not be sent with real funds
  attached.
- Reads via `gen_call` fail on this runner when the serialized
  calldata is long: a proof argument longer than ~90 characters
  fails with an RLP error (`RLP string ends with ... superfluous
  bytes`), while shorter reads succeed. The `verify_proof` view is
  correct on-chain, but a real multi-step proof cannot be checked
  through it on this runner; verify proofs off-chain with
  `scripts/merkle_lib.py` (same leaf definition, checked against
  the contract's pure-Python SHA-256) and let the claim transaction
  itself be the on-chain check. Writes are not affected: claims
  with full proofs finalize normally. Short reads
  (`get_distribution`, `get_totals`, `get_credit`, `is_claimed`,
  `get_leaf_hash`) are unaffected.
- A read immediately after a FINALIZED write can lag the node's
  read view (observed once: an EOA balance read right after a
  FINALIZED withdraw still showed the old value; a re-read seconds
  later showed the transfer). The evidence scripts poll read-backs
  until the expected state appears instead of trusting the first
  read.
- The contract does not know who the leaves belong to in the real
  world. It proves that a (address, amount) pair is a member of the
  committed set, not that the address owner is entitled to it off-chain.
- Abandoned deployments (faucet GEN only, zero cash cost; the
  ephemeral deployer / flow account keys were not retained, so the
  funds in them are unreachable):
  - `0xC77d4F68f449df5151CAe439C9EF224a7091976e` — first deploy;
    abandoned because `create_distribution` was not declared
    payable, so every funded call failed at method resolution.
    The failed-payable probe left 1 wei in it. Deploy transaction
    `0x48a48073f5b8853f360f6b0b180ed9636c82561186c2878220aaa95f76e4f57a`
    (FINALIZED). No distribution was ever created on it.
  - `0x6849008DD2e2E480342A29f002A6e8194a071BDe` — second deploy;
    used for a write-path probe (distribution 0 "probe-d0", 30 GEN
    funded; Alice claimed 5 GEN and holds a 5 GEN credit that was
    never withdrawn; 25 GEN escrow remains locked, the creator key
    is lost so it can never be reclaimed). 3 wei stranded (two from
    the failed-payable probes; one further wei appeared between two
    balance measurements and its source is unknown). Deploy
    transaction
    `0xc51e04f3a098ae27e25735ae62a3f45e4e35fd65a5d92c0fca4737d1b6abb007`
    (FINALIZED).
  - `0xEfC64f96fa875092c72AD0285783cF6DE597B7D5` — third deploy; two
    partial flow runs left four distributions (76 GEN escrow) and
    1 GEN + 2 wei stranded; all creator keys lost. Deploy
    transaction
    `0xb2be5393820cf65d077e6ee3960b0224c3aececff6afca593f5314c6162517e7`
    (FINALIZED).
  - `0xE39b02886b191c2A7e2a8F968645DCEf2bB63267` — fourth deploy; a
    partial flow run left four distributions (17 GEN escrow) and
    30 GEN of unwithdrawn leaf credits (Alice 5, Bob 10, Carol 15)
    plus 1 wei stranded; all account keys lost. Deploy transaction
    `0x196f86046d0bcf57a91e544fe868007143c55130d89483f647a27724ea8e0dc5`
    (FINALIZED).
  - `0x0663c679b168feA5A310008ECF128572A05Ff8Fe` — fifth deploy;
    an accidental double-deploy, never used; no transactions
    besides the deploy itself (deploy transaction not captured in
    the logs).
  - `0xC618956398fBB606296A021dC64406F224c94e26` — sixth deploy; a
    partial flow run left four distributions (6 GEN escrow: D1 4,
    D2 2) and a 1 GEN unwithdrawn Grace credit plus 1 wei stranded;
    Alice, Bob, Carol and Eve withdrew correctly (5, 10, 15,
    10 GEN). All account keys lost. Deploy transaction
    `0x319641c57cda6a48147db1fa0c84aaaee318b1d14a5e3a711263820df752fe89`
    (FINALIZED).
  - `0x23a9A058668725d0ab9007BFc5a401C3E2E30E91` — seventh deploy;
    a near-complete flow run (29 transactions, all FINALIZED /
    MAJORITY_AGREE, read back live): 47 GEN received, 47 GEN paid
    out, credits 0, escrow 0, contract balance 1 wei (the probe
    wei). D0 fully claimed (3 of 3), D1 and D2 reclaimed by the
    creator, all leaf withdrawals exact to the wei. The run was
    killed by a runtime restart during the final wait, before the
    D3 reclaim (0 GEN remaining — Grace had already claimed the
    only leaf — so the reclaim would have moved no funds); the
    ephemeral creator key died with the process, so D3 stays
    ACTIVE with 0 remaining and can never be reclaimed. The
    partial evidence (29 transactions) is kept in the workspace
    archive, not in the repo. Deploy transaction
    `0xc367a812f4247477ee4b86c310f47bd315a26e791f9586f6ae8946a3dd408f91`
    (FINALIZED).
  None of these is the deployed contract; see
  `docs/live-verification.md`.
- Each evidence-flow run funded nine fresh ephemeral accounts with
  10000 GEN each from the faucet; runs that stopped early left
  those accounts (and their faucet GEN) unreachable because the
  keys were never written to disk.
- The submission flow was verified with script accounts only.
