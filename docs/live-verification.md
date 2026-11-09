# Live verification

Contract: `0x062E5A1ee60fc61Bc37aCEC24A5fB23F350968ea`
(Stable Studionet, Chain ID 61999)

Deploy transaction:
`0xbc3fd29add69d23b92d54edddcede064346af57a265619bf7b0aac20fbf1a989`
(FINALIZED)

Deployed code SHA-256:
`56885b49f1679ec6166450cbbeb9eded2e10549dadd2d2214cb861a6360ee101`
— byte-for-byte the repo source `contracts/merkle_distributor.py`
at the same commit (checked by `scripts/deploy.mjs` at deploy time
and again by `scripts/verify.mjs`).

Evidence run: 2026-11-09 23:25 UTC (`evidence.json`,
`generatedAt 2026-11-09T23:25:25.939Z`). Nine ephemeral accounts,
each funded 10000 GEN from the faucet; the flow script is
`scripts/flow.mjs`. Every transaction below was re-read live by
`scripts/verify.mjs` (67 checks, all PASS) and is
FINALIZED / MAJORITY_AGREE.

## 0. Failed-payable probe (first, before any distribution)

| tx | result |
| --- | --- |
| `0xb12e510499cf80630ff9af6e125a01cb34fcc053cc48f5939cde93a171191e23` | ERROR `root_must_be_64_lowercase_hex` |

`create_distribution` with an invalid root (`"g"*64`) and 1 wei.
The call failed as expected; the 1 wei stayed in the contract
(balance 0 → 1 wei, `total_received` still 0, 0 distributions).
A failed payable keeps its value on this platform — the stranded
wei is carried explicitly in the final invariant below, never
assumed away. See `KNOWN_LIMITATIONS.md`.

## 1. Creates (4 distributions, 47 GEN funded)

| distribution | leaves | funded | expiry (epoch) | tx | result |
| --- | --- | --- | --- | --- | --- |
| D0 main | Alice 5 / Bob 10 / Carol 15 GEN | 30 GEN | 1794351258 | `0x97979d8a81b6cf1ce9c2d288bcd4e144f6a32b89dd5c0805178cdf12529f400f` | SUCCESS |
| D1 short | Dave 4 GEN | 4 GEN | 1794265758 | `0x2c6678685dd2c739ae0695b46f1795e36fdad0a4fd495efcdfe69dbe1bfb5dea` | SUCCESS |
| D2 underfunded | Eve 10 / Frank 10 GEN | 12 GEN | 1794265758 | `0x9837a5a068b21575807b74ee1961d1316868d9c4b19a6f06629ac37bcf53ae7c` | SUCCESS |
| D3 extendable | Grace 1 GEN | 1 GEN | 1794265758 | `0xac84132c1506b751c3298ff31053f7ae8ef5ef1ef25394c78949d41129157a95` | SUCCESS |

After the creates: received 47 GEN, withdrawn 0, credits 0,
escrow 47 GEN, contract balance 47 GEN + 1 wei, `invariant_ok`
true. Roots (from `evidence.json`):

- D0 `f90f2acae5e59236a8998453962749dcbf670722486a23fd874fce7470366e38`
- D1 `647783657c6a17d4bd61d2ba013f176884bcee73c0fd9d3f1cda0f8a70ca5334`
- D2 `223e4da245dd71b882071bf0cd222adc9df092b0559d9750f992c4e3adcd8e99`
- D3 `61781b91b31d4b63ccab127827f7d61c3bb5a6a3dd79686243be7f7d55088070`

## 2. Extend D3 (creator only)

| tx | result |
| --- | --- |
| stranger extend `0x2865ae1f52482b371058e331abf7efecc32cc16edf0bf72496b7b3346e411888` | ERROR `only_creator_can_extend` |
| creator extend `0x336662ecd81acfcdcb114d8c5d269b0fa29ee8ac7ed03b85244b3cd90ca8c672` | SUCCESS — D3 expiry 1794265758 → 1794266658 |

## 3. Happy claims on D0

| tx | result |
| --- | --- |
| Alice claim `0xb6f5d35521c29071c70f9b64243c2e1a528e11171c5dad86ec074cc78ef2d535` | SUCCESS — credit 5 GEN |
| Bob claim, relayed by stranger `0xac6f2950de025707b157336e18f594ed687616224bfc2c872e940212e7f908e4` | SUCCESS — credit 10 GEN to Bob, not to the relayer |
| Carol claim `0xaf321fd5deda2028ea501151792838eb08cf6230bfdf4fc4a08143ea2b94bae6` | SUCCESS — credit 15 GEN |

After the D0 claims: received 47 GEN, withdrawn 0, credits 30 GEN,
escrow 17 GEN, `invariant_ok` true. D0 claimed 3 of 3, remaining 0.

## 4. Adversarial cases (all must fail, no state change)

| case | tx | result |
| --- | --- | --- |
| double claim (Alice again) | `0x8a4b483113e5612fee07b4cc9bf510df34100ae2d054f8e0180b84b8303be513` | ERROR `leaf_already_claimed` |
| tampered proof (Frank / D2) | `0xe52368dc5abe435cc1cf82b8ddde082c7bd0dce55cd6218a2996e12209c6b214` | ERROR `proof_does_not_match_root` |
| wrong amount (Frank 11 GEN / D2) | `0x30936be53ad899b289ddb1408169b293be0594db16a0b0eeab30ffcbf8063dd8` | ERROR `proof_does_not_match_root` |
| checksummed address (Bob) | `0x9ad7ae3a730e8e21c2a19c76642687100ac84c6e2f50f9eb6cbece1f768d30ac` | ERROR `leaf_address_must_be_lowercase_0x_hex` |
| 33-step proof (Frank / D2) | `0x7625bf115b69fe72deb65107255104b0ffccb683cd9de3042ce81f51903a4d3c` | ERROR `proof_too_long` |
| stranger withdraw (no credit) | `0xce858b4c2ffec4ea7a5019650ae774ac8d6a4688f8c6ca825c0b4339deb72f7c` | ERROR `no_credit_to_withdraw` |

Each was followed by a read-back confirming no state changed
(claimed counts, credits and totals unchanged).

## 5. D2 underfunded

| tx | result |
| --- | --- |
| Eve claim 10 GEN `0xd9f66be1b4e4347b0c0417bff082c5064971bb03b56fa0c67cfacca65558d061` | SUCCESS — credit 10 GEN |
| Frank claim 10 GEN `0xf938a2110e770b8f643c7ea8821f0d3057e00443650dcfac739b7ee36753dc32` | ERROR `insufficient_escrow` — Frank's leaf stays unclaimed, D2 remaining 2 GEN |

## 6. Grace claims D3; all leaf withdrawals (pull payments, exact to the wei)

| tx | result |
| --- | --- |
| Grace claim 1 GEN `0xb1a45db01c370bfb0aaefef08019c5cc04e8d96905f0d8bf1d1ab97489418ff3` | SUCCESS — credit 1 GEN |
| Alice withdraw `0x630b08b12b49cc6aece8b9ec256a4afc5f0a528a185c7262260836f469563656` | SUCCESS — EOA 10000 → 10005 GEN |
| Bob withdraw `0x1911c334119e316b7ca512e48cd8b8e3d78fcd0028056a591aab808ea8351744` | SUCCESS — EOA 10000 → 10010 GEN |
| Carol withdraw `0x04741f67b2e9de229bb1c7be39d948a5b6f754558f28127e48d417af8207b407` | SUCCESS — EOA 10000 → 10015 GEN |
| Eve withdraw `0x47ded398c9b8428582ebc68b0f63e9d7a70c2a7e3bfdee7e8fa077d8d9984967` | SUCCESS — EOA 10000 → 10010 GEN |
| Grace withdraw `0x679ef0c398f06dbfed28e76f284522cc6d9cb13340935d9747b11bb9f8fc1de8` | SUCCESS — EOA 10000 → 10001 GEN |

After the leaf withdrawals: received 47 GEN, withdrawn 41 GEN,
credits 0, escrow 6 GEN, contract balance 6 GEN + 1 wei,
`invariant_ok` true.

## 7. After D1/D2 expiry

| tx | result |
| --- | --- |
| Dave claim (expired D1) `0x1d709576296531b5b422a35a31b35489f839db711cca17d14b1c55c3e346e951` | ERROR `distribution_expired` |
| stranger reclaim D1 `0xea1d07900e437d7cfa4b05bf3c22d5f2a084ce7e75fb689c082cd457e60a1fd4` | ERROR `only_creator_can_reclaim` |
| creator reclaim D1 `0xa48afbb7669812e1616edb76abc0767d88db139fc90f805c2dbbb3e32fd7ccf9` | SUCCESS — D1 RECLAIMED, creator credit 4 GEN |
| creator reclaim D2 `0xfacb9538a391647978a7c1284e1b4491c5e77bc8f0d9d16c3190bfbd9e9a003e` | SUCCESS — D2 RECLAIMED, creator credit 6 GEN |
| creator withdraw `0x19532a7139b96d26c4a63cbaf8559740edcdcb3e984d2a9bda5492d3cc4cd6ba` | SUCCESS — EOA 9952.999999999999999999 → 9958.999999999999999999 GEN |

After the reclaims and creator withdraw: received 47 GEN,
withdrawn 47 GEN, credits 0, escrow 0, contract balance 1 wei,
`invariant_ok` true.

## 8. After D3 expiry

| tx | result |
| --- | --- |
| creator reclaim D3 `0x659e34996c2db336b9e80c820a5f2ed87713cda721243825ffa19380df3aedc4` | SUCCESS — D3 RECLAIMED, remaining 0 GEN (Grace had already claimed the only leaf) |

## Final read-backs (2026-11-09T23:25:25.939Z)

- D0: ACTIVE, claimed 3 of 3, claimed 30 GEN, remaining 0
- D1: RECLAIMED, claimed 0, remaining 0
- D2: RECLAIMED, claimed 1 of 2 (Eve), remaining 0
- D3: RECLAIMED, claimed 1 of 1 (Grace), remaining 0, expiry 1794266658
- `get_totals`: received 47 GEN, withdrawn 47 GEN, credits 0,
  escrow 0, `invariant_ok` true, contract balance 1 wei
  (the stranded failed-payable probe wei; `balance_matches_held`
  is false by exactly that 1 wei, as designed)
- EOA balances (wei, exact): creator 9958999999999999999999,
  Alice 10005000000000000000000, Bob 10010000000000000000000,
  Carol 10015000000000000000000, Dave 10000000000000000000000,
  Eve 10010000000000000000000, Frank 10000000000000000000000,
  Grace 10001000000000000000000, stranger 10000000000000000000000

## Independent re-check

`node scripts/verify.mjs` — read-only, no keys, no writes:
67 checks, all PASS (source SHA, deployed code bytes, all 30
receipts FINALIZED / MAJORITY_AGREE with the expected
SUCCESS/ERROR outcome, all final read-backs, all EOA balances).
