/* On-chain evidence flow for MerkleDistributor on Stable Studionet.
 *
 * Usage: node scripts/flow.mjs   (uses deployment.json for the address)
 *
 * Ephemeral accounts only (keys never written to disk). Every account
 * is funded 10000 GEN from the faucet simulation (sim_fundAccount;
 * real testnet GEN, zero cash cost).
 *
 * Flow:
 *   0. Failed-payable probe FIRST: create_distribution with an invalid
 *      root and 1 wei. The call must fail; afterwards the contract
 *      balance tells us whether a failed payable keeps its value
 *      (recorded honestly in evidence.json, never assumed).
 *   1. Create D0 (Alice 5 / Bob 10 / Carol 15 GEN, funded 30 GEN),
 *      D1 (Dave 4 GEN, funded 4 GEN, short expiry),
 *      D2 (Eve 10 / Frank 10 GEN, funded 12 GEN = underfunded),
 *      D3 (Grace 1 GEN, funded 1 GEN, extendable).
 *   2. Extend D3 (creator only; stranger extend must fail).
 *   3. Happy claims on D0 (Bob's claim is relayed by a stranger: the
 *      credit must still go to Bob), then the adversarial cases, each
 *      of which must fail with the expected error and change no state:
 *      double claim, tampered proof, wrong amount, checksummed
 *      address, 33-step proof, stranger withdraw.
 *   4. D2: Eve claims 10 GEN; Frank's claim must fail with
 *      insufficient_escrow; Frank's leaf stays unclaimed.
 *   5. Grace claims 1 GEN on D3. All five leaf owners withdraw their
 *      credits (pull payments); EOA balances are checked to the wei.
 *   6. After D1/D2 expire: Dave's claim must fail (expired), a
 *      stranger reclaim must fail (not creator), the creator reclaims
 *      D1 (4 GEN) and D2 (2 GEN), then withdraws the 6 GEN.
 *   7. After D3 expires: the creator reclaims D3 (0 GEN remainder).
 *   8. Final read-backs: every distribution, get_totals, every EOA
 *      balance, contract balance; the money invariant is asserted.
 *
 * RPC discipline (old-line lesson: the shared RPC returns HTML error
 * pages and rate-limits at 500 requests/hour): reads retry with
 * exponential back-off; receipts are polled slowly (12 s); a write is
 * submitted exactly ONCE per attempt and never re-submitted on a
 * polling failure — the same hash is polled until it finalizes.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createClient, createAccount, generatePrivateKey } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const deployment = JSON.parse(readFileSync(path.join(root, "deployment.json"), "utf-8"));
const address = process.env.CONTRACT_ADDRESS || deployment.contractAddress;
if (!address) throw new Error("No contract address: set CONTRACT_ADDRESS or run deploy first");

const GEN = 10n ** 18n;
const FUND_GEN = 10000;
const genStr = (wei) => {
  const w = BigInt(wei);
  const whole = w / GEN;
  const frac = w % GEN;
  if (frac === 0n) return `${whole} GEN`;
  return `${whole}.${frac.toString().padStart(18, "0").replace(/0+$/, "")} GEN`;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- off-chain Merkle helpers (same definitions as scripts/merkle_lib.py) ---
const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const leafHash = (addr, amtStr) => sha(addr + ":" + amtStr);
function buildTree(pairs) {
  let level = pairs.map((p) => leafHash(p.address, p.amount));
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(sha(level[i] + level[i + 1]));
    if (level.length % 2 === 1) next.push(level[level.length - 1]);
    levels.push(next);
    level = next;
  }
  return { levels, root: levels[levels.length - 1][0] };
}
function recomputeRoot(leaf, proof) {
  let current = leaf;
  for (const step of proof) {
    current = step.left ? sha(step.sibling + current) : sha(current + step.sibling);
  }
  return current;
}
function proofFor(levels, idx) {
  const proof = [];
  let pos = idx;
  for (let l = 0; l < levels.length - 1; l++) {
    const level = levels[l];
    if (pos % 2 === 0) {
      if (pos + 1 < level.length) proof.push({ sibling: level[pos + 1], left: false });
    } else {
      proof.push({ sibling: level[pos - 1], left: true });
    }
    pos = Math.floor(pos / 2);
  }
  return proof;
}

// --- accounts (ephemeral; keys never leave this process) --------------------
const names = ["creator", "alice", "bob", "carol", "dave", "eve", "frank", "grace", "stranger"];
const accounts = {};
for (const name of names) {
  accounts[name] = createAccount(generatePrivateKey());
  console.log(`${name}: ${accounts[name].address} (leaf: ${accounts[name].address.toLowerCase()})`);
}
const leaf = (name) => accounts[name].address.toLowerCase();
console.log("Contract:", address);

const clientFor = (account) => createClient({ chain: studionet, account });
const reader = clientFor(accounts.creator);

const evidence = {
  network: "Stable Studionet",
  chainId: 61999,
  rpcUrl: "https://studio.genlayer.com/api",
  contractAddress: address,
  deployTxHash: deployment.deployTxHash,
  contractFile: "contracts/merkle_distributor.py",
  contractSha256: deployment.contractSha256,
  deployedCodeSha256: deployment.deployedCodeSha256,
  deployedCodeMatchesSource: deployment.deployedCodeMatchesSource,
  accounts: Object.fromEntries(names.map((n) => [n, accounts[n].address])),
  leafAddresses: Object.fromEntries(names.map((n) => [n, leaf(n)])),
  funding: {},
  failedPayableProbe: null,
  distributions: [],
  transactions: [],
  finalReadbacks: null,
  invariant: null,
  generatedAt: new Date().toISOString(),
};
const save = () => writeFileSync(path.join(root, "evidence.json"), JSON.stringify(evidence, null, 2) + "\n");

// --- rate-limit-aware reads --------------------------------------------------
const RETRYABLE = /html|429|rate limit|too many|ECONNRESET|ETIMEDOUT|fetch failed|Unexpected token|Service Unavailable|Bad Gateway|Gateway Timeout|temporarily|RLP|internal error|InternalRpcError|32603/i;
function retryAfterMs(err) {
  // genlayer-js surfaces the RPC error as err.cause = { code: -32029,
  // message: 'Rate limit exceeded...', data: { retry_after_seconds } }.
  let node = err;
  for (let i = 0; i < 5 && node; i++) {
    const secs = node?.data?.retry_after_seconds ?? node?.cause?.data?.retry_after_seconds;
    if (typeof secs === "number" && secs > 0) return Math.min(secs * 1000, 1500000);
    if (typeof node?.message === "string" && /rate limit/i.test(node.message)) {
      const m = node.message.match(/retry_after_seconds\D*(\d+)/);
      if (m) return Math.min(Number(m[1]) * 1000, 1500000);
    }
    node = node?.cause;
  }
  return null;
}
async function withRetry(fn, label, maxAttempts = 15) {
  let delay = 5000;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const out = await fn();
      if (typeof out === "string" && out.trimStart().startsWith("<")) {
        throw new Error("HTML error page instead of JSON");
      }
      return out;
    } catch (e) {
      const msg = String(e?.message || e);
      if (attempt === maxAttempts || !RETRYABLE.test(msg)) throw e;
      const wait = retryAfterMs(e) ?? delay;
      console.log(`  [retry ${label} attempt ${attempt}/${maxAttempts} after ${Math.round(wait / 1000)}s: ${msg.slice(0, 120)}]`);
      await sleep(wait);
      delay = Math.min(delay * 2, 60000);
    }
  }
}

async function rpc(method, params) {
  return withRetry(() => reader.request({ method, params }), `rpc ${method}`);
}

async function readJson(functionName, args = []) {
  const raw = await withRetry(
    () => reader.readContract({ address, functionName, args }),
    `read ${functionName}`,
  );
  if (typeof raw === "string" && (raw.startsWith("{") || raw.startsWith("["))) return JSON.parse(raw);
  return raw;
}

async function getBalanceWei(addr) {
  const bal = await withRetry(
    () => reader.getBalance({ address: addr }),
    `balance ${addr.slice(0, 10)}`,
  );
  return BigInt(bal.toString());
}

async function contractBalanceWei() {
  const hex = await rpc("eth_getBalance", [address, "latest"]);
  return BigInt(hex);
}

// --- receipt polling (slow; never re-submits) --------------------------------
const STATUS = { 0: "UNINITIALIZED", 1: "PENDING", 2: "PROPOSING", 3: "COMMITTING", 4: "REVEALING", 5: "ACCEPTED", 6: "UNDETERMINED", 7: "FINALIZED", 8: "CANCELED" };
const statusOf = (r) => r.status_name ?? r.statusName ?? STATUS[r.status] ?? String(r.status ?? "");
const resultOf = (r) => r.result_name ?? r.resultName ?? "";
function leaderOf(receipt) {
  const list = receipt.consensus_data?.leader_receipt || [];
  const arr = Array.isArray(list) ? list : [list];
  return arr.find((x) => x.mode === "leader") || arr[arr.length - 1] || {};
}

// The leader's `result` field carries the UserError payload, base64-encoded
// (e.g. "\x01EXPECTED: leaf_already_claimed"); a runner-level traceback
// lands in stderr instead. Both are error text.
function decodeResultField(value) {
  if (typeof value !== "string" || !value) return "";
  try {
    return Buffer.from(value, "base64").toString("utf-8").replace(/^[^\x20-\x7E]+/, "");
  } catch {
    return "";
  }
}
function errorTextOf(leader) {
  const fromResult = decodeResultField(leader.result);
  const fromStderr = (leader.genvm_result?.stderr || leader.stderr || "").toString();
  return [fromResult, fromStderr].filter(Boolean).join("\n");
}

async function pollReceipt(hash, label, maxPolls = 40, intervalMs = 12000) {
  for (let i = 0; i < maxPolls; i++) {
    const receipt = await rpc("eth_getTransactionByHash", [hash]);
    if (receipt && (statusOf(receipt) === "FINALIZED" || statusOf(receipt) === "CANCELED")) {
      return receipt;
    }
    if (i % 5 === 0) console.log(`  ${label}: waiting (${statusOf(receipt || {}) || "unknown"}), poll ${i + 1}/${maxPolls}`);
    await sleep(intervalMs);
  }
  throw new Error(`${label} did not finalize after ${maxPolls} polls (tx ${hash})`);
}

// --- writes: submitted exactly once per attempt ------------------------------
async function write(account, functionName, args, label, value = 0n, expectError = null) {
  const client = clientFor(account);
  // NOTE: no retry around this submit. If it throws, the flow stops
  // loudly instead of risking a duplicate submission.
  const hash = await client.writeContract({ address, functionName, args, value, leaderOnly: false });
  console.log(`${label} tx: ${hash}${value > 0n ? ` (value ${genStr(value)})` : ""}`);
  const receipt = await pollReceipt(hash, label);
  const status = statusOf(receipt);
  const consensus = resultOf(receipt);
  const leader = leaderOf(receipt);
  const execution = leader.execution_result || leader.executionResult || "";
  const stderr = errorTextOf(leader);
  const record = {
    label,
    method: functionName,
    args: JSON.parse(JSON.stringify(args, (k, v) => (typeof v === "bigint" ? v.toString() : v))),
    sender: account.address,
    value_wei: value.toString(),
    txHash: hash,
    receiptStatus: status,
    consensus,
    execution,
    expected_error: expectError,
    stderr_excerpt: stderr.slice(0, 500),
  };
  evidence.transactions.push(record);
  save();
  if (status !== "FINALIZED") throw new Error(`${label} ended ${status}, not FINALIZED (tx ${hash})`);
  if (consensus !== "MAJORITY_AGREE") throw new Error(`${label} consensus ${consensus}, not MAJORITY_AGREE (tx ${hash})`);
  if (expectError) {
    if (execution !== "ERROR") throw new Error(`${label} expected ERROR but leader executed ${execution} (tx ${hash})`);
    if (!stderr.includes(expectError)) {
      throw new Error(`${label} expected error ${expectError} but stderr was: ${stderr.slice(0, 300)} (tx ${hash})`);
    }
    console.log(`  ${label}: FINALIZED / MAJORITY_AGREE / ERROR (${expectError}) as expected`);
  } else {
    if (execution !== "SUCCESS") throw new Error(`${label} expected SUCCESS but leader executed ${execution}: ${stderr.slice(0, 300)} (tx ${hash})`);
    console.log(`  ${label}: FINALIZED / MAJORITY_AGREE / SUCCESS`);
  }
  return { hash, receipt, record };
}

async function attemptError(account, functionName, args, label, expectedError, value = 0n) {
  const attemptHashes = [];
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const out = await write(account, functionName, args, `${label} (attempt ${attempt})`, value, expectedError);
      return { ...out, attemptHashes };
    } catch (e) {
      const last = evidence.transactions[evidence.transactions.length - 1];
      if (last && last.txHash) attemptHashes.push(last.txHash);
      console.log(`  ${label} attempt ${attempt} did not reach agreed error: ${String(e.message || e).slice(0, 200)}`);
      if (attempt === 3) throw new Error(`${label} failed on all 3 attempts; hashes: ${attemptHashes.join(", ")}; last error: ${e.message}`);
      await sleep(15000);
    }
  }
  throw new Error("unreachable");
}

function assertEq(actual, expected, label) {
  if (String(actual) !== String(expected)) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

// Read-backs right after a FINALIZED write can lag the node's read view
// (observed: an EOA balance read immediately after a FINALIZED withdraw
// still showed the old value, while a re-read seconds later showed the
// transfer). Poll until the expected state appears instead of trusting
// the first read.
async function pollUntil(label, fn, ok, timeoutMs = 90000, intervalMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  for (;;) {
    last = await fn();
    if (ok(last)) return last;
    if (Date.now() >= deadline) {
      throw new Error(`${label}: state did not appear within ${timeoutMs / 1000}s; last value: ${JSON.stringify(last).slice(0, 400)}`);
    }
    await sleep(intervalMs);
  }
}

async function checkTotals(label) {
  const { totals, balance } = await pollUntil(
    `totals ${label}`,
    async () => {
      const t = await readJson("get_totals", []);
      const b = await contractBalanceWei();
      return { totals: t, balance: b };
    },
    ({ totals, balance }) =>
      totals.invariant_ok === true &&
      totals.contract_balance_wei === balance.toString(),
  );
  console.log(`  totals [${label}]: received ${genStr(totals.total_received_wei)}, withdrawn ${genStr(totals.total_withdrawn_wei)}, credits ${genStr(totals.credits_outstanding_wei)}, escrow ${genStr(totals.escrow_locked_wei)}, balance ${genStr(balance)}, invariant_ok=${totals.invariant_ok}`);
  return { totals, balance };
}

// ===========================================================================
// Main flow
// ===========================================================================
const t0 = Math.floor(Date.now() / 1000);
console.log("Flow start (unix):", t0, new Date(t0 * 1000).toISOString());

// --- 0. fund all accounts ----------------------------------------------------
for (const name of names) {
  const account = accounts[name];
  const client = clientFor(account);
  const fundTx = await withRetry(
    () => client.request({ method: "sim_fundAccount", params: [account.address, FUND_GEN * 10 ** 18] }),
    `fund ${name}`,
  );
  const bal = await getBalanceWei(account.address);
  assertEq(bal, BigInt(FUND_GEN) * GEN, `fund ${name} balance`);
  evidence.funding[name] = { address: account.address, funded_gen: FUND_GEN, fundTx: String(fundTx), balance_after_wei: bal.toString() };
  console.log(`fund ${name}: balance ${genStr(bal)}`);
}
save();

// --- 0b. failed-payable probe: invalid root + 1 wei ---------------------------
// The contract may already hold stranded wei from an earlier probe run
// (a failed payable keeps its value); measure it first so the final
// invariant can account for every wei.
console.log("\n--- probe: failing payable create (bad root, 1 wei) ---");
const PRE_STRANDED_WEI = await contractBalanceWei();
console.log(`  contract balance before probe: ${PRE_STRANDED_WEI} wei (pre-existing stranded)`);
{
  const balanceBefore = await contractBalanceWei();
  const probe = await write(
    accounts.creator, "create_distribution",
    ["g".repeat(64), String(t0 + 3600), "probe"],
    "probe-failing-payable-create", 1n, "root_must_be_64_lowercase_hex",
  );
  const balanceAfter = await contractBalanceWei();
  const totals = await readJson("get_totals", []);
  const kept = balanceAfter - balanceBefore;
  evidence.failedPayableProbe = {
    label: "create_distribution with invalid root and 1 wei must fail",
    txHash: probe.hash,
    value_wei: "1",
    expected_error: "root_must_be_64_lowercase_hex",
    receiptStatus: probe.record.receiptStatus,
    consensus: probe.record.consensus,
    execution: probe.record.execution,
    contract_balance_before_wei: balanceBefore.toString(),
    contract_balance_after_wei: balanceAfter.toString(),
    value_kept_wei: kept.toString(),
    value_kept: kept !== 0n,
    total_received_wei_after: totals.total_received_wei,
    distribution_count_after: totals.distribution_count,
    note: kept === 0n
      ? "Failed payable kept no value: the 1 wei was reverted with the failed call."
      : "Failed payable KEPT its value in the contract; the stranded wei is carried explicitly in the final invariant (see finalReadbacks.stranded_wei).",
  };
  evidence.failedPayableProbe.preExistingStrandedWei = PRE_STRANDED_WEI.toString();
  save();
  console.log(`  probe: value kept = ${kept} wei; total_received still ${totals.total_received_wei}; distributions ${totals.distribution_count}`);
}
const PROBE_KEPT_WEI = BigInt(evidence.failedPayableProbe.value_kept_wei);
const STRANDED_WEI = PRE_STRANDED_WEI + PROBE_KEPT_WEI;

// Preflight: the flow assumes a fresh contract (no distributions yet).
// A previous partial run leaves distributions behind with lost creator
// keys; re-running against such a contract would silently shift every
// distribution id. Fail fast here instead of 15 minutes in.
{
  const pre = await readJson("get_totals", []);
  if (pre.distribution_count !== 0) {
    throw new Error(`contract is not fresh: ${pre.distribution_count} distributions already exist (a previous partial run). Redeploy a fresh contract before running the flow.`);
  }
  if (pre.total_received_wei !== "0") {
    throw new Error(`contract is not fresh: total_received_wei is ${pre.total_received_wei}, expected 0. Redeploy a fresh contract before running the flow.`);
  }
  console.log("  preflight: fresh contract (0 distributions, 0 received, stranded " + STRANDED_WEI + " wei)");
}

// --- 1. build trees and create D0..D3 -----------------------------------------
const dists = [
  { id: "0", label: "main", leaves: [["alice", 5], ["bob", 10], ["carol", 15]], funded: 30, expiry: t0 + 86400 },
  { id: "1", label: "short", leaves: [["dave", 4]], funded: 4, expiry: t0 + 900 },
  { id: "2", label: "underfunded", leaves: [["eve", 10], ["frank", 10]], funded: 12, expiry: t0 + 900 },
  { id: "3", label: "extendable", leaves: [["grace", 1]], funded: 1, expiry: t0 + 900 },
];
for (const d of dists) {
  const pairs = d.leaves.map(([n, g]) => ({ address: leaf(n), amount: (BigInt(g) * GEN).toString() }));
  const { levels, root } = buildTree(pairs);
  d.root = root;
  d.levels = levels;
  d.pairs = pairs;
  d.proofs = pairs.map((_, i) => proofFor(levels, i));
  d.leafHashes = pairs.map((p) => leafHash(p.address, p.amount));
  // Off-chain pre-check: recompute every leaf's root from its proof
  // locally. (gen_call reads carrying a proof argument longer than ~90
  // chars fail on this runner with an RLP error, so the on-chain
  // verify_proof view cannot pre-check real proofs; the claim
  // transaction itself is the on-chain check.)
  for (let i = 0; i < pairs.length; i++) {
    if (recomputeRoot(d.leafHashes[i], d.proofs[i]) !== root) throw new Error(`off-chain proof mismatch for D${d.id} leaf ${i}`);
  }
  console.log(`D${d.id} (${d.label}): root ${root.slice(0, 16)}... ${d.leaves.length} leaves, funded ${d.funded} GEN, expiry ${d.expiry}`);
}
for (const d of dists) {
  const receipt = await write(
    accounts.creator, "create_distribution",
    [d.root, String(d.expiry), d.label],
    `create-D${d.id}-${d.label}`, BigInt(d.funded) * GEN,
  );
  const back = await pollUntil(
    `D${d.id} readback`,
    () => readJson("get_distribution", [d.id]),
    (b) =>
      b.id === d.id &&
      b.root === d.root &&
      b.expiry === String(d.expiry) &&
      b.funded_wei === (BigInt(d.funded) * GEN).toString() &&
      b.remaining_wei === (BigInt(d.funded) * GEN).toString() &&
      b.status === "ACTIVE",
  );
  evidence.distributions.push({
    id: d.id, label: d.label, root: d.root, expiry: d.expiry,
    funded_wei: (BigInt(d.funded) * GEN).toString(),
    leaves: d.leaves.map(([n, g], i) => ({
      name: n, address: leaf(n), amount_wei: (BigInt(g) * GEN).toString(),
      leaf_hash: d.leafHashes[i], proof: d.proofs[i],
    })),
    createTxHash: receipt.hash,
  });
  save();
}
await checkTotals("after creates");

// --- 2. extend D3 (stranger must fail, creator succeeds) ----------------------
console.log("\n--- extend D3 ---");
await attemptError(
  accounts.stranger, "extend_distribution", ["3", String(t0 + 900)],
  "adversarial-stranger-extend-D3", "only_creator_can_extend",
);
{
  const back = await readJson("get_distribution", ["3"]);
  assertEq(back.expiry, String(dists[3].expiry), "stranger extend changed nothing");
}
const newExpiryD3 = t0 + 1800;
await write(accounts.creator, "extend_distribution", ["3", String(newExpiryD3)], "extend-D3-creator");
{
  const back = await pollUntil(
    `D3 expiry after extend`,
    () => readJson("get_distribution", ["3"]),
    (b) => b.expiry === String(newExpiryD3),
  );
  dists[3].expiry = newExpiryD3;
  evidence.distributions[3].expiry = newExpiryD3;
  save();
}

// --- 3. happy claims on D0 ----------------------------------------------------
console.log("\n--- happy claims D0 ---");
async function claimOk(distId, name, proof, fromName) {
  const d = dists[Number(distId)];
  const idx = d.leaves.findIndex(([n]) => n === name);
  const amount = (BigInt(d.leaves[idx][1]) * GEN).toString();
  const before = await readJson("get_distribution", [distId]);
  const expectCount = before.claimed_count + 1;
  const expectRemaining = (BigInt(before.remaining_wei) - BigInt(amount)).toString();
  const out = await write(
    accounts[fromName], "claim",
    [distId, leaf(name), amount, JSON.stringify(proof)],
    `claim-D${distId}-${name} (from ${fromName})`,
  );
  await pollUntil(
    `D${distId} after ${name} claim`,
    () => readJson("get_distribution", [distId]),
    (b) => b.claimed_count === expectCount && b.remaining_wei === expectRemaining,
  );
  await pollUntil(
    `${name} credit after claim`,
    () => readJson("get_credit", [leaf(name)]),
    (c) => c.credit_wei === amount,
  );
  await pollUntil(
    `${name} is_claimed after claim`,
    () => readJson("is_claimed", [distId, d.leafHashes[idx]]),
    (c) => c.claimed === true,
  );
  return out;
}
await claimOk("0", "alice", dists[0].proofs[0], "alice");
await claimOk("0", "bob", dists[0].proofs[1], "stranger"); // relayed: credit still goes to Bob
{
  const bobCredit = await readJson("get_credit", [leaf("bob")]);
  assertEq(bobCredit.credit_wei, (10n * GEN).toString(), "Bob credit 10 GEN after relayed claim");
  const strangerCredit = await readJson("get_credit", [leaf("stranger")]);
  assertEq(strangerCredit.credit_wei, "0", "relayer got no credit");
}
await claimOk("0", "carol", dists[0].proofs[2], "carol");
{
  await pollUntil(
    "D0 fully claimed",
    () => readJson("get_distribution", ["0"]),
    (b) => b.claimed_count === 3 && b.remaining_wei === "0",
  );
}
await checkTotals("after D0 claims");

// --- 3b. adversarial cases on D0 (all must fail, no state change) ------------
console.log("\n--- adversarial cases on D0 ---");
async function assertD0Unchanged(label) {
  const back = await readJson("get_distribution", ["0"]);
  assertEq(back.claimed_count, 3, `${label}: D0 claimed_count unchanged`);
  assertEq(back.remaining_wei, "0", `${label}: D0 remaining unchanged`);
  const aliceCredit = await readJson("get_credit", [leaf("alice")]);
  assertEq(aliceCredit.credit_wei, (5n * GEN).toString(), `${label}: Alice credit unchanged`);
}
await attemptError(accounts.alice, "claim", ["0", leaf("alice"), (5n * GEN).toString(), JSON.stringify(dists[0].proofs[0])], "adversarial-double-claim-alice", "leaf_already_claimed");
await assertD0Unchanged("double-claim");
// The remaining proof cases need an UNCLAIMED leaf: the contract checks
// the claimed bit before the proof, so a tampered proof for an already
// claimed leaf fails with leaf_already_claimed instead. Frank's D2 leaf
// is still unclaimed here (Eve claims in the next section).
async function assertD2Unchanged(label) {
  const back = await readJson("get_distribution", ["2"]);
  assertEq(back.claimed_count, 0, `${label}: D2 claimed_count unchanged`);
  assertEq(back.remaining_wei, (12n * GEN).toString(), `${label}: D2 remaining unchanged`);
  const eveCredit = await readJson("get_credit", [leaf("eve")]);
  assertEq(eveCredit.credit_wei, "0", `${label}: Eve credit unchanged`);
  const frankCredit = await readJson("get_credit", [leaf("frank")]);
  assertEq(frankCredit.credit_wei, "0", `${label}: Frank credit unchanged`);
}
{
  const tampered = JSON.parse(JSON.stringify(dists[2].proofs[1]));
  tampered[0].sibling = (tampered[0].sibling[0] === "0" ? "1" : "0") + tampered[0].sibling.slice(1);
  await attemptError(accounts.frank, "claim", ["2", leaf("frank"), (10n * GEN).toString(), JSON.stringify(tampered)], "adversarial-tampered-proof-frank", "proof_does_not_match_root");
}
await assertD2Unchanged("tampered-proof");
await attemptError(accounts.frank, "claim", ["2", leaf("frank"), (11n * GEN).toString(), JSON.stringify(dists[2].proofs[1])], "adversarial-wrong-amount-frank", "proof_does_not_match_root");
await assertD2Unchanged("wrong-amount");
await attemptError(accounts.bob, "claim", ["0", "0x" + "B".repeat(40), (10n * GEN).toString(), JSON.stringify(dists[0].proofs[1])], "adversarial-checksummed-address-bob", "leaf_address_must_be_lowercase_0x_hex");
await assertD0Unchanged("checksummed-address");
await attemptError(
  accounts.frank, "claim",
  ["2", leaf("frank"), (10n * GEN).toString(), JSON.stringify(Array.from({ length: 33 }, () => ({ sibling: "a".repeat(64), left: false })))],
  "adversarial-proof-too-long", "proof_too_long",
);
await assertD2Unchanged("proof-too-long");
await attemptError(accounts.stranger, "withdraw_payout", [], "adversarial-stranger-withdraw", "no_credit_to_withdraw");
await assertD0Unchanged("stranger-withdraw");

// --- 4. D2 underfunded: Eve ok, Frank must fail -------------------------------
console.log("\n--- D2 underfunded ---");
await claimOk("2", "eve", dists[2].proofs[0], "eve");
await attemptError(accounts.frank, "claim", ["2", leaf("frank"), (10n * GEN).toString(), JSON.stringify(dists[2].proofs[1])], "adversarial-underfunded-frank-claim", "insufficient_escrow");
{
  const claimed = await readJson("is_claimed", ["2", dists[2].leafHashes[1]]);
  if (claimed.claimed !== false) throw new Error("Frank leaf must stay unclaimed after escrow failure");
  const back = await readJson("get_distribution", ["2"]);
  assertEq(back.remaining_wei, (2n * GEN).toString(), "D2 remaining 2 GEN after Eve");
  console.log("  Frank leaf still unclaimed; D2 remaining 2 GEN");
}

// --- 5. Grace claims D3; all leaf owners withdraw -----------------------------
console.log("\n--- Grace claims D3; withdrawals ---");
await claimOk("3", "grace", dists[3].proofs[0], "grace");
async function withdrawOk(name) {
  const before = await getBalanceWei(accounts[name].address);
  const credit = await readJson("get_credit", [leaf(name)]);
  const amount = BigInt(credit.credit_wei);
  if (amount === 0n) throw new Error(`${name} has no credit to withdraw`);
  await write(accounts[name], "withdraw_payout", [], `withdraw-${name}`);
  const after = await pollUntil(
    `${name} EOA balance after withdraw`,
    () => getBalanceWei(accounts[name].address),
    (b) => b - before === amount,
  );
  await pollUntil(
    `${name} credit zeroed after withdraw`,
    () => readJson("get_credit", [leaf(name)]),
    (c) => c.credit_wei === "0",
  );
  console.log(`  ${name} withdrew ${genStr(amount)}; EOA ${genStr(before)} -> ${genStr(after)}`);
}
for (const n of ["alice", "bob", "carol", "eve", "grace"]) await withdrawOk(n);
await checkTotals("after leaf withdrawals");

// --- 6. wait for D1/D2 expiry; expired claim, stranger reclaim, creator reclaims
console.log("\n--- wait for D1/D2 expiry ---");
{
  const target = t0 + 920;
  const nowSec = Math.floor(Date.now() / 1000);
  if (nowSec < target) {
    console.log(`  sleeping ${target - nowSec}s until D1/D2 expiry passes`);
    await sleep((target - nowSec) * 1000);
  }
}
await attemptError(accounts.dave, "claim", ["1", leaf("dave"), (4n * GEN).toString(), JSON.stringify(dists[1].proofs[0])], "adversarial-expired-claim-dave", "distribution_expired");
{
  const claimed = await readJson("is_claimed", ["1", dists[1].leafHashes[0]]);
  if (claimed.claimed !== false) throw new Error("Dave leaf must stay unclaimed after expired claim");
}
await attemptError(accounts.stranger, "reclaim_distribution", ["1"], "adversarial-stranger-reclaim-D1", "only_creator_can_reclaim");
{
  const back = await readJson("get_distribution", ["1"]);
  assertEq(back.status, "ACTIVE", "stranger reclaim changed nothing");
}
await write(accounts.creator, "reclaim_distribution", ["1"], "reclaim-D1-creator");
{
  await pollUntil(
    "D1 after reclaim",
    () => readJson("get_distribution", ["1"]),
    (b) => b.status === "RECLAIMED" && b.remaining_wei === "0",
  );
  await pollUntil(
    "creator credit after D1 reclaim",
    () => readJson("get_credit", [leaf("creator")]),
    (c) => c.credit_wei === (4n * GEN).toString(),
  );
}
await write(accounts.creator, "reclaim_distribution", ["2"], "reclaim-D2-creator");
{
  await pollUntil(
    "D2 after reclaim",
    () => readJson("get_distribution", ["2"]),
    (b) => b.status === "RECLAIMED",
  );
  await pollUntil(
    "creator credit after D1+D2 reclaims",
    () => readJson("get_credit", [leaf("creator")]),
    (c) => c.credit_wei === (6n * GEN).toString(),
  );
}
await withdrawOk("creator");
await checkTotals("after reclaims + creator withdraw");

// --- 7. wait for D3 expiry; creator reclaims the 0 remainder ------------------
console.log("\n--- wait for D3 expiry ---");
{
  const target = newExpiryD3 + 20;
  const nowSec = Math.floor(Date.now() / 1000);
  if (nowSec < target) {
    console.log(`  sleeping ${target - nowSec}s until D3 expiry passes`);
    await sleep((target - nowSec) * 1000);
  }
}
await write(accounts.creator, "reclaim_distribution", ["3"], "reclaim-D3-creator");
{
  await pollUntil(
    "D3 after reclaim",
    () => readJson("get_distribution", ["3"]),
    (b) => b.status === "RECLAIMED" && b.remaining_wei === "0",
  );
}

// --- 8. final read-backs --------------------------------------------------------
console.log("\n--- final read-backs ---");
const finalDistributions = [];
for (const d of dists) finalDistributions.push(await readJson("get_distribution", [d.id]));
const finalTotals = await readJson("get_totals", []);
const finalContractBalance = await contractBalanceWei();
const finalEoa = {};
const expectedEoa = {
  creator: (BigInt(FUND_GEN) * GEN - 47n * GEN + 6n * GEN - PROBE_KEPT_WEI).toString(),
  alice: (BigInt(FUND_GEN) * GEN + 5n * GEN).toString(),
  bob: (BigInt(FUND_GEN) * GEN + 10n * GEN).toString(),
  carol: (BigInt(FUND_GEN) * GEN + 15n * GEN).toString(),
  dave: (BigInt(FUND_GEN) * GEN).toString(),
  eve: (BigInt(FUND_GEN) * GEN + 10n * GEN).toString(),
  frank: (BigInt(FUND_GEN) * GEN).toString(),
  grace: (BigInt(FUND_GEN) * GEN + 1n * GEN).toString(),
  stranger: (BigInt(FUND_GEN) * GEN).toString(),
};
for (const name of names) {
  finalEoa[name] = (
    await pollUntil(
      `final EOA balance ${name}`,
      () => getBalanceWei(accounts[name].address),
      (b) => b.toString() === expectedEoa[name],
    )
  ).toString();
}
const held = BigInt(finalTotals.credits_outstanding_wei) + BigInt(finalTotals.escrow_locked_wei);
const strandedFinal = finalContractBalance - held;
assertEq(finalTotals.total_received_wei, (47n * GEN).toString(), "final received 47 GEN");
assertEq(finalTotals.total_withdrawn_wei, (47n * GEN).toString(), "final withdrawn 47 GEN");
assertEq(finalTotals.credits_outstanding_wei, "0", "final credits 0");
assertEq(finalTotals.escrow_locked_wei, "0", "final escrow 0");
if (finalTotals.invariant_ok !== true) throw new Error("final invariant_ok false");
if (strandedFinal !== STRANDED_WEI) throw new Error(`final stranded ${strandedFinal} wei != probe ${STRANDED_WEI} wei`);
console.log("  final totals:", JSON.stringify(finalTotals));
console.log(`  final contract balance: ${genStr(finalContractBalance)} (stranded ${strandedFinal} wei from the probe)`);
console.log("  final EOA balances all match expected values to the wei");

evidence.finalReadbacks = {
  distributions: finalDistributions,
  totals: finalTotals,
  contractBalanceWei: finalContractBalance.toString(),
  strandedWei: strandedFinal.toString(),
  eoaBalancesWei: finalEoa,
  expectedEoaBalancesWei: expectedEoa,
  readBackAt: new Date().toISOString(),
};
evidence.invariant = {
  received_wei: finalTotals.total_received_wei,
  withdrawn_wei: finalTotals.total_withdrawn_wei,
  credits_outstanding_wei: finalTotals.credits_outstanding_wei,
  escrow_locked_wei: finalTotals.escrow_locked_wei,
  accounted_wei: finalTotals.accounted_wei,
  contract_balance_wei: finalTotals.contract_balance_wei,
  stranded_wei: strandedFinal.toString(),
  invariant_ok: finalTotals.invariant_ok,
  balance_matches_held_plus_stranded: (finalContractBalance - strandedFinal).toString() === (BigInt(finalTotals.credits_outstanding_wei) + BigInt(finalTotals.escrow_locked_wei)).toString(),
};
evidence.generatedAt = new Date().toISOString();
save();
console.log("\nFLOW COMPLETE. Wrote evidence.json with", evidence.transactions.length, "transactions.");
