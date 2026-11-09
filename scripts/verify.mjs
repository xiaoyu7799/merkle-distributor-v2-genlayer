/* Independent re-check of the MerkleDistributor deployment + evidence.
 *
 * Read-only: sends no transactions and no writes.
 * Usage: node scripts/verify.mjs
 *
 * Checks:
 *   1. Deployed code (gen_getContractCode, base64-decoded) is byte-for-byte
 *      the repo source; SHA-256 matches deployment.json / evidence.json.
 *   2. Every transaction in evidence.json is FINALIZED / MAJORITY_AGREE,
 *      sent by the recorded sender to the contract, with the leader
 *      execution result the evidence claims (SUCCESS, or ERROR with the
 *      expected error code in stderr).
 *   3. Live read-backs match evidence.json final read-backs: every
 *      distribution, get_totals, every leaf/creator credit, and the
 *      adversarial leaves still unclaimed.
 *   4. The money invariant holds live, and every EOA balance matches
 *      the evidence to the wei.
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const deployment = JSON.parse(readFileSync(path.join(root, "deployment.json"), "utf-8"));
const evidence = JSON.parse(readFileSync(path.join(root, "evidence.json"), "utf-8"));
const address = deployment.contractAddress;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const RETRYABLE = /html|429|rate limit|too many|ECONNRESET|ETIMEDOUT|fetch failed|Unexpected token|Service Unavailable|Bad Gateway|Gateway Timeout|temporarily/i;
function retryAfterMs(err) {
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
      if (typeof out === "string" && out.trimStart().startsWith("<")) throw new Error("HTML error page instead of JSON");
      return out;
    } catch (e) {
      const msg = String(e?.message || e);
      if (attempt === maxAttempts || !RETRYABLE.test(msg)) throw e;
      const wait = retryAfterMs(e) ?? delay;
      console.log(`  [retry ${label} ${attempt}/${maxAttempts} after ${Math.round(wait / 1000)}s]`);
      await sleep(wait);
      delay = Math.min(delay * 2, 60000);
    }
  }
}

const client = createClient({ chain: studionet });
const chain = await withRetry(() => client.request({ method: "eth_chainId", params: [] }), "chainId");
if (BigInt(chain) !== 61999n) throw new Error("Wrong network: " + chain);

let failures = 0;
const check = (ok, label) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}`);
  if (!ok) failures++;
};

// 1. source hash
const source = readFileSync(path.join(root, "contracts", "merkle_distributor.py"), "utf-8");
const sourceSha = createHash("sha256").update(source).digest("hex");
check(sourceSha === deployment.contractSha256, `source SHA matches deployment.json (${sourceSha.slice(0, 16)}...)`);
check(sourceSha === evidence.contractSha256, "source SHA matches evidence.json");
const cc = await withRetry(() => client.request({ method: "gen_getContractCode", params: [address] }), "gen_getContractCode");
let decoded = null;
try { decoded = Buffer.from(cc, "base64").toString("utf-8"); } catch { /* ignore */ }
if (decoded !== source && cc === source) decoded = cc;
check(decoded === source, "deployed code is byte-for-byte the repo source");
check(createHash("sha256").update(decoded || "").digest("hex") === sourceSha, "deployed code SHA matches source SHA");

// helpers
const STATUS = { 0: "UNINITIALIZED", 1: "PENDING", 2: "PROPOSING", 3: "COMMITTING", 4: "REVEALING", 5: "ACCEPTED", 6: "UNDETERMINED", 7: "FINALIZED", 8: "CANCELED" };
const statusOf = (r) => r.status_name ?? r.statusName ?? STATUS[r.status] ?? String(r.status ?? "");
const resultOf = (r) => r.result_name ?? r.resultName ?? "";
function leaderOf(receipt) {
  const list = receipt.consensus_data?.leader_receipt || [];
  const arr = Array.isArray(list) ? list : [list];
  return arr.find((x) => x.mode === "leader") || arr[arr.length - 1] || {};
}
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
async function readJson(functionName, args = []) {
  const raw = await withRetry(() => client.readContract({ address, functionName, args }), `read ${functionName}`);
  if (typeof raw === "string" && (raw.startsWith("{") || raw.startsWith("["))) return JSON.parse(raw);
  return raw;
}

// 2. every transaction
for (const tx of evidence.transactions) {
  const live = await withRetry(() => client.request({ method: "eth_getTransactionByHash", params: [tx.txHash] }), `tx ${tx.label}`);
  if (!live) { check(false, `${tx.label}: receipt not found (${tx.txHash})`); continue; }
  const leader = leaderOf(live);
  const execution = leader.execution_result || leader.executionResult || "";
  const stderr = errorTextOf(leader);
  const from = (live.from_address || live.sender || "").toLowerCase();
  const to = (live.to_address || live.recipient || "").toLowerCase();
  const okStatus = statusOf(live) === "FINALIZED" && tx.receiptStatus === "FINALIZED";
  const okConsensus = resultOf(live) === "MAJORITY_AGREE" && tx.consensus === "MAJORITY_AGREE";
  const okSender = from === tx.sender.toLowerCase();
  const okTarget = to === address.toLowerCase();
  const okExec = tx.expected_error
    ? execution === "ERROR" && stderr.includes(tx.expected_error)
    : execution === "SUCCESS";
  check(okStatus && okConsensus && okSender && okTarget && okExec,
    `${tx.label}: FINALIZED/MAJORITY_AGREE/${execution}${tx.expected_error ? ` (error ${tx.expected_error})` : ""} ${tx.txHash.slice(0, 18)}...`);
  if (!(okStatus && okConsensus && okSender && okTarget && okExec)) {
    console.log(`    live: status=${statusOf(live)} consensus=${resultOf(live)} execution=${execution} from=${from} to=${to} stderr=${stderr.slice(0, 200)}`);
  }
}

// 3. live read-backs vs evidence
const finalTotals = await readJson("get_totals", []);
check(JSON.stringify(finalTotals) === JSON.stringify(evidence.finalReadbacks.totals), "live get_totals matches evidence final totals");
for (const d of evidence.finalReadbacks.distributions) {
  const live = await readJson("get_distribution", [d.id]);
  check(JSON.stringify(live) === JSON.stringify(d), `live get_distribution(${d.id}) matches evidence (${d.label}, ${d.status})`);
}
for (const d of evidence.distributions) {
  for (const lf of d.leaves) {
    const live = await readJson("is_claimed", [d.id, lf.leaf_hash]);
    const saved = evidence.finalReadbacks.distributions[Number(d.id)].claimed[lf.leaf_hash] === true;
    check(live.claimed === saved, `live is_claimed D${d.id} ${lf.name} = ${live.claimed} (evidence ${saved})`);
    const credit = await readJson("get_credit", [lf.address]);
    check(credit.credit_wei === "0", `live get_credit ${lf.name} = 0 after withdrawals`);
  }
}
const creatorCredit = await readJson("get_credit", [evidence.leafAddresses.creator]);
check(creatorCredit.credit_wei === "0", "live creator credit = 0 after withdraw");
const liveBalance = BigInt(await withRetry(() => client.request({ method: "eth_getBalance", params: [address, "latest"] }), "contract balance"));
check(liveBalance.toString() === evidence.finalReadbacks.contractBalanceWei, `live contract balance ${liveBalance} matches evidence`);
check(
  BigInt(finalTotals.total_received_wei) === BigInt(finalTotals.total_withdrawn_wei) + BigInt(finalTotals.credits_outstanding_wei) + BigInt(finalTotals.escrow_locked_wei),
  "live money invariant holds",
);
check(finalTotals.invariant_ok === true, "live invariant_ok is true");

// 4. EOA balances
for (const [name, expected] of Object.entries(evidence.finalReadbacks.expectedEoaBalancesWei)) {
  const live = BigInt(await withRetry(() => client.getBalance({ address: evidence.accounts[name] }), `balance ${name}`));
  check(live.toString() === expected, `live EOA balance ${name} matches evidence (${live})`);
}

if (failures > 0) {
  console.log(`\nVERIFY FAILED: ${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nPASS: source, transactions, votes, call bindings, finalized state and balances. No writes were sent.");
