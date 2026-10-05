// Offline proof for mainnet-smoke/smoke.mjs — runs the SAME CLI entry point and the SAME tx builders against a
// Fleet MockChain behind a mocked network module (the four functions of createNodeApi). No node, no network:
// globalThis.fetch is replaced by a function that fails the run if anything tries to use it.
//
// The mock "node" is strict where MockChain is not: every submitted tx is checked for input existence,
// creationHeight <= next block height, the monotonic-creation-height rule, minimum box value per byte (360 nanoERG),
// token conservation (no burn; minting only with id = first input box id), a single >= 0.001 ERG miner-fee output,
// and then fully validated by sigma-rust (validate_tx: every input proof + ERG balance) against the same headers
// the script used to sign. Only then are the outputs applied to the MockChain UTXO set and one block is mined.
//
// Run: node mainnet-smoke/smoke.offline.test.mjs
import fs from "fs";
import os from "os";
import path from "path";
import { MockChain, mockUTxO, mockHeaders } from "@fleet-sdk/mock-chain";
import { FEE_CONTRACT, ErgoAddress } from "@fleet-sdk/core";
import { estimateBoxSize, decode } from "@fleet-sdk/serializer";
import * as SR from "ergo-lib-wasm-nodejs";
import { main, buildContext, computeBudget, loadContracts, keyFromSecret, C } from "./smoke.mjs";

// ── no network, ever ──
let fetchCalls = 0;
globalThis.fetch = async () => { fetchCalls++; throw new Error("NETWORK CALL ATTEMPTED IN OFFLINE TEST"); };

const results = [];
const log = (l = "") => console.log(l);
function check(name, ok, detail = "") {
  results.push({ name, ok: !!ok });
  log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `\n      ${detail}` : ""}`);
}

// ── mock node on MockChain ──
const chain = new MockChain({ height: 1_650_000 });
const parties = new Map(); // ergoTree -> party
const partyFor = (tree) => { if (!parties.has(tree)) parties.set(tree, chain.addParty(tree, `tree-${parties.size}`)); return parties.get(tree); };
const allUtxos = () => [...parties.values()].flatMap((p) => p.utxos.toArray());
const headerCache = new Map();
function headersAt(H) {
  if (!headerCache.has(H)) headerCache.set(H, mockHeaders(10).map((x, j) => ({ ...x, height: H - j, timestamp: 1_790_000_000_000 + (H - j) * 120_000 })));
  return headerCache.get(H);
}
// Node-style JSON: numbers for value / amount, headers in ascending order, powSolutions.d numeric.
const nodeBox = (b) => ({ boxId: b.boxId, transactionId: b.transactionId, index: b.index, value: Number(b.value), ergoTree: b.ergoTree,
  creationHeight: b.creationHeight, assets: b.assets.map((a) => ({ tokenId: a.tokenId, amount: Number(a.amount) })), additionalRegisters: { ...b.additionalRegisters } });
const calls = { getTip: 0, getBox: 0, submit: 0, check: 0, txStatus: 0 };
const submitted = []; // { id, json, accepted, detail, checkOnly }
const minted = new Map(); // tokenId -> amount minted
const mined = new Map();
const invalidated = new Set();

function nodeValidate(j, ins) {
  const H = chain.height;
  const outs = SR.Transaction.from_json(JSON.stringify(j)).outputs();
  const outBoxes = []; for (let k = 0; k < outs.len(); k++) outBoxes.push(outs.get(k).to_js_eip12());
  const maxIn = Math.max(...ins.map((b) => b.creationHeight));
  for (const [k, b] of outBoxes.entries()) {
    if (b.creationHeight > H + 1) return `output ${k} creationHeight ${b.creationHeight} > block height ${H + 1}`;
    if (b.creationHeight < maxIn) return `output ${k} creationHeight ${b.creationHeight} < max input creationHeight ${maxIn}`;
    const min = BigInt(estimateBoxSize(b)) * 360n;
    if (BigInt(b.value) < min) return `output ${k} value ${b.value} < min ${min}`;
  }
  const sum = (bs) => { const m = new Map(); for (const b of bs) for (const a of b.assets) m.set(a.tokenId, (m.get(a.tokenId) ?? 0n) + BigInt(a.amount)); return m; };
  const tin = sum(ins), tout = sum(outBoxes);
  for (const [id, a] of tin) if ((tout.get(id) ?? 0n) !== a) return `TOKEN BURN/INFLATION ${id.slice(0, 12)}: in ${a} out ${tout.get(id) ?? 0n}`;
  for (const [id] of tout) if (!tin.has(id) && id !== j.inputs[0].boxId) return `token ${id.slice(0, 12)} from nowhere`;
  const fees = outBoxes.filter((b) => b.ergoTree === FEE_CONTRACT);
  if (fees.length !== 1 || BigInt(fees[0].value) < 1_000_000n) return "fee output missing or below 0.001 ERG";
  return null;
}
const net = {
  async getTip() { calls.getTip++; return { height: chain.height, headers: headersAt(chain.height).slice().reverse().map((h) => ({ ...h, powSolutions: { ...h.powSolutions, d: 0 } })), minValuePerByte: 360 }; },
  async getBox(id) { calls.getBox++; const b = allUtxos().find((x) => x.boxId === id); return b ? { box: nodeBox(b), where: "utxo" } : null; },
  async submitTx(text, { checkOnly = false } = {}) {
    checkOnly ? calls.check++ : calls.submit++;
    const j = JSON.parse(text);
    // Like the real node, remember ids of rejected txs and decline a resubmission of the same id without revalidating
    // (conservatively also for /transactions/check). A negative control sharing an id with a later honest post would
    // therefore block that post; the test fails if that ever happens.
    const reject = (detail) => { invalidated.add(j.id); submitted.push({ id: j.id, json: j, accepted: false, detail, checkOnly }); return { ok: false, status: 400, body: { error: 400, reason: "bad.request", detail } }; };
    if (invalidated.has(j.id)) { submitted.push({ id: j.id, json: j, accepted: false, detail: "invalidated earlier", checkOnly, cached: true }); return { ok: false, status: 400, body: { error: 400, reason: "bad.request", detail: "Malformed transaction: transaction was invalidated earlier (id cache)" } }; }
    const ins = j.inputs.map((i) => allUtxos().find((b) => b.boxId === i.boxId));
    if (ins.some((b) => !b) && !checkOnly && mined.has(j.id)) return { ok: false, status: 400, body: { error: 400, reason: "bad.request", detail: "already mined" } };
    if (ins.some((b) => !b)) return reject("Malformed transaction: input box not found in the UTXO set");
    const insN = ins.map((b) => ({ ...nodeBox(b), value: String(b.value), assets: b.assets.map((a) => ({ tokenId: a.tokenId, amount: String(a.amount) })) }));
    const consensus = nodeValidate(j, insN);
    if (consensus) return reject(`Malformed transaction: ${consensus}`);
    const tx = SR.Transaction.from_json(text);
    const ctx = buildContext({ height: chain.height, headers: headersAt(chain.height) });
    try { SR.validate_tx(tx, ctx.srCtx, SR.ErgoBoxes.from_boxes_json(insN), SR.ErgoBoxes.from_boxes_json([])); }
    catch (e) {
      const per = j.inputs.map((_i, k) => { try { return SR.verify_tx_input_proof(k, ctx.srCtx, tx, SR.ErgoBoxes.from_boxes_json(insN), SR.ErgoBoxes.from_boxes_json([])); } catch { return "throw"; } });
      return reject(`Malformed transaction: ${String(e?.message ?? e).split("\n")[0].replace(/:? ?VerificationResult \{.*$/, "").slice(0, 200)} [per-input proof: ${per.map((x, k) => `#${k}=${x}`).join(" ")}]`);
    }
    submitted.push({ id: j.id, json: j, accepted: true, checkOnly });
    if (checkOnly) return { ok: true, status: 200, body: j.id };
    // apply: spend inputs, add outputs, mine one block
    for (const i of j.inputs) for (const p of parties.values()) if (p.utxos.exists(i.boxId)) p.utxos.remove(i.boxId);
    const outs = tx.outputs();
    for (let k = 0; k < outs.len(); k++) {
      const b = outs.get(k).to_js_eip12();
      partyFor(b.ergoTree).addUTxOs({ ...b, value: BigInt(b.value), assets: b.assets.map((a) => ({ tokenId: a.tokenId, amount: BigInt(a.amount) })) });
      for (const a of b.assets) if (a.tokenId === j.inputs[0].boxId) minted.set(a.tokenId, BigInt(a.amount));
    }
    mined.set(j.id, chain.height + 1);
    chain.newBlock();
    return { ok: true, status: 200, body: j.id };
  },
  async txStatus(id) {
    calls.txStatus++;
    if (mined.has(id)) return { state: "confirmed", numConfirmations: chain.height - mined.get(id) + 1 };
    const outs = allUtxos().filter((b) => b.transactionId === id);
    if (outs.length) return { state: "confirmed", tx: { id, outputs: outs.map(nodeBox) } };
    return { state: "unknown" };
  },
};

// ── run helpers ──
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), "mainnet-smoke-offline-"));
const transcript = [];
async function run(args, { echo = true } = {}) {
  const lines = [];
  const code = await main(args, { net, dir: DIR, print: (l) => { lines.push(l); transcript.push(l); } });
  if (echo) { log(`\n$ node smoke.mjs ${args.join(" ")}   (exit ${code})`); for (const l of lines) log(`  | ${l}`); }
  return { code, lines, text: lines.join("\n") };
}
const state = () => JSON.parse(fs.readFileSync(path.join(DIR, "state.json"), "utf-8"));
const lastSubmitted = () => submitted[submitted.length - 1];
const treeLabel = (st, t) => t === st.contracts?.oracleTree ? "oracle" : t === st.contracts?.authorityTree ? "authority" : t === FEE_CONTRACT ? "fee" : t.startsWith("0008cd") ? "P2PK" : "other";
// The posting lock is the authority box's R7 post stamp (Int), not its creation height.
const r7Of = (b) => Number(decode(b.additionalRegisters.R7).data);
async function waitUnlock() {
  const st = state();
  const need = r7Of(st.boxes.authority) + C.EPOCH_LENGTH + 1;
  if (chain.height < need) chain.newBlocks(need - chain.height);
  return need;
}
function tokenTotals() {
  const m = new Map();
  for (const b of allUtxos()) for (const a of b.assets) m.set(a.tokenId, (m.get(a.tokenId) ?? 0n) + BigInt(a.amount));
  return m;
}
function noBurnSoFar(label) {
  const t = tokenTotals();
  const bad = [...minted].filter(([id, a]) => t.get(id) !== a);
  check(`token conservation after ${label}: every minted token's full supply is still in the UTXO set`, bad.length === 0,
    bad.length ? bad.map(([id, a]) => `${id.slice(0, 10)} minted ${a} present ${t.get(id) ?? 0n}`).join("; ") : [...minted].map(([id, a]) => `${id.slice(0, 8)}..=${a}`).join(" "));
}
const quote = (text, re) => text.split("\n").filter((l) => re.test(l)).map((l) => l.trim()).join("\n      ");

// ═════════════════════════════ the sequence ═════════════════════════════
log(`mainnet-smoke offline test — state dir ${DIR}`);
const contracts = loadContracts();
const budget = computeBudget(contracts);

// 1. keys
{
  const r = await run(["keys"]);
  const addrOk = r.lines.length === 1 && /^9[1-9A-HJ-NP-Za-km-z]{50}$/.test(r.lines[0]) && ErgoAddress.decode(r.lines[0]).ergoTree.startsWith("0008cd");
  const mode = fs.statSync(path.join(DIR, ".keys.json")).mode & 0o777;
  check("keys: prints exactly one line, the owner's mainnet P2PK address", r.code === 0 && addrOk, r.lines[0]);
  check("keys: .keys.json is chmod 600", mode === 0o600, `mode ${mode.toString(8)}`);
  const before = fs.readFileSync(path.join(DIR, ".keys.json"), "utf-8");
  const r2 = await run(["keys"]);
  check("keys: refuses to overwrite an existing key file", r2.code !== 0 && fs.readFileSync(path.join(DIR, ".keys.json"), "utf-8") === before, r2.lines[0]);
}
const keysRaw = () => JSON.parse(fs.readFileSync(path.join(DIR, ".keys.json"), "utf-8")).keys;
const K = Object.fromEntries(Object.entries(keysRaw()).map(([n, v]) => [n, keyFromSecret(v.secret)]));

// 2. plan
log("\n──────────────── plan output ────────────────");
const planRun = await run(["plan"], { echo: false });
for (const l of planRun.lines) log(l);
log("─────────────────────────────────────────────");
check("plan: runs offline and its ledger balances (returned + stranded + fees = funding)", planRun.code === 0 && /= funding [\d.]+ ERG: OK/.test(planRun.text));

// 3. operator funds the owner address (simulated) — fund by TX id, exercising the tx lookup path
const fundBox = mockUTxO({ value: budget.recommended, ergoTree: K.owner.tree, creationHeight: chain.height });
partyFor(K.owner.tree).addUTxOs(fundBox);
chain.newBlock();
{
  const r = await run(["fund", fundBox.transactionId]);
  check("fund <txId>: finds the owner output and records it", r.code === 0 && state().funding?.box.boxId === fundBox.boxId);
}

// 4. mint: dry, check, broadcast
{
  const s0 = calls.submit + calls.check;
  const r = await run(["mint"]);
  check("mint (dry run): builds + signs + verifies 3 txs, sends nothing, state unchanged", r.code === 0 && calls.submit + calls.check === s0 && state().mint.length === 0
    && (r.text.match(/validate_tx OK/g) ?? []).length === 3);
  const r2 = await run(["mint", "--check"]);
  check("mint --check: first tx accepted by POST /transactions/check, chained ones not checked, state unchanged",
    r2.code === 0 && calls.check === 1 && calls.submit === 0 && state().mint.length === 0 && /ACCEPTED/.test(r2.text));
  const r3 = await run(["mint", "--broadcast"]);
  const st = state();
  const okIds = st.mint.every((m, k) => submitted.filter((x) => x.accepted && !x.checkOnly)[k]?.json.inputs[0].boxId === m.tokenId);
  check("mint --broadcast: three chained mint txs accepted", r3.code === 0 && st.mint.length === 3);
  check("mint: each token id = the id of its tx's FIRST input box", okIds);
  check("mint: supplies oracle x2, reward x10, nft x1", minted.get(st.tokens.oracle) === 2n && minted.get(st.tokens.reward) === 10n && minted.get(st.tokens.nft) === 1n);
  noBurnSoFar("mint");
}

// 5. setup
{
  const r = await run(["setup", "--broadcast"]);
  const st = state();
  const ob = st.boxes.oracle, ab = st.boxes.authority;
  check("setup --broadcast: accepted", r.code === 0 && lastSubmitted().accepted && st.contracts);
  check("setup: oracle box = 0.01 ERG, tokens [oracle 1, reward 2], R4/R5/R6, at the oracle script",
    ob.value === "10000000" && ob.ergoTree === st.contracts.oracleTree && ob.assets[0].tokenId === st.tokens.oracle && ob.assets[0].amount === "1"
    && ob.assets[1].tokenId === st.tokens.reward && ob.assets[1].amount === "2" && ["R4", "R5", "R6"].every((x) => ob.additionalRegisters[x]));
  check("setup: authority box = NFT at tokens(0), R4 owner, R5 oracle token id, R6 posting key, R7 = R8 = setup stamp (Int)",
    ab.assets.length === 1 && ab.assets[0].tokenId === st.tokens.nft && ab.additionalRegisters.R4 === "07" + K.owner.pk
    && ab.additionalRegisters.R5 === "0e20" + st.tokens.oracle && ab.additionalRegisters.R6 === "07" + K.posting.pk
    && r7Of(ab) === ab.creationHeight && Number(decode(ab.additionalRegisters.R8).data) === ab.creationHeight, `authority value ${ab.value}`);
  noBurnSoFar("setup");
}

// 6. post too early → refused locally, nothing sent
{
  const n = submitted.length;
  const r = await run(["post", "--broadcast"]);
  check("post right after setup: refused by the height-lock pre-check, nothing sent", r.code === 3 && submitted.length === n && /HEIGHT LOCK/.test(r.text));
}

// 7. post #1
const postChecks = (label, signerName) => {
  const st = state(); const s = lastSubmitted(); const j = s.json;
  check(`${label}: accepted by the node (sigma-rust validated every proof)`, s.accepted && !s.checkOnly);
  check(`${label}: inputs = [oracle, authority], outputs = [oracle', authority', miner fee]; no P2PK input, no change`,
    j.inputs.length === 2 && j.outputs.length === 3 && j.outputs.map((o) => treeLabel(st, o.ergoTree)).join() === "oracle,authority,fee"
    && !j.outputs.some((o) => o.ergoTree.startsWith("0008cd")),
    `outputs=[${j.outputs.map((o) => treeLabel(st, o.ergoTree))}] fee=${j.outputs[2].value}`);
  const holds = allUtxos().filter((b) => b.ergoTree === K[signerName]?.tree || b.ergoTree === keyFromSecret(keysRaw()[signerName].secret).tree).length;
  check(`${label}: the ${signerName} key controls no box (posting key has no wallet)`, holds === 0, `${signerName} P2PK UTxOs: ${holds}`);
  noBurnSoFar(label);
};
await waitUnlock();
{
  const r = await run(["post", "--broadcast"]);
  check("post #1: exit 0", r.code === 0);
  postChecks("post #1", "posting");
}

// 8. wait 5 blocks → post #2
chain.newBlocks(5);
{
  const r = await run(["post", "--broadcast"]);
  check("post #2 (5 blocks later): exit 0", r.code === 0);
  postChecks("post #2", "posting");
}

// 9. negatives
const negative = async (variant, mode = "--broadcast") => {
  const before = JSON.stringify(state().boxes);
  const r = await run(["post-bad", variant, mode]);
  const s = lastSubmitted();
  const rejected = s && !s.accepted && !s.cached && s.checkOnly === (mode === "--check") && /reduced to false/.test(s.detail);
  check(`post-bad ${variant} ${mode}: REJECTED by the node; state unchanged`, r.code === 0 && rejected && JSON.stringify(state().boxes) === before,
    `node: ${s?.detail}\n      ${quote(r.text, /interpreter|reduced:|local verify/)}`);
  return r;
};
await negative("early");
{
  await waitUnlock();
  const n = submitted.length;
  const r = await run(["post-bad", "early", "--broadcast"]);
  check("post-bad early once the lock is open: refused (it would be a valid post), nothing sent", r.code !== 0 && submitted.length === n, r.lines[r.lines.length - 1]);
}
await negative("change");
await negative("overfee", "--check");
await negative("overfee");

// 10. rotate, old key rejected, new key accepted
{
  const r = await run(["rotate", "--broadcast"]);
  const st = state();
  const k2 = keyFromSecret(keysRaw().posting2.secret);
  check("rotate --broadcast: owner key replaced R6 in place (accepted)", r.code === 0 && st.boxes.authority.additionalRegisters.R6 === "07" + k2.pk && st.activePosting === "posting2"
    && fs.statSync(path.join(DIR, ".keys.json")).mode % 0o1000 === 0o600);
  noBurnSoFar("rotate");
}
await waitUnlock();
await negative("oldkey");
{
  const r = await run(["post", "--broadcast"]);
  check("post #3 with the NEW key: exit 0", r.code === 0);
  postChecks("post #3 (new key)", "posting2");
}

// 11. reclaim
{
  const dest = keyFromSecret(Buffer.from(SR.SecretKey.random_dlog().to_bytes()).toString("hex")); // throwaway in-memory destination
  const r = await run(["reclaim", dest.address, "--broadcast"]);
  const st = state();
  check("reclaim --broadcast: accepted", r.code === 0 && lastSubmitted().accepted && st.reclaim?.txId);
  const destBoxes = allUtxos().filter((b) => b.ergoTree === dest.tree);
  const oracleBoxes = allUtxos().filter((b) => b.ergoTree === st.contracts.oracleTree);
  const feeTotal = submitted.filter((x) => x.accepted && !x.checkOnly).reduce((s, x) => s + BigInt(x.json.outputs.find((o) => o.ergoTree === FEE_CONTRACT).value), 0n);
  const d = destBoxes[0]; const tok = (b, id) => BigInt(b?.assets.find((a) => a.tokenId === id)?.amount ?? 0n);
  check("reclaim: destination gets the NFT, the spare oracle token and all 10 reward tokens",
    destBoxes.length === 1 && tok(d, st.tokens.nft) === 1n && tok(d, st.tokens.oracle) === 1n && tok(d, st.tokens.reward) === 10n,
    `dest tokens: ${d?.assets.map((a) => `${a.tokenId.slice(0, 8)}x${a.amount}`).join(", ")}`);
  check("reclaim: destination ERG = funding - all fees - 0.01 stranded oracle ERG",
    BigInt(d.value) === budget.recommended - feeTotal - C.ORACLE_VALUE, `dest ${d.value} nanoERG; funding ${budget.recommended}; fees ${feeTotal}`);
  check("reclaim: only the oracle box is left behind: 0.01 ERG + oracle token x1, still at the oracle script",
    oracleBoxes.length === 1 && BigInt(oracleBoxes[0].value) === C.ORACLE_VALUE && oracleBoxes[0].assets.length === 1 && oracleBoxes[0].assets[0].tokenId === st.tokens.oracle);
  const leftover = allUtxos().filter((b) => b.ergoTree === K.owner.tree || b.ergoTree === st.contracts.authorityTree);
  check("reclaim: nothing left at the owner address or the authority script", leftover.length === 0, `left: ${leftover.length}`);
  noBurnSoFar("reclaim");
}

// 12. undo (live recovery path for a post that expired unmined): refuses without --yes, then restores the prior pointers
{
  const authBefore = submitted.filter((x) => x.accepted && !x.checkOnly).slice(-2)[0].json; // post #3 tx
  const r0 = await run(["undo"], { echo: false });
  const r1 = await run(["undo", "--yes"], { echo: false });
  const st = state();
  const expectAuth = SR.Transaction.from_json(JSON.stringify(authBefore)).outputs().get(1).box_id().to_str();
  check("undo: refuses without --yes; with --yes restores the state recorded before the last step (pre-reclaim)",
    r0.code === 1 && r1.code === 0 && st.reclaim === null && st.boxes.authority?.boxId === expectAuth, `authority pointer ${st.boxes.authority?.boxId?.slice(0, 16)}..`);
}

// 13. status + hygiene
{
  const r = await run(["status"]);
  check("status: prints recorded state", r.code === 0 && /posts:/.test(r.text));
  const secrets = Object.values(keysRaw()).map((v) => v.secret);
  const leaked = secrets.filter((s) => transcript.some((l) => l.includes(s)) || fs.readFileSync(path.join(DIR, "state.json"), "utf-8").includes(s)
    || fs.readdirSync(path.join(DIR, "txs")).some((f) => fs.readFileSync(path.join(DIR, "txs", f), "utf-8").includes(s)));
  check("no secret appears in any printed line, state.json or saved tx file", leaked.length === 0, `${secrets.length} secrets scanned, ${transcript.length} lines`);
  check("no network call was attempted (fetch never called)", fetchCalls === 0);
  const accepted = submitted.filter((x) => x.accepted && !x.checkOnly).length;
  check("every on-chain tx went through the mock node; 9 accepted broadcasts (3 mint, setup, 3 posts, rotate, reclaim)", accepted === 9, `accepted=${accepted} rejected=${submitted.filter((x) => !x.accepted).length} checks=${calls.check} getBox=${calls.getBox}`);
}

const passed = results.filter((r) => r.ok).length;
log(`\nSUMMARY ${passed}/${results.length} PASS${passed === results.length ? "" : `  (${results.length - passed} FAIL)`}`);
fs.rmSync(DIR, { recursive: true, force: true });
process.exit(passed === results.length ? 0 : 1);
