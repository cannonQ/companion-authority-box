#!/usr/bin/env node
// mainnet-smoke/smoke.mjs — MAINNET smoke test for CompanionAuthorityHotKey.es + OracleContractV2-valuefix.es
//
// What it proves on the real chain: a server holding ONLY a posting key (no wallet, no UTXOs) can update an
// oracle box. The post tx is INPUTS = [oracle box, authority box], OUTPUTS = [oracle', authority', miner fee];
// the fee comes out of the authority box, there is no change output, and only the posting key signs.
//
// Everything is dummy: three tokens minted here, throwaway keys in ./.keys.json (chmod 600).
//
// SAFETY
//  - Every state-changing subcommand is a DRY RUN by default: it builds, signs locally, verifies locally with
//    sigma-rust and saves the tx JSON, but contacts the node only with GET requests.
//  - `--check` additionally POSTs to /transactions/check (validates, never broadcasts).
//  - `--broadcast` POSTs to /transactions. Nothing is ever broadcast without it.
//  - Secrets are never printed (all output passes through a redactor as a second line of defence).
//  - The contract sources are read from ../ at run time. After `setup` the DEPLOYED ergoTrees recorded in
//    state.json are what every later step uses; a source edit after setup only produces a warning.
//
// Subcommands: keys | plan | fund <boxId|txId> | mint | setup | post | post-bad <early|change|overfee|oldkey>
//              | rotate | reclaim <P2PK address> | status [--live] | undo --yes
// Flags: --broadcast  --check  --stamp-offset <n> (default 1: outputs stamped tip-1, OracleBoxPoster.scala:208)
// Env:   NODE_URL (required for every command that talks to the node; no default)   SMOKE_DIR (state dir override)
//
// Network access: only the four functions in createNodeApi() below.

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { compile } from "@fleet-sdk/compiler";
import { OutputBuilder, ErgoUnsignedInput, ErgoUnsignedTransaction, FEE_CONTRACT, ErgoAddress, Network } from "@fleet-sdk/core";
import { SInt, SLong, SColl, SByte, SGroupElement, decode, estimateBoxSize } from "@fleet-sdk/serializer";
import { blake2b256, hex, utf8 } from "@fleet-sdk/crypto";
import { ProverBuilder$, GroupElement$, AvlTree$ } from "sigmastate-js/main";
import { BLOCKCHAIN_PARAMETERS, mockHeaders, mockUTxO } from "@fleet-sdk/mock-chain";
import * as SR from "ergo-lib-wasm-nodejs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CONTRACT_DIR = path.resolve(HERE, "..");
const AUTH_SRC_FILE = path.join(CONTRACT_DIR, "CompanionAuthorityHotKey.es");
const ORACLE_SRC_FILE = path.join(CONTRACT_DIR, "OracleContractV2-valuefix.es");

// ───────────────────────────── fixed test parameters ─────────────────────────────
export const C = {
  EPOCH_LENGTH: 5,                 // authority compile constant `epochLength`
  FEE: 1_000_000n,                 // 0.001 ERG: every tx in this test (and the node's default minimalFeeAmount)
  ORACLE_VALUE: 10_000_000n,       // dummy oracle box value (= oracle contract minStorageRent, parsed + checked)
  POSTS_BUDGET: 10n,               // authority box funded for ~10 posts
  N_PRICES: 21,                    // R6 Coll[Long] length
  CHANGE_VARIANT_VALUE: 1_000_000n,// `post-bad change`: extra output to the owner
  MIN_VALUE_PER_BYTE: 360n,        // consensus minimum box value per serialized byte (overridden by /info if higher)
  TOKENS: {
    oracle: { amount: 2n, name: "SMOKETEST-ORACLE", description: "Dummy oracle token for a mainnet smoke test. Worthless." },
    reward: { amount: 10n, name: "SMOKETEST-REWARD", description: "Dummy reward token for a mainnet smoke test. Worthless." },
    nft: { amount: 1n, name: "SMOKETEST-AUTHORITY-NFT", description: "Dummy companion authority NFT for a mainnet smoke test. Worthless." },
  },
  MINT_ORDER: ["oracle", "reward", "nft"],
};
// No token can ever have this id (a token id is the id of a box; finding a box hashing to this is preimage-hard),
// so the oracle contract's collection path is dead for the dummy oracle box.
export const POOL_NFT_DUMMY = hex.encode(blake2b256(utf8.decode("mainnet-smoke: no pool NFT will ever have this id")));

const ERG = 1_000_000_000n;
const fmtErg = (n) => {
  const v = BigInt(n); const neg = v < 0n; const a = neg ? -v : v;
  return `${neg ? "-" : ""}${a / ERG}.${String(a % ERG).padStart(9, "0")}`;
};
const roundUp = (v, step) => ((v + step - 1n) / step) * step;
const bytesC = (h) => SColl(SByte, typeof h === "string" ? hex.decode(h) : h);
const maxBig = (...xs) => xs.reduce((m, x) => (x > m ? x : m));

// ───────────────────────────── output / redaction ─────────────────────────────
const SECRETS = new Set();
function redact(s) {
  let t = String(s);
  for (const sec of SECRETS) if (sec && sec.length >= 32) t = t.split(sec).join("[REDACTED]");
  return t;
}

// ───────────────────────────── NETWORK MODULE (the only code that touches the node) ─────────────────────────────
// Exactly four functions. Target: standard Ergo node REST API. NODE_URL is required; there is no default.
export function createNodeApi(baseUrl) {
  if (!baseUrl) throw new Error("NODE_URL is not set. Point it at your own Ergo node, e.g. NODE_URL=http://127.0.0.1:9053");
  const base = baseUrl.replace(/\/+$/, "");
  async function call(method, p, body) {
    const res = await fetch(base + p, {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json" } : {},
      body,
    });
    const text = await res.text();
    let json; try { json = JSON.parse(text); } catch { json = text; }
    return { ok: res.ok, status: res.status, body: json };
  }
  return {
    // 1. current height + last 10 headers (needed for the signing context)
    async getTip() {
      const info = await call("GET", "/info");
      if (!info.ok) throw new Error(`GET /info failed: HTTP ${info.status}`);
      const i = info.body;
      if (i.network && String(i.network).toLowerCase() !== "mainnet") throw new Error(`node reports network=${i.network}, expected mainnet`);
      if (i.headersHeight != null && i.fullHeight != null && i.headersHeight !== i.fullHeight)
        throw new Error(`node is not synced (headersHeight ${i.headersHeight} != fullHeight ${i.fullHeight})`);
      const hs = await call("GET", "/blocks/lastHeaders/10");
      if (!hs.ok || !Array.isArray(hs.body) || hs.body.length !== 10) throw new Error(`GET /blocks/lastHeaders/10 failed: HTTP ${hs.status}`);
      const headers = hs.body.slice().sort((a, b) => b.height - a.height);
      if (i.fullHeight != null && headers[0].height !== i.fullHeight)
        throw new Error(`last header height ${headers[0].height} != /info fullHeight ${i.fullHeight}`);
      return { height: headers[0].height, headers, minValuePerByte: i.parameters?.minValuePerByte };
    },
    // 2. fetch box by id (confirmed UTXO set first, then UTXO set + mempool)
    async getBox(boxId) {
      const a = await call("GET", `/utxo/byId/${boxId}`);
      if (a.ok) return { box: a.body, where: "utxo" };
      const b = await call("GET", `/utxo/withPool/byId/${boxId}`);
      if (b.ok) return { box: b.body, where: "mempool" };
      return null;
    },
    // 3. submit signed tx (checkOnly: POST /transactions/check — validates, never broadcasts)
    async submitTx(txJsonText, { checkOnly = false } = {}) {
      return call("POST", checkOnly ? "/transactions/check" : "/transactions", txJsonText);
    },
    // 4. tx confirmation status
    async txStatus(txId) {
      const m = await call("GET", `/transactions/unconfirmed/byTransactionId/${txId}`);
      if (m.ok) return { state: "mempool", tx: m.body };
      const c = await call("GET", `/blockchain/transaction/byId/${txId}`); // needs extraIndex=true on the node
      if (c.ok) return { state: "confirmed", tx: c.body, inclusionHeight: c.body.inclusionHeight, numConfirmations: c.body.numConfirmations };
      return { state: "unknown", note: `not in mempool; indexer lookup HTTP ${c.status} (needs extraIndex=true)` };
    },
  };
}

// ───────────────────────────── contracts (read at run time, never copied) ─────────────────────────────
export function loadContracts() {
  const authSrc = fs.readFileSync(AUTH_SRC_FILE, "utf-8");
  const oracleSrc = fs.readFileSync(ORACLE_SRC_FILE, "utf-8");
  const num = (src, name, file) => {
    const m = src.match(new RegExp(`val\\s+${name}\\s*=\\s*(\\d+)L?`));
    if (!m) throw new Error(`constant ${name} not found in ${path.basename(file)}`);
    return BigInt(m[1]);
  };
  const maxFeePerEpoch = num(authSrc, "maxFeePerEpoch", AUTH_SRC_FILE);
  const mempoolSlack = Number(num(authSrc, "mempoolSlack", AUTH_SRC_FILE));
  const minStorageRent = num(oracleSrc, "minStorageRent", ORACLE_SRC_FILE);
  if (!authSrc.includes(`fromBase16("${FEE_CONTRACT}")`)) throw new Error("authority minerFeeProp != Fleet FEE_CONTRACT (the fee output would not match)");
  for (const id of ["poolNftId", "authorityNftId", "authorityScriptHash"]) if (!oracleSrc.includes(id)) throw new Error(`oracle source no longer references ${id}`);
  if (!/\bepochLength\b/.test(authSrc)) throw new Error("authority source no longer references epochLength");
  if (!/\bpoolNftId\b/.test(authSrc)) throw new Error("authority source no longer references poolNftId");
  if (C.FEE > maxFeePerEpoch) throw new Error(`post fee ${C.FEE} exceeds the contract cap maxFeePerEpoch=${maxFeePerEpoch}`);
  if (C.ORACLE_VALUE < minStorageRent) throw new Error(`oracle box value ${C.ORACLE_VALUE} < contract minStorageRent ${minStorageRent}`);
  if (mempoolSlack >= C.EPOCH_LENGTH) throw new Error(`mempoolSlack ${mempoolSlack} must be < epochLength ${C.EPOCH_LENGTH}`);
  return { authSrc, oracleSrc, maxFeePerEpoch, mempoolSlack, minStorageRent };
}
// The authority's refresh-fee path needs poolNftId at INPUTS(0). This test never refreshes: the same unreachable dummy id
// as the oracle's poolNftId keeps that path dead, exactly like the oracle's collection path.
export const compileAuthority = (c) => compile(c.authSrc, { map: { epochLength: SInt(C.EPOCH_LENGTH), poolNftId: bytesC(POOL_NFT_DUMMY) } }).toHex();
// The audited oracle pins the authority script: authorityScriptHash = blake2b256(authority tree). The authority is
// therefore compiled FIRST and its tree passed in. authorityNftId was `companionNftId` before the audit (renamed, V-2).
export const authorityScriptHashOf = (authorityTree) => hex.encode(blake2b256(hex.decode(authorityTree)));
export const compileOracle = (c, authorityNftId, authorityTree = compileAuthority(c)) =>
  compile(c.oracleSrc, { map: { poolNftId: bytesC(POOL_NFT_DUMMY), authorityNftId: bytesC(authorityNftId),
    authorityScriptHash: bytesC(authorityScriptHashOf(authorityTree)) } }).toHex();
const p2sAddress = (tree) => ErgoAddress.fromErgoTree(tree, Network.Mainnet).encode(Network.Mainnet);

// ───────────────────────────── keys ─────────────────────────────
export function keyFromSecret(secretHex) {
  const sk = SR.SecretKey.dlog_from_bytes(hex.decode(secretHex));
  const addr = sk.get_address();
  const tree = addr.to_ergo_tree().to_base16_bytes();
  if (!tree.startsWith("0008cd") || tree.length !== 6 + 66) throw new Error("unexpected P2PK tree shape");
  return { secret: secretHex, pk: tree.slice(6), tree, address: addr.to_base58(SR.NetworkPrefix.Mainnet) };
}
function newSecret() { return hex.encode(SR.SecretKey.random_dlog().to_bytes()); }

// ───────────────────────────── box helpers ─────────────────────────────
// Normalize a node / sigma-rust / EIP-12 box into the EIP-12 shape (value + amounts as strings, registers hex).
export function normBox(b) {
  const regs = {};
  for (const [k, v] of Object.entries(b.additionalRegisters ?? {})) regs[k] = typeof v === "string" ? v : v.serializedValue;
  return {
    boxId: b.boxId, transactionId: b.transactionId, index: Number(b.index),
    value: String(b.value), ergoTree: b.ergoTree, creationHeight: Number(b.creationHeight),
    assets: (b.assets ?? []).map((a) => ({ tokenId: a.tokenId, amount: String(a.amount) })),
    additionalRegisters: regs,
  };
}
const regVal = (box, r) => decode(box.additionalRegisters[r]).data;
// The posting lock: the authority box's R7 post stamp (Int). A box recorded before the stamps existed (the pre-audit
// contract that ran on mainnet on 2026-10-03) has no R7; its lock was its creation height.
const postStampOf = (ab) => (ab.additionalRegisters?.R7 ? Number(regVal(ab, "R7")) : Number(ab.creationHeight));
const gePk = (box, r) => { const h = box.additionalRegisters[r]; if (!h?.startsWith("07") || h.length !== 68) throw new Error(`${r} is not a GroupElement`); return h.slice(2); };
const sumTokens = (boxes) => {
  const m = new Map();
  for (const b of boxes) for (const a of b.assets) m.set(a.tokenId, (m.get(a.tokenId) ?? 0n) + BigInt(a.amount));
  return m;
};

// ───────────────────────────── signing context (both interpreters) ─────────────────────────────
// The node validates mempool txs against the UPCOMING block (height tip+1, parent = tip). Same here.
function normHeader(h) {
  return {
    id: h.id, parentId: h.parentId, version: Number(h.version), height: Number(h.height),
    adProofsRoot: h.adProofsRoot, stateRoot: h.stateRoot, transactionsRoot: h.transactionsRoot,
    timestamp: Number(h.timestamp), nBits: Number(h.nBits), extensionHash: h.extensionHash,
    powSolutions: { pk: h.powSolutions.pk, w: h.powSolutions.w, n: h.powSolutions.n, d: String(h.powSolutions.d) },
    votes: h.votes,
  };
}
export function buildContext(tip) {
  const headers = tip.headers.map(normHeader).sort((a, b) => b.height - a.height);
  if (headers.length !== 10) throw new Error("need exactly 10 headers");
  for (let j = 0; j + 1 < headers.length; j++)
    if (headers[j].parentId !== headers[j + 1].id) throw new Error(`headers not linked at ${headers[j].height}`);
  const t = headers[0];
  const next = { ...t, id: hex.encode(blake2b256(hex.decode(t.id))), parentId: t.id, height: t.height + 1, timestamp: t.timestamp + 120_000 };
  const conv = (h) => ({
    ...h, ADProofsRoot: h.adProofsRoot, stateRoot: AvlTree$.fromDigest(h.stateRoot), timestamp: BigInt(h.timestamp),
    nBits: BigInt(h.nBits), extensionRoot: h.extensionHash, minerPk: GroupElement$.fromPointHex(h.powSolutions.pk),
    powOnetimePk: GroupElement$.fromPointHex(h.powSolutions.w), powNonce: h.powSolutions.n, powDistance: BigInt(h.powSolutions.d),
  });
  const ssHeaders = headers.map(conv);
  const ssCtx = { sigmaLastHeaders: ssHeaders, previousStateDigest: ssHeaders[0].stateRoot.digest, sigmaPreHeader: conv(next) };
  const srCtx = new SR.ErgoStateContext(
    SR.PreHeader.from_block_header(SR.BlockHeader.from_json(JSON.stringify(next))),
    SR.BlockHeaders.from_json(headers),
    SR.Parameters.default_parameters());
  const mvpb = maxBig(C.MIN_VALUE_PER_BYTE, BigInt(tip.minValuePerByte ?? 0));
  return { tip: t.height, nextHeight: t.height + 1, ssCtx, srCtx, minValuePerByte: mvpb };
}

// ───────────────────────────── tx assembly / sign / verify ─────────────────────────────
// Inputs are taken in EXACTLY the given order (no selector), outputs exactly as given (no change logic).
function assemble(inputSpecs, outputBuilders) {
  const inputs = inputSpecs.map(({ box, ext }) => { const i = new ErgoUnsignedInput(box); if (ext) i.setContextExtension(ext); return i; });
  const outputs = outputBuilders.map((o) => o.build(inputs));
  const tx = new ErgoUnsignedTransaction(inputs, [], outputs);
  const eip12 = tx.toEIP12Object();
  inputSpecs.forEach((s, k) => { if (eip12.inputs[k].boxId !== s.box.boxId) throw new Error("input order changed"); });
  return { tx, eip12 };
}
const jsonBig = (o) => JSON.parse(JSON.stringify(o, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
const srBoxes = (eip12) => SR.ErgoBoxes.from_boxes_json(jsonBig(eip12.inputs).map(({ extension: _x, ...box }) => box));

// Honest signing: sigmastate-js reduces every input against the context and signs with the given secrets only.
function signSigmastate(eip12, ctx, secrets) {
  const b = ProverBuilder$.create(BLOCKCHAIN_PARAMETERS, 0 /* mainnet */);
  for (const s of secrets) b.withDLogSecret(BigInt("0x" + s));
  const prover = b.build();
  const reduced = prover.reduce(ctx.ssCtx, eip12, eip12.inputs, eip12.dataInputs, [], 0);
  const signed = JSON.parse(JSON.stringify(prover.signReduced(reduced)));
  const srTx = SR.Transaction.from_json(JSON.stringify(signed));
  if (srTx.id().to_str() !== signed.id) throw new Error("sigma-rust tx id != sigmastate tx id");
  return srTx;
}
// Negative controls: the posting key's genuine Schnorr signature over THIS tx's bytes-to-sign goes on every input
// guarded by the authority script; other inputs get an empty proof (they reduce to true on the companion path).
// That is the best any holder of only the posting key can produce for the tx.
function signAsPostingKeyOnly(eip12, signer, authTree) {
  const unsignedId = SR.UnsignedTransaction.from_json(JSON.stringify(eip12)).id().to_str();
  const empty = eip12.inputs.map(() => new Uint8Array(0));
  // from_unsigned_tx consumes its argument, so every use parses a fresh UnsignedTransaction.
  const msg = SR.Transaction.from_unsigned_tx(SR.UnsignedTransaction.from_json(JSON.stringify(eip12)), empty).sigma_serialize_bytes();
  if (hex.encode(blake2b256(msg)) !== unsignedId) throw new Error("bytes-to-sign do not hash to the tx id");
  const keys = new SR.SecretKeys(); keys.add(SR.SecretKey.dlog_from_bytes(hex.decode(signer.secret)));
  const wallet = SR.Wallet.from_secrets(keys);
  const sigAddr = SR.Address.from_base58(signer.address);
  const proofs = eip12.inputs.map((i) => (i.ergoTree === authTree ? wallet.sign_message_using_p2pk(sigAddr, msg) : new Uint8Array(0)));
  return SR.Transaction.from_unsigned_tx(SR.UnsignedTransaction.from_json(JSON.stringify(eip12)), proofs);
}
function verifyInputs(srTx, eip12, ctx) {
  const per = eip12.inputs.map((_i, k) => {
    try { return SR.verify_tx_input_proof(k, ctx.srCtx, srTx, srBoxes(eip12), SR.ErgoBoxes.from_boxes_json([])) === true; }
    catch (e) { return `threw: ${String(e?.message ?? e).split("\n")[0].slice(0, 160)}`; }
  });
  let full = "OK";
  try { SR.validate_tx(srTx, ctx.srCtx, srBoxes(eip12), SR.ErgoBoxes.from_boxes_json([])); }
  catch (e) { full = String(e?.message ?? e).split("\n")[0].replace(/:? ?VerificationResult \{.*$/, "").slice(0, 300); }
  return { per, full };
}
// What each input's script reduces to under this context (sigmastate, no secrets). Keys are named.
// "posting" alone on the authority input = the posting path is TRUE; "owner" alone = the posting path is FALSE.
function reduceReport(eip12, ctx, names, labelOf) {
  try {
    const reduced = ProverBuilder$.create(BLOCKCHAIN_PARAMETERS, 0).build().reduce(ctx.ssCtx, eip12, eip12.inputs, eip12.dataInputs, [], 0);
    const arr = reduced._tx.Lorg_ergoplatform_sdk_ReducedTransaction__f_ergoTx.Lorg_ergoplatform_sdk_ReducedErgoLikeTransaction__f_reducedInputs.sci_ArraySeq$ofRef__f_unsafeArray;
    return Array.from(arr.u ?? arr).map((ri, k) => {
      const v = ri.Lorg_ergoplatform_sdk_ReducedInputData__f_reductionResult.Lsigmastate_interpreter_Interpreter$ReductionResult__f_value;
      let str = String(v);
      const walk = (o, d = 0) => {
        if (!o || typeof o !== "object" || d > 12) return;
        if (o.Lsigma_crypto_Platform$Ecp__f_point) {
          const x = o.Lsigma_crypto_Platform$Ecp__f_point.x.toString(16).padStart(64, "0");
          str = str.split(String(o)).join(names.get(x) ?? "?key");
          return;
        }
        for (const kk of Object.keys(o)) walk(o[kk], d + 1);
      };
      walk(v);
      return `in#${k} ${labelOf(eip12.inputs[k].ergoTree)} => ${str.replace(/ProveDlog\((\w+)\)/g, "proveDlog($1)")}`;
    }).join(" | ");
  } catch (e) { return `(reduction report unavailable: ${String(e?.message ?? e).split("\n")[0].slice(0, 120)})`; }
}

// Consensus rules MockChain does not enforce, plus no-burn. Returns a list of problems (empty = fine).
function lint(eip12, srTx, ctx, { fee }) {
  const problems = [];
  const outs = srTx.outputs(); const outBoxes = [];
  for (let k = 0; k < outs.len(); k++) outBoxes.push(outs.get(k).to_js_eip12());
  const maxInH = Math.max(...eip12.inputs.map((b) => Number(b.creationHeight)));
  outBoxes.forEach((b, k) => {
    const size = BigInt(estimateBoxSize(b));
    const min = size * ctx.minValuePerByte;
    if (BigInt(b.value) < min) problems.push(`output #${k} value ${b.value} < minimum ${min} (${size} B x ${ctx.minValuePerByte})`);
    if (b.creationHeight > ctx.nextHeight) problems.push(`output #${k} creationHeight ${b.creationHeight} > next block height ${ctx.nextHeight}`);
    if (b.creationHeight < maxInH) problems.push(`output #${k} creationHeight ${b.creationHeight} < max input creationHeight ${maxInH} (monotonic-height rule)`);
  });
  const ergIn = eip12.inputs.reduce((s, b) => s + BigInt(b.value), 0n);
  const ergOut = outBoxes.reduce((s, b) => s + BigInt(b.value), 0n);
  if (ergIn !== ergOut) problems.push(`ERG in ${ergIn} != ERG out ${ergOut}`);
  const tin = sumTokens(eip12.inputs), tout = sumTokens(outBoxes);
  for (const [id, a] of tin) if ((tout.get(id) ?? 0n) !== a) problems.push(`TOKEN NOT CONSERVED ${id.slice(0, 12)}..: in ${a} out ${tout.get(id) ?? 0n}`);
  for (const [id] of tout) if (!tin.has(id) && id !== eip12.inputs[0].boxId) problems.push(`token ${id.slice(0, 12)}.. appears from nowhere`);
  const feeOuts = outBoxes.filter((b) => b.ergoTree === FEE_CONTRACT);
  if (feeOuts.length !== 1) problems.push(`expected exactly one miner-fee output, got ${feeOuts.length}`);
  else if (BigInt(feeOuts[0].value) !== fee) problems.push(`fee output ${feeOuts[0].value} != intended ${fee}`);
  if (fee < C.FEE) problems.push(`fee ${fee} below the node default minimalFeeAmount ${C.FEE}`);
  return { problems, outBoxes };
}

// ───────────────────────────── state / persistence ─────────────────────────────
function freshState() {
  return { version: 1, network: "mainnet", seq: 0, keys: {}, contracts: null, funding: null, mint: [], tokens: {},
           boxes: {}, activePosting: "posting", retiredPosting: null, posts: [], negatives: [], rotations: [],
           reclaim: null, txs: [], history: [] };
}
function makeIO(dir, print) {
  const statePath = path.join(dir, "state.json");
  const keysPath = path.join(dir, ".keys.json");
  const txDir = path.join(dir, "txs");
  const writeAtomic = (p, text, mode) => {
    const tmp = p + ".tmp-" + process.pid;
    fs.writeFileSync(tmp, text, { mode }); if (mode) fs.chmodSync(tmp, mode); fs.renameSync(tmp, p);
  };
  return {
    dir, statePath, keysPath, print,
    loadState: () => (fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, "utf-8")) : freshState()),
    saveState: (s) => writeAtomic(statePath, JSON.stringify(s, null, 2) + "\n"),
    keysExist: () => fs.existsSync(keysPath),
    loadKeys: () => {
      if (!fs.existsSync(keysPath)) throw new Error("no keys yet: run `keys` first");
      const st = fs.statSync(keysPath);
      if ((st.mode & 0o077) !== 0) print(`WARNING: ${keysPath} is readable by group/other (mode ${(st.mode & 0o777).toString(8)}); chmod 600 it`);
      const k = JSON.parse(fs.readFileSync(keysPath, "utf-8"));
      for (const v of Object.values(k.keys)) SECRETS.add(v.secret);
      return k;
    },
    createKeys: (obj) => { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(keysPath, JSON.stringify(obj, null, 2) + "\n", { flag: "wx", mode: 0o600 }); fs.chmodSync(keysPath, 0o600); },
    rewriteKeys: (obj) => writeAtomic(keysPath, JSON.stringify(obj, null, 2) + "\n", 0o600),
    saveTx: (name, text) => { fs.mkdirSync(txDir, { recursive: true }); const p = path.join(txDir, name); fs.writeFileSync(p, text + "\n"); return path.relative(dir, p); },
  };
}

// ───────────────────────────── the step engine ─────────────────────────────
// S = { io, net, mode: "dry"|"check"|"broadcast", stampOffset, state, keys (derived), contracts }
function keyset(S) {
  const raw = S.keysRaw.keys;
  const out = {};
  for (const [name, v] of Object.entries(raw)) out[name] = keyFromSecret(v.secret);
  return out;
}
function labelFn(S) {
  const K = S.K ?? {}; const st = S.state;
  return (tree) => {
    if (tree === FEE_CONTRACT) return "miner-fee";
    if (st.contracts && tree === st.contracts.oracleTree) return "oracle-script";
    if (st.contracts && tree === st.contracts.authorityTree) return "authority-script";
    for (const [n, k] of Object.entries(K)) if (k.tree === tree) return `${n}-P2PK`;
    if (st.reclaim?.destTree === tree) return "dest-P2PK";
    return tree.startsWith("0008cd") ? "P2PK(other)" : "P2S(other)";
  };
}
function tokenName(S, id) {
  for (const [n, t] of Object.entries({ ...(S._tmpTokens ?? {}), ...S.state.tokens })) if (t === id) return n;
  return id.slice(0, 10) + "..";
}
function printTx(S, title, eip12, srTx, fee, extra = []) {
  const p = S.io.print; const label = labelFn(S);
  const size = srTx.sigma_serialize_bytes().length;
  const outs = srTx.outputs();
  const fmtBox = (b) => {
    const toks = b.assets.length ? b.assets.map((a) => `${tokenName(S, a.tokenId)}:${a.amount}`).join(",") : "-";
    const regs = Object.keys(b.additionalRegisters ?? {}).filter((r) => b.additionalRegisters[r]).sort().join(",") || "-";
    return `${b.boxId}  ${fmtErg(b.value).padStart(14)} ERG  ${label(b.ergoTree).padEnd(17)} h=${b.creationHeight}  tokens: ${toks}  regs: ${regs}`;
  };
  p(`\n[${title}]`);
  p(`  txId ${srTx.id().to_str()}   size ${size} B   fee ${fmtErg(fee)} ERG`);
  eip12.inputs.forEach((b, k) => p(`  in  #${k}  ${fmtBox(b)}${Object.keys(b.extension ?? {}).length ? `  ctxVars: ${Object.keys(b.extension).join(",")}` : ""}`));
  for (let k = 0; k < outs.len(); k++) p(`  out #${k}  ${fmtBox(outs.get(k).to_js_eip12())}`);
  for (const l of extra) p(`  ${l}`);
  return size;
}

async function getCtx(S) {
  if (!S._ctx) {
    const tip = await S.net.getTip();
    S._ctx = buildContext(tip);
  }
  return S._ctx;
}
function stampFor(S, ctx, inputBoxes) {
  const maxIn = Math.max(...inputBoxes.map((b) => Number(b.creationHeight)));
  return Math.max(ctx.tip - S.stampOffset, maxIn); // monotonic-height rule: never below an input's creation height
}
function snapshot(S) {
  const { history: _h, ...rest } = S.state;
  S.state.history = [...(S.state.history ?? []).slice(-19), JSON.parse(JSON.stringify(rest))];
}
function persist(S) { if (S.io.saveState) S.io.saveState(S.state); }

// Run the dry/check/broadcast tail for one signed tx. Returns { accepted, rejected, body, file }.
async function finish(S, name, srTx, { expectReject = false } = {}) {
  const text = srTx.to_json();
  const tag = S.mode === "broadcast" ? "" : S.mode === "check" ? ".check" : ".dryrun";
  const fileName = S.mode === "broadcast" && !expectReject
    ? `${String(++S.state.seq).padStart(2, "0")}-${name}.json` : `${name}${expectReject ? ".negative" : ""}${tag}.json`;
  const file = S.io.saveTx ? S.io.saveTx(fileName, text) : null;
  if (file) S.io.print(`  saved ${file}`);
  if (S.mode === "dry") { S.io.print("  DRY RUN: nothing sent (add --check to validate on the node, --broadcast to submit)"); return { accepted: false, dry: true, file }; }
  const res = await S.net.submitTx(text, { checkOnly: S.mode === "check" });
  const body = typeof res.body === "string" ? res.body : JSON.stringify(res.body);
  const verb = S.mode === "check" ? "POST /transactions/check" : "POST /transactions";
  if (res.ok) {
    S.io.print(`  node (${verb}): ACCEPTED HTTP ${res.status} ${body.slice(0, 200)}`);
    if (typeof res.body === "string" && res.body !== srTx.id().to_str()) S.io.print(`  WARNING: node returned id ${res.body}, local id ${srTx.id().to_str()}`);
  } else {
    S.io.print(`  node (${verb}): REJECTED HTTP ${res.status} ${body.slice(0, 600)}`);
  }
  return { accepted: res.ok, rejected: !res.ok, body, file, broadcast: S.mode === "broadcast" };
}
function recordTx(S, step, srTx, fee, size, extra = {}) {
  S.state.txs.push({ step, txId: srTx.id().to_str(), size, fee: String(fee), builtAtTip: S._ctx.tip, ...extra });
}
function requireMode(S, ok, msg) { if (!ok) throw new Error(msg); }

// ── budget: derive every value from the contracts and measured sizes ──
export function computeBudget(contracts, mvpb = C.MIN_VALUE_PER_BYTE) {
  const authTree = compileAuthority(contracts);
  const dummy = (b) => b.toString(16).padStart(2, "0").repeat(32);
  const pk = "02" + dummy(0x11);
  const authCand = { value: "11000000", ergoTree: authTree, creationHeight: 1_700_000, assets: [{ tokenId: dummy(0xa2), amount: "1" }],
    additionalRegisters: { R4: SGroupElement(hex.decode(pk)).toHex(), R5: bytesC(dummy(0xa3)).toHex(), R6: SGroupElement(hex.decode(pk)).toHex(),
      R7: SInt(1_700_000).toHex(), R8: SInt(1_700_000).toHex() } };
  const authSize = BigInt(estimateBoxSize(authCand));
  const authMin = authSize * mvpb;
  const authReserve = maxBig(C.FEE, roundUp(2n * authMin, 1_000_000n));
  const authorityValue = C.POSTS_BUDGET * C.FEE + authReserve;
  const changeFloor = C.FEE + 1_000_000n; // reclaim fee + a comfortably-above-minimum destination box
  const minFunding = 3n * C.FEE + C.FEE + C.ORACLE_VALUE + authorityValue + changeFloor;
  const recommended = maxBig(100_000_000n, roundUp(3n * minFunding, 10_000_000n));
  return { authTree, authSize, authMin, authReserve, authorityValue, changeFloor, minFunding, recommended };
}

// ── steps ──
async function stepFund(S, id) {
  requireMode(S, !S.state.funding, "already funded (use `undo --yes` first if the recorded box is wrong)");
  const owner = S.K.owner;
  let got = await S.net.getBox(id);
  if (!got) {
    const st = await S.net.txStatus(id);
    if (st.state === "unknown" || !st.tx) throw new Error(`no unspent box and no tx found with id ${id} (${st.note ?? ""})`);
    const outs = (st.tx.outputs ?? []).filter((o) => o.ergoTree === owner.tree);
    if (outs.length !== 1) throw new Error(`tx ${id} has ${outs.length} outputs to the owner address; pass the box id instead`);
    got = await S.net.getBox(outs[0].boxId);
    if (!got) throw new Error(`owner output ${outs[0].boxId} of tx ${id} is not unspent`);
  }
  const box = normBox(got.box);
  if (box.ergoTree !== owner.tree) throw new Error("that box is not at the owner address");
  if (box.assets.length) throw new Error("the funding box carries tokens; send a plain-ERG box (tokens would have to be carried through every step)");
  const budget = computeBudget(S.contracts);
  if (BigInt(box.value) < budget.minFunding) throw new Error(`funding ${fmtErg(box.value)} ERG < minimum ${fmtErg(budget.minFunding)} ERG (recommended ${fmtErg(budget.recommended)})`);
  snapshot(S);
  S.state.funding = { box, where: got.where };
  persist(S);
  S.io.print(`funding box recorded: ${box.boxId}  ${fmtErg(box.value)} ERG  (${got.where}, creationHeight ${box.creationHeight})`);
  if (BigInt(box.value) < budget.recommended) S.io.print(`note: below the recommended ${fmtErg(budget.recommended)} ERG, but above the minimum`);
  return box;
}

async function stepMint(S) {
  requireMode(S, S.state.funding, "no funding box: run `fund <boxId|txId>` first");
  const ctx = await getCtx(S);
  const owner = S.K.owner;
  const results = [];
  const startK = S.state.mint.length;
  let prev = startK ? S.state.mint[startK - 1].out : S.state.funding.box;
  S._tmpTokens = {};
  for (let k = startK; k < 3; k++) {
    const key = C.MINT_ORDER[k]; const t = C.TOKENS[key];
    const stamp = stampFor(S, ctx, [prev]);
    const outB = new OutputBuilder(BigInt(prev.value) - C.FEE, owner.tree, stamp).addTokens(prev.assets.map((a) => ({ tokenId: a.tokenId, amount: BigInt(a.amount) })))
      .mintToken({ amount: t.amount, name: t.name, decimals: 0, description: t.description });
    const { eip12 } = assemble([{ box: prev }], [outB, new OutputBuilder(C.FEE, FEE_CONTRACT, stamp)]);
    const tokenId = prev.boxId; // a token minted in a tx has id = the tx's FIRST input box id
    S._tmpTokens[key] = tokenId;
    const srTx = signSigmastate(eip12, ctx, [owner.secret]);
    const v = verifyInputs(srTx, eip12, ctx);
    const { problems, outBoxes } = lint(eip12, srTx, ctx, { fee: C.FEE });
    const size = printTx(S, `mint ${k + 1}/3: ${key} token x${t.amount} (id ${tokenId})`, eip12, srTx, C.FEE,
      [`local verify (sigma-rust): ${v.per.map((x, i) => `in#${i} ${x === true ? "OK" : x}`).join(", ")}; validate_tx ${v.full}`,
       problems.length ? `PROBLEMS: ${problems.join("; ")}` : "consensus/no-burn checks: OK"]);
    if (problems.length || v.full !== "OK" || v.per.some((x) => x !== true)) throw new Error("local checks failed; not continuing");
    if (S.mode === "check" && k > startK) {
      const f = S.io.saveTx?.(`mint-${key}.check.json`, srTx.to_json());
      if (f) S.io.print(`  saved ${f}`);
      S.io.print("  not checked on the node: spends an output of a tx that was not submitted (it is checked when you run with --broadcast)");
      results.push({ key, tokenId, srTx, size, r: { dry: true } });
      prev = normBox(outBoxes[0]);
      continue;
    }
    const r = await finish(S, `mint-${key}`, srTx);
    results.push({ key, tokenId, srTx, size, r });
    if (S.mode === "broadcast") {
      if (!r.accepted) throw new Error("node rejected the mint tx; stopping (state unchanged for this tx; rerun `mint` to resume)");
      snapshot(S);
      S.state.tokens[key] = tokenId;
      S.state.mint.push({ key, tokenId, txId: srTx.id().to_str(), out: normBox(outBoxes[0]) });
      recordTx(S, `mint-${key}`, srTx, C.FEE, size);
      persist(S);
    }
    prev = normBox(outBoxes[0]);
  }
  S._tmpTokens = null;
  if (S.state.mint.length === 3) S.io.print(`\nall three tokens minted: oracle=${S.state.tokens.oracle} reward=${S.state.tokens.reward} nft=${S.state.tokens.nft}`);
  return results;
}

function makePrices(seed) {
  return Array.from({ length: C.N_PRICES }, (_v, i) => BigInt(1_000_000 + i * 1_000) + BigInt(seed % 997));
}

async function stepSetup(S) {
  requireMode(S, S.state.mint.length === 3, "mint all three tokens first");
  requireMode(S, !S.state.contracts, "setup already done");
  const ctx = await getCtx(S);
  const owner = S.K.owner, posting = S.K.posting;
  const input = S.state.mint[2].out;
  const nftId = S.state.tokens.nft, oracleId = S.state.tokens.oracle, rewardId = S.state.tokens.reward;
  const authorityTree = compileAuthority(S.contracts);              // FIRST: the oracle pins its hash
  const oracleTree = compileOracle(S.contracts, nftId, authorityTree);
  const budget = computeBudget(S.contracts, ctx.minValuePerByte);
  const stamp = stampFor(S, ctx, [input]);
  const have = sumTokens([input]);
  if (have.get(oracleId) !== 2n || have.get(rewardId) !== 10n || have.get(nftId) !== 1n) throw new Error("mint output does not hold oracle x2, reward x10, nft x1");
  const rest = BigInt(input.value) - C.ORACLE_VALUE - budget.authorityValue - C.FEE;
  const oracleOut = new OutputBuilder(C.ORACLE_VALUE, oracleTree, stamp)
    .addTokens([{ tokenId: oracleId, amount: 1n }, { tokenId: rewardId, amount: 2n }])
    .setAdditionalRegisters({ R4: SGroupElement(hex.decode(owner.pk)), R5: SInt(1), R6: SColl(SLong, makePrices(ctx.tip)) });
  const authOut = new OutputBuilder(budget.authorityValue, authorityTree, stamp)
    .addTokens([{ tokenId: nftId, amount: 1n }])
    // R7 post stamp / R8 fee stamp start at the setup stamp: the first post needs a stamp >= setup stamp + epochLength.
    .setAdditionalRegisters({ R4: SGroupElement(hex.decode(owner.pk)), R5: bytesC(oracleId), R6: SGroupElement(hex.decode(posting.pk)),
      R7: SInt(stamp), R8: SInt(stamp) });
  const extraTokens = input.assets.filter((a) => ![oracleId, rewardId, nftId].includes(a.tokenId)).map((a) => ({ tokenId: a.tokenId, amount: BigInt(a.amount) }));
  const changeOut = new OutputBuilder(rest, owner.tree, stamp)
    .addTokens([{ tokenId: oracleId, amount: 1n }, { tokenId: rewardId, amount: 8n }, ...extraTokens]);
  const { eip12 } = assemble([{ box: input }], [oracleOut, authOut, changeOut, new OutputBuilder(C.FEE, FEE_CONTRACT, stamp)]);
  // Temporarily expose the trees for labels.
  const prevContracts = S.state.contracts;
  S.state.contracts = { oracleTree, authorityTree };
  const srTx = signSigmastate(eip12, ctx, [owner.secret]);
  const v = verifyInputs(srTx, eip12, ctx);
  const { problems, outBoxes } = lint(eip12, srTx, ctx, { fee: C.FEE });
  const size = printTx(S, "setup: dummy oracle box + authority box", eip12, srTx, C.FEE, [
    `oracle script  ${p2sAddress(oracleTree)}  (${oracleTree.length / 2} B tree; poolNftId = unreachable dummy, authorityNftId = ${nftId}, authorityScriptHash = ${authorityScriptHashOf(authorityTree)})`,
    `authority script ${p2sAddress(authorityTree)}  (${authorityTree.length / 2} B tree; epochLength=${C.EPOCH_LENGTH})`,
    `authority value ${fmtErg(budget.authorityValue)} ERG = ${C.POSTS_BUDGET} posts x ${fmtErg(C.FEE)} + reserve ${fmtErg(budget.authReserve)} (box min ${fmtErg(budget.authMin)})`,
    `first post allowed once tip-${S.stampOffset} >= ${stamp + C.EPOCH_LENGTH} (i.e. tip >= ${stamp + C.EPOCH_LENGTH + S.stampOffset})`,
    `local verify (sigma-rust): ${v.per.map((x, i) => `in#${i} ${x === true ? "OK" : x}`).join(", ")}; validate_tx ${v.full}`,
    problems.length ? `PROBLEMS: ${problems.join("; ")}` : "consensus/no-burn checks: OK"]);
  S.state.contracts = prevContracts;
  if (problems.length || v.full !== "OK" || v.per.some((x) => x !== true)) throw new Error("local checks failed");
  const r = await finish(S, "setup", srTx);
  if (r.accepted && r.broadcast) {
    snapshot(S);
    S.state.contracts = { oracleTree, authorityTree, oracleAddress: p2sAddress(oracleTree), authorityAddress: p2sAddress(authorityTree),
      epochLength: C.EPOCH_LENGTH, maxFeePerEpoch: String(S.contracts.maxFeePerEpoch), mempoolSlack: S.contracts.mempoolSlack,
      minStorageRent: String(S.contracts.minStorageRent), poolNftId: POOL_NFT_DUMMY, authorityNftId: nftId,
      authorityScriptHash: authorityScriptHashOf(authorityTree) };
    S.state.boxes = { oracle: normBox(outBoxes[0]), authority: normBox(outBoxes[1]), ownerChange: normBox(outBoxes[2]) };
    recordTx(S, "setup", srTx, C.FEE, size);
    persist(S);
  }
  return { srTx, r, size };
}

function warnDrift(S) {
  const c = S.state.contracts; if (!c) return;
  try {
    // state.json written before the audit records the NFT as companionNftId
    const nowAuth = compileAuthority(S.contracts), nowOracle = compileOracle(S.contracts, c.authorityNftId ?? c.companionNftId, nowAuth);
    if (nowAuth !== c.authorityTree || nowOracle !== c.oracleTree)
      S.io.print("WARNING: the contract sources in ../ now compile to different trees than the deployed ones; using the DEPLOYED trees and the cap recorded at setup.");
  } catch (e) { S.io.print(`WARNING: current contract sources no longer compile (${String(e.message).slice(0, 80)}); using the deployed trees.`); }
}

// Build a post (honest or a negative-control variant) at the current tip.
// priceSalt != 0 makes the tx bytes (and so the tx id) differ from the honest post at the same height. The node
// caches the ids of txs it rejected, so a negative control must never share an id with a post you later want mined.
function buildPostTx(S, ctx, { variant = "honest", priceSalt = 0 } = {}) {
  const c = S.state.contracts; const ob = S.state.boxes.oracle, ab = S.state.boxes.authority;
  const cap = BigInt(c.maxFeePerEpoch);
  const fee = variant === "overfee" ? cap + C.FEE : C.FEE;
  const changeV = variant === "change" ? C.CHANGE_VARIANT_VALUE : 0n;
  const stamp = stampFor(S, ctx, [ob, ab]);
  const epoch = Number(regVal(ob, "R5")) + 1;
  const oracleOut = new OutputBuilder(BigInt(ob.value), c.oracleTree, stamp)
    .addTokens(ob.assets.map((a) => ({ tokenId: a.tokenId, amount: BigInt(a.amount) })))
    .setAdditionalRegisters({ R4: ob.additionalRegisters.R4, R5: SInt(epoch), R6: SColl(SLong, makePrices(ctx.tip + epoch + priceSalt)) });
  // A post writes its stamp into R7 and carries R8 (the fee stamp) over.
  const succ = new OutputBuilder(BigInt(ab.value) - fee - changeV, c.authorityTree, stamp)
    .addTokens(ab.assets.map((a) => ({ tokenId: a.tokenId, amount: BigInt(a.amount) })))
    .setAdditionalRegisters({ R4: ab.additionalRegisters.R4, R5: ab.additionalRegisters.R5, R6: ab.additionalRegisters.R6,
      R7: SInt(stamp), R8: ab.additionalRegisters.R8 });
  const outs = [oracleOut, succ];
  if (changeV) outs.push(new OutputBuilder(changeV, S.K.owner.tree, stamp));
  outs.push(new OutputBuilder(fee, FEE_CONTRACT, stamp));
  const { eip12 } = assemble([{ box: ob, ext: { 0: SInt(0) } }, { box: ab }], outs);
  return { eip12, fee, stamp, epoch, unlockAt: postStampOf(ab) + C.EPOCH_LENGTH };
}
function assertPostShape(S, eip12, fee, signer) {
  const c = S.state.contracts; const fails = [];
  const ins = eip12.inputs, outs = eip12.outputs;
  if (ins.length !== 2 || ins[0].ergoTree !== c.oracleTree || ins[1].ergoTree !== c.authorityTree) fails.push("inputs are not exactly [oracle box, authority box]");
  if (ins.some((b) => b.ergoTree.startsWith("0008cd"))) fails.push("a P2PK input is present");
  if (ins.some((b) => b.ergoTree === signer.tree)) fails.push("the posting key's own P2PK box is an input");
  if (outs.length !== 3 || outs[0].ergoTree !== c.oracleTree || outs[1].ergoTree !== c.authorityTree || outs[2].ergoTree !== FEE_CONTRACT)
    fails.push("outputs are not exactly [oracle', authority', miner fee] (change output present?)");
  if (outs.some((b) => b.ergoTree.startsWith("0008cd"))) fails.push("an output pays a P2PK address");
  if (fee > BigInt(c.maxFeePerEpoch)) fails.push(`fee ${fee} > cap ${c.maxFeePerEpoch}`);
  if (gePk(ins[1], "R6") !== signer.pk) fails.push("signer is not the authority box's R6 posting key");
  const ein = ins.reduce((s, b) => s + BigInt(b.value), 0n), eout = outs.reduce((s, b) => s + BigInt(b.value), 0n);
  if (ein !== eout) fails.push("ERG not balanced");
  return fails;
}
function names(S) {
  const m = new Map();
  for (const [n, k] of Object.entries(S.K)) m.set(k.pk.slice(2), n);
  return m;
}

async function stepPost(S) {
  requireMode(S, S.state.contracts && S.state.boxes.authority && !S.state.reclaim, "run `setup` first (or the box was reclaimed)");
  warnDrift(S);
  const ctx = await getCtx(S);
  const signer = S.K[S.state.activePosting];
  const { eip12, fee, stamp, epoch, unlockAt } = buildPostTx(S, ctx);
  if (stamp < unlockAt) {
    const needTip = unlockAt + S.stampOffset;
    S.io.print(`HEIGHT LOCK: this post would be stamped ${stamp}, the authority box (post stamp R7 = ${postStampOf(S.state.boxes.authority)}) allows >= ${unlockAt}.`);
    S.io.print(`wait until the node tip is >= ${needTip} (${needTip - ctx.tip} more block(s)); nothing built.`);
    return { tooEarly: true, needTip };
  }
  const fails = assertPostShape(S, eip12, fee, signer);
  if (fails.length) throw new Error(`post shape assertion failed: ${fails.join("; ")}`);
  let srTx;
  try { srTx = signSigmastate(eip12, ctx, [signer.secret]); }
  catch (e) {
    S.io.print(`local signing FAILED with the ${S.state.activePosting} key only: ${String(e.message).split("\n")[0].slice(0, 200)}`);
    S.io.print(`reduced: ${reduceReport(eip12, ctx, names(S), labelFn(S))}`);
    throw new Error("post cannot be signed by the posting key alone");
  }
  const v = verifyInputs(srTx, eip12, ctx);
  const { problems, outBoxes } = lint(eip12, srTx, ctx, { fee });
  const size = printTx(S, `post (epoch ${epoch}, signed by the ${S.state.activePosting} key ONLY)`, eip12, srTx, fee, [
    `assertions: inputs=[oracle-script, authority-script], no P2PK input, outputs=[oracle', authority', miner-fee], no change output, fee ${fmtErg(fee)} <= cap ${fmtErg(S.state.contracts.maxFeePerEpoch)}: OK`,
    `signers: ${S.state.activePosting} only (the posting key owns no box; its only power is the authority script's proveDlog(R6))`,
    `height: stamped ${stamp} (tip ${ctx.tip} - ${ctx.tip - stamp}); authority allows ${unlockAt}..; includable in blocks ${ctx.nextHeight}..${stamp + S.state.contracts.mempoolSlack}`,
    `local verify (sigma-rust): ${v.per.map((x, i) => `in#${i} ${x === true ? "OK" : x}`).join(", ")}; validate_tx ${v.full}`,
    problems.length ? `PROBLEMS: ${problems.join("; ")}` : "consensus/no-burn checks: OK"]);
  if (problems.length || v.full !== "OK" || v.per.some((x) => x !== true)) throw new Error("local checks failed");
  const r = await finish(S, `post-e${epoch}`, srTx);
  if (r.accepted && r.broadcast) {
    snapshot(S);
    S.state.boxes.oracle = normBox(outBoxes[0]); S.state.boxes.authority = normBox(outBoxes[1]);
    S.state.posts.push({ txId: srTx.id().to_str(), epoch, stamp, key: S.state.activePosting, builtAtTip: ctx.tip });
    recordTx(S, `post-e${epoch}`, srTx, fee, size);
    persist(S);
  }
  return { srTx, r, size, fee, eip12 };
}

async function stepPostBad(S, variant) {
  const VARIANTS = ["early", "change", "overfee", "oldkey"];
  requireMode(S, VARIANTS.includes(variant), `variant must be one of ${VARIANTS.join("|")}`);
  requireMode(S, S.state.contracts && S.state.boxes.authority && !S.state.reclaim, "run `setup` first");
  warnDrift(S);
  const ctx = await getCtx(S);
  const lab = labelFn(S);
  let signerName = S.state.activePosting;
  if (variant === "oldkey") {
    requireMode(S, S.state.retiredPosting, "`oldkey` needs a completed `rotate`");
    signerName = S.state.retiredPosting;
  }
  const signer = S.K[signerName];
  const control = buildPostTx(S, ctx);
  if (variant === "early") {
    requireMode(S, S.state.posts.length > 0, "`early` must follow a successful post");
    if (control.stamp >= control.unlockAt)
      throw new Error(`the height lock is already open (stamp ${control.stamp} >= ${control.unlockAt}); \`early\` would be a valid post now. Run it within ${C.EPOCH_LENGTH} blocks of a post.`);
  } else {
    // The variant must be the ONLY reason for rejection: the honest post at this height must verify locally.
    if (control.stamp < control.unlockAt) throw new Error(`height lock closed until tip ${control.unlockAt + S.stampOffset}; the honest control would also fail. Wait and rerun.`);
    const honestSigner = S.K[S.state.activePosting];
    const csr = signSigmastate(control.eip12, ctx, [honestSigner.secret]);
    const cv = verifyInputs(csr, control.eip12, ctx);
    if (cv.full !== "OK") throw new Error(`honest control does not verify locally (${cv.full}); not a clean negative`);
    S.io.print(`control: the honest post at this height (signed by ${S.state.activePosting}) verifies locally: ${cv.per.map((x, i) => `in#${i} ${x === true ? "OK" : x}`).join(", ")}`);
  }
  const salt = 100 + VARIANTS.indexOf(variant) * 10 + (S.mode === "check" ? 1 : S.mode === "dry" ? 2 : 0);
  const { eip12, fee } = buildPostTx(S, ctx, { variant: variant === "oldkey" || variant === "early" ? "honest" : variant, priceSalt: salt });
  const idOf = (e) => SR.UnsignedTransaction.from_json(JSON.stringify(e)).id().to_str();
  if (idOf(eip12) === idOf(control.eip12)) throw new Error("negative control would share its tx id with the honest post; refusing");
  let signErr = "(none)";
  try { signSigmastate(eip12, ctx, [signer.secret]); signErr = null; }
  catch (e) { signErr = String(e.message).split("\n")[0].slice(0, 200); }
  const reason = reduceReport(eip12, ctx, names(S), lab);
  if (signErr === null) throw new Error(`ALARM: the ${signerName} key alone CAN sign the '${variant}' tx locally; the contract accepts it. Not sending.`);
  const srTx = signAsPostingKeyOnly(eip12, signer, S.state.contracts.authorityTree);
  const v = verifyInputs(srTx, eip12, ctx);
  const authIdx = eip12.inputs.findIndex((b) => b.ergoTree === S.state.contracts.authorityTree);
  const desc = { early: "second post before the height lock allows", change: "extra output to the owner address", overfee: `fee ${fmtErg(fee)} above the cap ${fmtErg(S.state.contracts.maxFeePerEpoch)}`, oldkey: "post signed by the OLD (rotated-out) posting key" }[variant];
  const size = printTx(S, `post-bad ${variant}: ${desc} — MUST BE REJECTED`, eip12, srTx, fee, [
    `interpreter (sigmastate, ${signerName} key only): ${signErr}`,
    `reduced: ${reason}`,
    `local verify (sigma-rust) with the ${signerName} key's real signature on the authority input: ${v.per.map((x, i) => `in#${i} ${x === true ? "OK" : x === false ? "FAILS" : x}`).join(", ")}; validate_tx: ${v.full}`]);
  if (v.per[authIdx] === true || v.full === "OK") throw new Error(`ALARM: the '${variant}' tx VERIFIES locally; not sending.`);
  const r = await finish(S, `post-bad-${variant}`, srTx, { expectReject: true });
  const outcome = r.dry ? "local-only" : r.accepted ? "ACCEPTED(ALARM)" : "rejected";
  S.state.negatives.push({ variant, txId: srTx.id().to_str(), outcome, mode: S.mode, atTip: ctx.tip, node: r.body ? String(r.body).slice(0, 300) : null });
  if (r.accepted && r.broadcast) {
    S.io.print("ALARM: the node ACCEPTED a negative control. The contract does not enforce this rule. State updated to follow the chain.");
    const outs = srTx.outputs();
    snapshot(S);
    S.state.boxes.oracle = normBox(outs.get(0).to_js_eip12()); S.state.boxes.authority = normBox(outs.get(1).to_js_eip12());
  }
  persist(S);
  return { srTx, r, size, signErr, reason, v, outcome };
}

async function stepRotate(S) {
  requireMode(S, S.state.contracts && S.state.boxes.authority && !S.state.reclaim, "run `setup` first");
  requireMode(S, !S.state.retiredPosting, "already rotated once; this smoke test supports one rotation");
  warnDrift(S);
  if (!S.keysRaw.keys.posting2) {
    S.keysRaw.keys.posting2 = { secret: newSecret() };
    SECRETS.add(S.keysRaw.keys.posting2.secret);
    S.io.rewriteKeys?.(S.keysRaw);
    S.K = keyset(S);
    S.io.print("generated a new posting key (posting2) into .keys.json");
  }
  const ctx = await getCtx(S);
  const ab = S.state.boxes.authority, c = S.state.contracts;
  const stamp = stampFor(S, ctx, [ab]);
  const newKey = S.K.posting2;
  const succ = new OutputBuilder(BigInt(ab.value) - C.FEE, c.authorityTree, stamp)
    .addTokens(ab.assets.map((a) => ({ tokenId: a.tokenId, amount: BigInt(a.amount) })))
    .setAdditionalRegisters({ R4: ab.additionalRegisters.R4, R5: ab.additionalRegisters.R5, R6: SGroupElement(hex.decode(newKey.pk)),
      R7: ab.additionalRegisters.R7, R8: ab.additionalRegisters.R8 });
  const { eip12 } = assemble([{ box: ab }], [succ, new OutputBuilder(C.FEE, FEE_CONTRACT, stamp)]);
  const srTx = signSigmastate(eip12, ctx, [S.K.owner.secret]);
  const v = verifyInputs(srTx, eip12, ctx);
  const { problems, outBoxes } = lint(eip12, srTx, ctx, { fee: C.FEE });
  const size = printTx(S, "rotate: owner (cold) key replaces R6 with posting2, in place; fee out of the authority box", eip12, srTx, C.FEE, [
    `next post (new key) allowed once tip >= ${postStampOf(ab) + C.EPOCH_LENGTH + S.stampOffset} (the rotation carries R7/R8 over: it does not restart the lock)`,
    `local verify (sigma-rust): ${v.per.map((x, i) => `in#${i} ${x === true ? "OK" : x}`).join(", ")}; validate_tx ${v.full}`,
    problems.length ? `PROBLEMS: ${problems.join("; ")}` : "consensus/no-burn checks: OK"]);
  if (problems.length || v.full !== "OK" || v.per.some((x) => x !== true)) throw new Error("local checks failed");
  const r = await finish(S, "rotate", srTx);
  if (r.accepted && r.broadcast) {
    snapshot(S);
    S.state.boxes.authority = normBox(outBoxes[0]);
    S.state.retiredPosting = S.state.activePosting; S.state.activePosting = "posting2";
    S.state.rotations.push({ txId: srTx.id().to_str(), stamp });
    recordTx(S, "rotate", srTx, C.FEE, size);
    persist(S);
  }
  return { srTx, r, size };
}

async function stepReclaim(S, destAddr) {
  requireMode(S, S.state.contracts && S.state.boxes.authority && !S.state.reclaim, "nothing to reclaim (no setup, or already reclaimed)");
  requireMode(S, destAddr, "usage: reclaim <mainnet P2PK address>");
  let dest;
  try { dest = ErgoAddress.decode(destAddr); } catch { throw new Error("destination is not a valid address"); }
  const destTree = dest.ergoTree;
  if (!destAddr.startsWith("9") || !destTree.startsWith("0008cd") || destTree.length !== 72) throw new Error("destination must be a MAINNET P2PK address (starts with 9)");
  for (const [n, k] of Object.entries(S.K)) if (k.tree === destTree) throw new Error(`destination is the throwaway ${n} address; give your own wallet address`);
  warnDrift(S);
  const ctx = await getCtx(S);
  const { oracle: ob, authority: ab, ownerChange: cb } = S.state.boxes;
  const c = S.state.contracts;
  const stamp = stampFor(S, ctx, [ob, ab, cb]);
  const minRent = BigInt(c.minStorageRent);
  // The oracle box can never leave the oracle script (isSimpleCopy: same script, tokens(0) = oracle token,
  // R4 defined, value >= minStorageRent, on every path). The owner keeps it at exactly minStorageRent with only the
  // oracle token, and takes the reward tokens + any ERG above minStorageRent.
  const oracleKeep = [{ tokenId: ob.assets[0].tokenId, amount: BigInt(ob.assets[0].amount) }];
  const oracleOut = new OutputBuilder(minRent, c.oracleTree, stamp).addTokens(oracleKeep)
    .setAdditionalRegisters({ R4: ob.additionalRegisters.R4, R5: ob.additionalRegisters.R5, R6: ob.additionalRegisters.R6 });
  const all = sumTokens([ob, ab, cb]);
  all.set(oracleKeep[0].tokenId, all.get(oracleKeep[0].tokenId) - oracleKeep[0].amount);
  const order = [S.state.tokens.nft, S.state.tokens.oracle, S.state.tokens.reward];
  const ids = [...order.filter((id) => (all.get(id) ?? 0n) > 0n), ...[...all.keys()].filter((id) => !order.includes(id) && all.get(id) > 0n)];
  const destValue = BigInt(ob.value) + BigInt(ab.value) + BigInt(cb.value) - minRent - C.FEE;
  const destOut = new OutputBuilder(destValue, destTree, stamp).addTokens(ids.map((id) => ({ tokenId: id, amount: all.get(id) })));
  const { eip12 } = assemble([{ box: ob, ext: { 0: SInt(0) } }, { box: ab }, { box: cb }], [oracleOut, destOut, new OutputBuilder(C.FEE, FEE_CONTRACT, stamp)]);
  S.state.reclaim = { destTree, pending: true };
  let srTx, v, problems, outBoxes, size;
  try {
    srTx = signSigmastate(eip12, ctx, [S.K.owner.secret]);
    v = verifyInputs(srTx, eip12, ctx);
    ({ problems, outBoxes } = lint(eip12, srTx, ctx, { fee: C.FEE }));
    size = printTx(S, "reclaim: owner key takes the NFT, all ERG and every token that can leave", eip12, srTx, C.FEE, [
      `stranded forever in the oracle script: ${fmtErg(minRent)} ERG + oracle token x${oracleKeep[0].amount}`,
      `to ${destAddr}: ${fmtErg(destValue)} ERG + ${ids.map((id) => `${tokenName(S, id)}:${all.get(id)}`).join(", ")}`,
      `local verify (sigma-rust): ${v.per.map((x, i) => `in#${i} ${x === true ? "OK" : x}`).join(", ")}; validate_tx ${v.full}`,
      problems.length ? `PROBLEMS: ${problems.join("; ")}` : "consensus/no-burn checks: OK"]);
  } finally { S.state.reclaim = null; }
  if (problems.length || v.full !== "OK" || v.per.some((x) => x !== true)) throw new Error("local checks failed");
  const r = await finish(S, "reclaim", srTx);
  if (r.accepted && r.broadcast) {
    snapshot(S);
    S.state.reclaim = { destTree, destAddress: destAddr, txId: srTx.id().to_str(), destBox: normBox(outBoxes[1]), strandedOracleBox: normBox(outBoxes[0]) };
    S.state.boxes = { strandedOracle: normBox(outBoxes[0]) };
    recordTx(S, "reclaim", srTx, C.FEE, size);
    persist(S);
  }
  return { srTx, r, size, outBoxes };
}

async function stepStatus(S, live) {
  const p = S.io.print; const st = S.state;
  p(`state: ${S.io.statePath ?? "(memory)"}`);
  p(`owner address: ${st.keys.ownerAddress ?? "(no keys)"}`);
  p(`funding: ${st.funding ? `${st.funding.box.boxId} ${fmtErg(st.funding.box.value)} ERG` : "-"}`);
  p(`tokens: ${C.MINT_ORDER.map((k) => `${k}=${st.tokens[k] ?? "-"}`).join("  ")}`);
  if (st.contracts) p(`scripts: oracle ${st.contracts.oracleAddress}\n         authority ${st.contracts.authorityAddress}`);
  for (const [n, b] of Object.entries(st.boxes ?? {}))
    p(`box ${n.padEnd(15)} ${b.boxId}  ${fmtErg(b.value)} ERG  h=${b.creationHeight}  tokens: ${b.assets.map((a) => `${tokenName(S, a.tokenId)}:${a.amount}`).join(",") || "-"}`);
  if (st.boxes?.authority) p(`next post allowed at tip >= ${postStampOf(st.boxes.authority) + C.EPOCH_LENGTH + S.stampOffset} (stamp offset ${S.stampOffset}); active posting key: ${st.activePosting}`);
  p(`posts: ${st.posts.map((x) => `e${x.epoch}@stamp${x.stamp}(${x.key}) ${x.txId}`).join("\n       ") || "-"}`);
  p(`negative controls: ${st.negatives.map((x) => `${x.variant}:${x.outcome}[${x.mode}]`).join(", ") || "-"}`);
  if (st.reclaim) p(`reclaimed to ${st.reclaim.destAddress} in ${st.reclaim.txId}`);
  p("txs:");
  for (const t of st.txs) {
    let s = "";
    if (live) { const r = await S.net.txStatus(t.txId); s = `  [${r.state}${r.numConfirmations != null ? ` ${r.numConfirmations} conf` : ""}${r.note ? ` ${r.note}` : ""}]`; }
    p(`  ${t.step.padEnd(14)} ${t.txId}  ${t.size} B  fee ${fmtErg(t.fee)}  built at tip ${t.builtAtTip}${s}`);
  }
}

// ───────────────────────────── plan (simulated end to end, measured) ─────────────────────────────
// In-memory chain for `plan`: same builders, ephemeral keys never written anywhere, sizes measured on real txs.
export function createSimNet({ height = 1_650_000, check } = {}) {
  const utxos = new Map(); const txs = new Map(); let h = height; const cache = new Map();
  const headersAt = (H) => {
    if (!cache.has(H)) cache.set(H, mockHeaders(10).map((x, j) => ({ ...x, height: H - j, timestamp: 1_790_000_000_000 + (H - j) * 120_000 })));
    return cache.get(H);
  };
  return {
    get height() { return h; },
    mine(n = 1) { h += n; },
    addBox(b) { utxos.set(b.boxId, normBox(b)); },
    async getTip() { return { height: h, headers: headersAt(h), minValuePerByte: 360 }; },
    async getBox(id) { return utxos.has(id) ? { box: utxos.get(id), where: "utxo" } : null; },
    async submitTx(text, { checkOnly = false } = {}) {
      const tx = SR.Transaction.from_json(text);
      const j = JSON.parse(text);
      const ins = j.inputs.map((i) => utxos.get(i.boxId));
      if (ins.some((b) => !b)) return { ok: false, status: 400, body: { error: 400, reason: "bad.request", detail: "input not found" } };
      const ctx = buildContext({ height: h, headers: headersAt(h) });
      try { SR.validate_tx(tx, ctx.srCtx, SR.ErgoBoxes.from_boxes_json(ins), SR.ErgoBoxes.from_boxes_json([])); }
      catch (e) { return { ok: false, status: 400, body: { error: 400, reason: "bad.request", detail: String(e?.message ?? e).slice(0, 300) } }; }
      if (check) { const extra = check(j, ins, ctx); if (extra) return { ok: false, status: 400, body: { error: 400, reason: "bad.request", detail: extra } }; }
      if (checkOnly) return { ok: true, status: 200, body: tx.id().to_str() };
      for (const i of j.inputs) utxos.delete(i.boxId);
      const outs = tx.outputs(); for (let k = 0; k < outs.len(); k++) { const b = normBox(outs.get(k).to_js_eip12()); utxos.set(b.boxId, b); }
      txs.set(tx.id().to_str(), { at: h + 1, tx: j });
      h += 1;
      return { ok: true, status: 200, body: tx.id().to_str() };
    },
    async txStatus(id) { return txs.has(id) ? { state: "confirmed", tx: txs.get(id).tx, inclusionHeight: txs.get(id).at, numConfirmations: h - txs.get(id).at + 1 } : { state: "unknown" }; },
    utxos,
  };
}

async function runPlan(print) {
  const contracts = loadContracts();
  const budget = computeBudget(contracts);
  const sim = createSimNet();
  const quiet = [];
  const io = { print: (l) => quiet.push(l), dir: null };
  const keysRaw = { keys: { owner: { secret: newSecret() }, posting: { secret: newSecret() } } };
  for (const v of Object.values(keysRaw.keys)) SECRETS.add(v.secret);
  const S = { io, net: sim, mode: "broadcast", stampOffset: 1, state: freshState(), keysRaw, contracts };
  S.K = keyset(S);
  const F = budget.recommended;
  const fundBox = mockUTxO({ value: F, ergoTree: S.K.owner.tree, creationHeight: sim.height, assets: [], additionalRegisters: {} });
  sim.addBox(fundBox);
  const fresh = () => { S._ctx = null; };
  const rows = [];
  const wait = (blocks) => { sim.mine(blocks); fresh(); };
  const untilUnlock = () => { const need = postStampOf(S.state.boxes.authority) + C.EPOCH_LENGTH + S.stampOffset; if (sim.height < need) wait(need - sim.height); };
  await stepFund(S, fundBox.boxId); fresh();
  const mints = await stepMint(S); fresh();
  for (const m of mints) rows.push({ step: `mint-${m.key}`, size: m.size, fee: C.FEE, signer: "owner" });
  const su = await stepSetup(S); fresh(); rows.push({ step: "setup", size: su.size, fee: C.FEE, signer: "owner" });
  untilUnlock();
  const p1 = await stepPost(S); fresh(); rows.push({ step: "post #1", size: p1.size, fee: p1.fee, signer: "posting" });
  const neg = [];
  S.mode = "dry"; const e = await stepPostBad(S, "early"); S.mode = "broadcast"; fresh(); neg.push(["early", e.size]);
  untilUnlock();
  const p2 = await stepPost(S); fresh(); rows.push({ step: "post #2", size: p2.size, fee: p2.fee, signer: "posting" });
  untilUnlock();
  for (const v of ["change", "overfee"]) { S.mode = "dry"; const x = await stepPostBad(S, v); S.mode = "broadcast"; fresh(); neg.push([v, x.size]); }
  const rot = await stepRotate(S); fresh(); rows.push({ step: "rotate", size: rot.size, fee: C.FEE, signer: "owner" });
  untilUnlock();
  { S.mode = "dry"; const x = await stepPostBad(S, "oldkey"); S.mode = "broadcast"; fresh(); neg.push(["oldkey", x.size]); }
  const p3 = await stepPost(S); fresh(); rows.push({ step: "post #3 (new key)", size: p3.size, fee: p3.fee, signer: "posting2" });
  const destKey = keyFromSecret(newSecret()); SECRETS.add(destKey.secret);
  const rc = await stepReclaim(S, destKey.address); fresh(); rows.push({ step: "reclaim", size: rc.size, fee: C.FEE, signer: "owner" });

  const fees = rows.reduce((s, r) => s + r.fee, 0n);
  const dest = S.state.reclaim.destBox, stranded = S.state.reclaim.strandedOracleBox;
  const oracleBox = S.state.boxes.strandedOracle;
  const p = print;
  p("PLAN — mainnet smoke test resource math (measured on a full simulated run of the same builders)");
  p("");
  p("Parameters (parsed from the contract sources at run time):");
  p(`  CompanionAuthorityHotKey.es   maxFeePerEpoch = ${fmtErg(contracts.maxFeePerEpoch)} ERG   mempoolSlack = ${contracts.mempoolSlack}   epochLength (compile) = ${C.EPOCH_LENGTH}`);
  p(`  OracleContractV2-valuefix.es  minStorageRent = ${fmtErg(contracts.minStorageRent)} ERG   poolNftId = unreachable dummy   authorityNftId = the minted authority NFT   authorityScriptHash = blake2b256(authority tree)`);
  p(`  fee per tx = ${fmtErg(C.FEE)} ERG (post fee ${C.FEE <= contracts.maxFeePerEpoch ? "<=" : ">"} cap)   min box value = bytes x ${C.MIN_VALUE_PER_BYTE} nanoERG`);
  p("");
  p("Transactions that land on chain (in order):");
  p("  step                 size(B)   fee(ERG)      signed by");
  for (const r of rows) p(`  ${r.step.padEnd(20)} ${String(r.size).padStart(7)}   ${fmtErg(r.fee)}   ${r.signer}`);
  p(`  ${"TOTAL".padEnd(20)} ${String(rows.reduce((s, r) => s + r.size, 0)).padStart(7)}   ${fmtErg(fees)}   (${rows.length} txs)`);
  p("Negative controls (rejected by the node at submission: cost 0, nothing mined):");
  for (const [v, s] of neg) p(`  post-bad ${v.padEnd(8)} ${String(s).padStart(5)} B`);
  p("");
  p("Box values:");
  p(`  funding box (operator -> owner address) ${fmtErg(F)} ERG  (recommended; hard minimum ${fmtErg(budget.minFunding)})`);
  p(`  mint outputs: funding - 0.001 per mint, all value + tokens carried in one owner box`);
  p(`  oracle box        ${fmtErg(C.ORACLE_VALUE)} ERG + oracle x1 + reward x2   (R4 owner, R5 epoch, R6 ${C.N_PRICES} prices)`);
  p(`  authority box     ${fmtErg(budget.authorityValue)} ERG + NFT x1   = ${C.POSTS_BUDGET} posts x ${fmtErg(C.FEE)} + reserve ${fmtErg(budget.authReserve)}  (box ${budget.authSize} B, min ${fmtErg(budget.authMin)})`);
  p(`  owner change      ${fmtErg(F - 4n * C.FEE - C.ORACLE_VALUE - budget.authorityValue)} ERG + oracle x1 (spare) + reward x8`);
  p(`  each post moves ${fmtErg(C.FEE)} ERG from the authority box to the miner; rotate also pays ${fmtErg(C.FEE)} from it`);
  p("");
  p("At the end (after reclaim):");
  p(`  spent on fees (gone)          ${fmtErg(fees)} ERG`);
  p(`  PERMANENTLY STRANDED          ${fmtErg(stranded.value)} ERG + 1 dummy oracle token, in the oracle box at the oracle script.`);
  p("                                The dummy oracle box can never leave the oracle script: every spending path requires");
  p("                                isSimpleCopy (same script, oracle token at tokens(0), R4, value >= minStorageRent).");
  p("                                The owner can only withdraw its reward tokens and any ERG above minStorageRent.");
  p(`  returned to your address      ${fmtErg(dest.value)} ERG + ${dest.assets.map((a) => `${tokenName(S, a.tokenId)}:${a.amount}`).join(", ")}`);
  p(`  check: returned + stranded + fees = ${fmtErg(BigInt(dest.value) + BigInt(stranded.value) + fees)} ERG = funding ${fmtErg(F)} ERG: ${BigInt(dest.value) + BigInt(stranded.value) + fees === F ? "OK" : "MISMATCH"}`);
  p(`  net cost of the whole test    ${fmtErg(fees + BigInt(stranded.value))} ERG (+ any extra posts you choose to make, ${fmtErg(C.FEE)} each)`);
  p("");
  p(`RECOMMENDED FUNDING: send ${fmtErg(F)} ERG (one plain-ERG box, no tokens) to the owner address.`);
  p(`  hard minimum ${fmtErg(budget.minFunding)} ERG; everything except ${fmtErg(fees + BigInt(stranded.value))} ERG comes back at reclaim.`);
  p("");
  p(`Timing: post #1 needs ~${C.EPOCH_LENGTH + 1} blocks after setup; each next post ${C.EPOCH_LENGTH}+ blocks after the previous one;`);
  p(`  post-bad early must run within ~${C.EPOCH_LENGTH - 1} blocks after a post; change/overfee/oldkey only while the lock is OPEN`);
  p(`  (the script checks both); the ${C.EPOCH_LENGTH}-block lock runs on the post stamp R7, which rotate keeps. Whole live run ~25-35 blocks (~1 h).`);
  p(`  A post is includable only in blocks tip+1..tip+${contracts.mempoolSlack - 1} (stamped tip-1). If it is not mined by then it`);
  p("  expires: check `status --live`; once it shows unknown, `undo --yes` and post again (costs nothing).");
  if (!oracleBox) p("(internal: oracle box not recorded)");
  return { rows, fees, F, budget, dest, stranded };
}

// ───────────────────────────── CLI ─────────────────────────────
function parseArgs(argv) {
  const flags = { broadcast: false, check: false, live: false, yes: false, stampOffset: 1 };
  const pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--broadcast") flags.broadcast = true;
    else if (a === "--check") flags.check = true;
    else if (a === "--live") flags.live = true;
    else if (a === "--yes") flags.yes = true;
    else if (a === "--stamp-offset") flags.stampOffset = Number(argv[++i]);
    else if (a.startsWith("--stamp-offset=")) flags.stampOffset = Number(a.split("=")[1]);
    else if (a.startsWith("--")) throw new Error(`unknown flag ${a}`);
    else pos.push(a);
  }
  if (!Number.isInteger(flags.stampOffset) || flags.stampOffset < 0 || flags.stampOffset > 3) throw new Error("--stamp-offset must be an integer 0..3");
  if (flags.broadcast && flags.check) throw new Error("use either --check or --broadcast, not both");
  return { cmd: pos[0], args: pos.slice(1), flags };
}
const USAGE = `usage: node smoke.mjs <command> [--check | --broadcast] [--stamp-offset N]
  keys                     generate owner + posting keys into .keys.json (prints the owner address only)
  plan                     resource math (no node needed)
  fund <boxId|txId>        record the funding box you sent to the owner address
  mint                     mint the three dummy tokens (3 chained txs)
  setup                    create the dummy oracle box and the authority box
  post                     THE TEST: posting-key-only post, fee from the authority box, no change output
  post-bad <variant>       negative control: early | change | overfee | oldkey (must be rejected)
  rotate                   owner key replaces the posting key (R6) in place
  reclaim <P2PK address>   owner takes the NFT, the ERG and every token that can leave
  status [--live]          recorded state (no secrets); --live asks the node for tx status
  undo --yes               forget the last recorded state change (only if that tx never made it on chain)
state-changing commands are DRY RUNS unless --broadcast is given; --check validates on the node without broadcasting.`;

export async function main(argv, { net, dir, print } = {}) {
  const out = print ?? ((l) => console.log(redact(l)));
  const p = (l) => out(redact(l));
  let parsed;
  try { parsed = parseArgs(argv); } catch (e) { p(`error: ${e.message}`); p(USAGE); return 2; }
  const { cmd, args, flags } = parsed;
  const stateDir = dir ?? process.env.SMOKE_DIR ?? HERE;
  const io = makeIO(stateDir, p);
  try {
    if (!cmd || cmd === "help") { p(USAGE); return cmd ? 0 : 2; }
    if (cmd === "plan") { await runPlan(p); return 0; }
    if (cmd === "keys") {
      if (io.keysExist()) { p(`refusing: ${io.keysPath} already exists (never overwritten)`); return 1; }
      const raw = { version: 1, network: "mainnet", note: "THROWAWAY keys for mainnet-smoke. Never reuse.", keys: { owner: { secret: newSecret() }, posting: { secret: newSecret() } } };
      for (const v of Object.values(raw.keys)) SECRETS.add(v.secret);
      io.createKeys(raw);
      const owner = keyFromSecret(raw.keys.owner.secret);
      const st = io.loadState();
      st.keys = { ownerAddress: owner.address, ownerPk: owner.pk, postingPk: keyFromSecret(raw.keys.posting.secret).pk };
      io.saveState(st);
      p(owner.address);
      return 0;
    }
    const S = { io, mode: flags.broadcast ? "broadcast" : flags.check ? "check" : "dry", stampOffset: flags.stampOffset, state: io.loadState() };
    S.keysRaw = io.keysExist() ? io.loadKeys() : null;
    S.K = S.keysRaw ? keyset(S) : {};
    if (cmd === "status") {
      if (flags.live) S.net = net ?? createNodeApi(process.env.NODE_URL);
      await stepStatus(S, flags.live); return 0;
    }
    if (cmd === "undo") {
      if (!flags.yes) { p("undo reverts the last recorded state change. Only do this if `status --live` shows that tx is neither in the mempool nor on chain. Rerun with --yes."); return 1; }
      const h = S.state.history ?? [];
      if (!h.length) { p("nothing to undo"); return 1; }
      const prev = h[h.length - 1];
      S.state = { ...prev, history: h.slice(0, -1) };
      io.saveState(S.state); p("reverted the last recorded state change"); return 0;
    }
    if (!S.keysRaw) throw new Error("no keys: run `keys` first");
    S.contracts = loadContracts();
    S.net = net ?? createNodeApi(process.env.NODE_URL);
    if (S.mode !== "dry") p(`mode: ${S.mode === "check" ? "CHECK (POST /transactions/check, no broadcast)" : "BROADCAST"}`);
    switch (cmd) {
      case "fund": if (!args[0]) throw new Error("usage: fund <boxId|txId>"); await stepFund(S, args[0]); return 0;
      case "mint": await stepMint(S); return 0;
      case "setup": await stepSetup(S); return 0;
      case "post": { const r = await stepPost(S); return r.tooEarly ? 3 : r.r?.rejected ? 1 : 0; }
      case "post-bad": { const r = await stepPostBad(S, args[0]); return r.outcome === "ACCEPTED(ALARM)" ? 1 : 0; }
      case "rotate": await stepRotate(S); return 0;
      case "reclaim": await stepReclaim(S, args[0]); return 0;
      default: p(`unknown command ${cmd}`); p(USAGE); return 2;
    }
  } catch (e) {
    p(`error: ${String(e?.message ?? e).split("\n")[0].slice(0, 400)}`);
    if (process.env.SMOKE_DEBUG) p(String(e?.stack ?? "").split("\n").slice(1, 8).join("\n"));
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (e) => { console.error(redact(`fatal: ${e?.message ?? e}`)); process.exit(1); });
}
