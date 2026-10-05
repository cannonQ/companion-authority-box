// Proof-lifting probe — offline, throwaway MockChain keys, two independent interpreters.
// No node, no wallet, no mainnet. Run: node lift.test.mjs   (writes ./lift.result)
//
// Claim under test (CompanionAuthorityHotKey.es): a sigma-protocol proof commits to the
// transaction bytes, so the hot key's proof from tx A cannot be lifted onto a different tx B.
//
// MockChain.execute() only reduces + signs; it never verifies a foreign proof. So here we
// SIGN with sigmastate-js (Scala interpreter, the same calls mock-chain uses) and keep the
// signed tx, then VERIFY each input with sigma-rust (ergo-lib-wasm-nodejs 0.28.0,
// verify_tx_input_proof). Every negative result is paired with a positive control on the
// same tx shape, same boxes and the same ErgoStateContext.
//
// Wave 2: the hot-key candidate only accepts SELF-FUNDED posts (INPUTS = [oracle, companion],
// OUTPUTS = [oracle', companion', miner fee], no change output). tx A and tx B are both built
// that way, on the SAME companion box, with different prices/epoch; the server key owns no box.
import { readFileSync, writeFileSync } from "fs";
import { compile } from "@fleet-sdk/compiler";
import { MockChain, mockUTxO, mockHeaders, BLOCKCHAIN_PARAMETERS } from "@fleet-sdk/mock-chain";
import { OutputBuilder, TransactionBuilder, ErgoUnsignedInput, RECOMMENDED_MIN_FEE_VALUE, FEE_CONTRACT } from "@fleet-sdk/core";
import { SInt, SLong, SColl, SByte, SGroupElement } from "@fleet-sdk/serializer";
import { blake2b256, hex, bigintBE } from "@fleet-sdk/crypto";
import { ProverBuilder$, GroupElement$, AvlTree$ } from "sigmastate-js/main";
import * as SR from "ergo-lib-wasm-nodejs";

const ORIGINALS = new URL("./reference/", import.meta.url);
const HASH_GATE_SRC = readFileSync(new URL("CompanionAuthorityContract.es", ORIGINALS), "utf-8");
const ORACLE_V2_SRC = readFileSync(new URL("OracleContractV2.es", ORIGINALS), "utf-8");
const HOT_KEY_SRC = readFileSync(new URL("./CompanionAuthorityHotKey.es", import.meta.url), "utf-8");
// The AUDITED (fixed) oracle contract: the hot-key world posts through it. The hash-gate contrast keeps the original
// OracleContractV2.es (the fixed oracle pins the hot-key authority script by hash, so the hash gate cannot drive it).
const ORACLE_V2_VALUEFIX_SRC = readFileSync(new URL("./OracleContractV2-valuefix.es", import.meta.url), "utf-8");

const EPOCH = 5;   // authority lock compile constant (probe.test.mjs EPOCH); was 30
const POST_FEE = 1_000_000n; // intended single-box post fee (probe.test.mjs POST_FEE); the contract cap is 2x it
const H0 = 1_000_000;
const ERG = 1_000_000_000n;
const fakeId = (b) => b.toString(16).padStart(2, "0").repeat(32);
const POOL_NFT = fakeId(0xa1), COMPANION_NFT = fakeId(0xa2), ORACLE_TOKEN = fakeId(0xa3), REWARD_TOKEN = fakeId(0xa4);
const PREIMAGE = hex.decode(fakeId(0x5e));
const bytes = (h) => SColl(SByte, typeof h === "string" ? hex.decode(h) : h);
const short = (s) => String(s).split("\n")[0].slice(0, 200);

// ───────────────────────────── result log ─────────────────────────────
const out = [];
const section = (t) => out.push(`\n== ${t} ==`);
const info = (t) => out.push(`      ${t}`);
// v: { kind: "true" | "false" | "throw", msg? }. want: true = must verify, false = must NOT verify.
function check(name, v, want) {
  const verified = v.kind === "true";
  const got = v.kind === "true" ? "VERIFIES (true)"
    : v.kind === "false" ? "DOES NOT VERIFY (returned false)"
    : `DOES NOT VERIFY (threw: ${v.msg})`;
  out.push(`${verified === want ? "PASS" : "FAIL"}  ${name}\n      want=${want ? "VERIFIES" : "DOES NOT VERIFY"}  got=${got}`);
}
// A harness step that must succeed for the following checks to mean anything.
function harness(name, fn) {
  try { const r = fn(); out.push(`PASS  ${name}`); return r; }
  catch (e) { out.push(`FAIL  ${name}\n      harness error: ${short(e.message || e)}`); return undefined; }
}

// ───────────────────────────── one shared context for both interpreters ─────────────────────────────
// 11 well-formed mock headers, newest first. Newest (height H0) becomes the pre-header, the other 10
// the last-headers. The hot-key script reads HEIGHT (= pre-header height H0) for its height window;
// both interpreters and every verification below use these same header values.
// mockHeaders' array order already satisfies sigmastate's chain check (headers[i].parentId ==
// headers[i+1].id, i.e. index 0 is the chain tip), but its heights/timestamps ascend with the index.
// Re-stamp heights and timestamps so index 0 is also the highest/latest (tip height = H0).
const T0 = Date.UTC(2026, 0, 1);
const HEADERS = mockHeaders(11).map((h, j) => ({ ...h, height: H0 - j, timestamp: T0 - j * 120_000 }));
for (let j = 0; j + 1 < HEADERS.length; j++) {
  if (HEADERS[j].parentId !== HEADERS[j + 1].id) throw new Error(`mock headers not linked tip-first at ${j}`);
}

function sigmastateContext() {
  const conv = HEADERS.map((h) => ({
    ...h,
    ADProofsRoot: h.adProofsRoot,
    stateRoot: AvlTree$.fromDigest(h.stateRoot),
    timestamp: BigInt(h.timestamp),
    nBits: BigInt(h.nBits),
    extensionRoot: h.extensionHash,
    minerPk: GroupElement$.fromPointHex(h.powSolutions.pk),
    powOnetimePk: GroupElement$.fromPointHex(h.powSolutions.w),
    powNonce: h.powSolutions.n,
    powDistance: BigInt(h.powSolutions.d),
  }));
  return { sigmaLastHeaders: conv.slice(1), previousStateDigest: conv[1].stateRoot.digest, sigmaPreHeader: conv[0] };
}

const SR_HEADERS = SR.BlockHeaders.from_json(HEADERS.slice(1));
const SR_CTX = new SR.ErgoStateContext(
  SR.PreHeader.from_block_header(SR.BlockHeader.from_json(JSON.stringify(HEADERS[0]))),
  SR_HEADERS,
  SR.Parameters.default_parameters());

// ───────────────────────────── world / tx builders (copied from probe.test.mjs) ─────────────────────────────
function world({ gate, oracleSrc = gate === "hash" ? ORACLE_V2_SRC : ORACLE_V2_VALUEFIX_SRC }) {
  const chain = new MockChain({ height: H0 });
  const owner = chain.newParty("owner-cold");
  const server = chain.newParty("server");       // hash gate: only pays fees. hotkey gate: its key IS the posting key
  const attacker = chain.newParty("attacker");
  // Hot-key gate: the server key owns NOTHING (self-funded posts). Hash gate: the server pays fees as in wave 1.
  for (const p of [owner, attacker, ...(gate === "hash" ? [server] : [])]) p.addBalance({ nanoergs: ERG });

  // Authority compiled FIRST: the fixed oracle takes blake2b256(authority tree) as authorityScriptHash, and names its
  // NFT constant authorityNftId (audit V-2); the original OracleContractV2.es keeps companionNftId and no hash.
  // The hot-key authority also takes poolNftId (its refresh-fee path needs the pool NFT at INPUTS(0)); same id as the oracle's.
  const companionTree = gate === "hash"
    ? compile(HASH_GATE_SRC, { map: { epochLength: SInt(EPOCH) } }).toHex()
    : compile(HOT_KEY_SRC, { map: { epochLength: SInt(EPOCH), poolNftId: bytes(POOL_NFT) } }).toHex();
  const omap = { poolNftId: bytes(POOL_NFT) };
  omap[oracleSrc.includes("authorityNftId") ? "authorityNftId" : "companionNftId"] = bytes(COMPANION_NFT);
  if (oracleSrc.includes("authorityScriptHash")) omap.authorityScriptHash = bytes(blake2b256(hex.decode(companionTree)));
  const oracleTree = compile(oracleSrc, { map: omap }).toHex();
  const oracleParty = chain.addParty(oracleTree, "oracle-script");
  const companionParty = chain.addParty(companionTree, "companion-script");

  oracleParty.addUTxOs(mockUTxO({
    ergoTree: oracleTree, value: ERG, creationHeight: H0 - 100,
    assets: [{ tokenId: ORACLE_TOKEN, amount: 1n }, { tokenId: REWARD_TOKEN, amount: 10n }],
    additionalRegisters: {
      R4: SGroupElement(owner.key.publicKey).toHex(), R5: SInt(7).toHex(), R6: SColl(SLong, [100n, 200n]).toHex(),
    },
  }));
  companionParty.addUTxOs(mockUTxO({
    ergoTree: companionTree, value: ERG / 10n, creationHeight: H0 - EPOCH,
    assets: [{ tokenId: COMPANION_NFT, amount: 1n }],
    additionalRegisters: {
      R4: SGroupElement(owner.key.publicKey).toHex(),
      R5: bytes(ORACLE_TOKEN).toHex(),
      R6: (gate === "hash" ? bytes(blake2b256(PREIMAGE)) : SGroupElement(server.key.publicKey)).toHex(),
      // hot-key gate: R7 = post stamp, R8 = fee stamp (Int), both one lock length back, so a post stamped H0 is allowed
      ...(gate === "hash" ? {} : { R7: SInt(H0 - EPOCH).toHex(), R8: SInt(H0 - EPOCH).toHex() }),
    },
  }));
  return { chain, owner, server, attacker, oracleTree, companionTree, oracleParty, companionParty, gate };
}

const oracleBox = (w) => w.oracleParty.utxos.toArray()[0];
const companionBox = (w) => w.companionParty.utxos.toArray()[0];

// Posting tx.
//   payer given (hash gate, wave-1 shape): INPUTS = [oracle, companion, payer boxes], OUTPUTS = [oracle', companion', change, fee].
//   no payer (hot-key gate, self-funded):  INPUTS = [oracle, companion],              OUTPUTS = [oracle', companion' (value - fee), fee].
function post(w, { payer, prices, epoch = 8, ext }) {
  const ob = oracleBox(w), cb = companionBox(w);
  const companionIn = new ErgoUnsignedInput(cb);
  if (ext) companionIn.setContextExtension(ext);
  const inputs = [new ErgoUnsignedInput(ob).setContextExtension({ 0: SInt(0) }), companionIn, ...(payer ? payer.utxos.toArray() : [])];
  const oracleOut = new OutputBuilder(ob.value, w.oracleTree)
    .addTokens(ob.assets)
    .setAdditionalRegisters({ R4: ob.additionalRegisters.R4, R5: SInt(epoch), R6: SColl(SLong, prices) });
  // Self-funded hot-key post pays the intended single-post fee (POST_FEE); the wallet-paid hash-gate post keeps Fleet's default.
  const fee = payer ? RECOMMENDED_MIN_FEE_VALUE : POST_FEE;
  // Hot-key successor: R7 := the post stamp (= the build height H0, the HEIGHT both interpreters see), R8 carried over.
  const stamps = cb.additionalRegisters.R7 === undefined ? {} : { R7: SInt(w.chain.height), R8: cb.additionalRegisters.R8 };
  const successor = new OutputBuilder(payer ? cb.value : cb.value - fee, w.companionTree)
    .addTokens(cb.assets)
    .setAdditionalRegisters({ R4: cb.additionalRegisters.R4, R5: cb.additionalRegisters.R5, R6: cb.additionalRegisters.R6, ...stamps });
  return new TransactionBuilder(w.chain.height)
    .from(inputs, { ensureInclusion: true })
    .to([oracleOut, successor])
    .sendChangeTo((payer ?? w.attacker).address) // self-funded: inputs == outputs + fee, so no change box is created
    .payFee(fee)
    .build();
}
const shapeOf = (w, eip12) => {
  const kind = (t) => t === w.oracleTree ? "oracle" : t === w.companionTree ? "companion" : t === FEE_CONTRACT ? "minerFee" : "OTHER";
  return `inputs=[${eip12.inputs.map((b) => kind(b.ergoTree))}] outputs=[${eip12.outputs.map((b) => kind(b.ergoTree))}]`;
};
const liftExtension = (tx) => tx.toEIP12Object().inputs[1].extension;
const preimageExt = (p = PREIMAGE) => ({ 0: bytes(p) });

// ───────────────────────────── sign (sigmastate-js) / verify (sigma-rust) ─────────────────────────────
// Same calls as mock-chain's execute(), but the SignedTransaction is returned instead of discarded.
function sign(unsignedTx, parties) {
  const eip12 = unsignedTx.toEIP12Object();
  const builder = ProverBuilder$.create(BLOCKCHAIN_PARAMETERS, 0 /* mainnet */);
  for (const p of parties) builder.withDLogSecret(bigintBE.encode(p.key.privateKey));
  const prover = builder.build();
  const reduced = prover.reduce(sigmastateContext(), eip12, eip12.inputs, eip12.dataInputs, [], 0);
  const signed = prover.signReduced(reduced);
  return { eip12, signed: JSON.parse(JSON.stringify(signed)) }; // plain JSON copy we can mutate safely
}

const jsonBig = (o) => JSON.parse(JSON.stringify(o, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
// boxes_to_spend for sigma-rust, in input order, from the unsigned tx (sigma-rust recomputes each boxId).
function srBoxes(eip12) {
  return SR.ErgoBoxes.from_boxes_json(jsonBig(eip12.inputs).map(({ extension: _x, ...box }) => box));
}
function srTx(signedJson) {
  const tx = SR.Transaction.from_json(JSON.stringify(signedJson));
  const rid = tx.id().to_str();
  if (rid !== signedJson.id) throw new Error(`sigma-rust tx id ${rid} != sigmastate tx id ${signedJson.id}`);
  return tx;
}
function verify(idx, signedJson, eip12) {
  try {
    const ok = SR.verify_tx_input_proof(idx, SR_CTX, srTx(signedJson), srBoxes(eip12), SR.ErgoBoxes.from_boxes_json([]));
    return { kind: ok === true ? "true" : "false" };
  } catch (e) {
    return { kind: "throw", msg: short(e?.message ?? e) };
  }
}
function withProof(signedJson, idx, proofBytes) {
  const c = structuredClone(signedJson);
  c.inputs[idx].spendingProof.proofBytes = proofBytes;
  return c;
}
const proofOf = (s, i) => s.inputs[i].spendingProof.proofBytes;
const proofLen = (p) => `${p.length / 2} bytes`;

const treeHash = (t) => hex.encode(blake2b256(hex.decode(t))).slice(0, 16);

// ───────────────────────────── Hot-key gate (candidate) ─────────────────────────────
section("HOT-KEY gate (candidate CompanionAuthorityHotKey.es) — sign: sigmastate-js, verify: sigma-rust");
{
  const w = world({ gate: "hotkey" });
  info(`companion ergoTree blake2b256[0..8]=${treeHash(w.companionTree)} (${w.companionTree.length / 2} bytes); companion boxId=${companionBox(w).boxId.slice(0, 16)}..`);
  info(`oracle = FIXED OracleContractV2-valuefix.es, ergoTree ${w.oracleTree.length / 2} bytes, blake2b256[0..8]=${treeHash(w.oracleTree)}`);

  // tx A: the server (holder of the hot key) posts [101, 201], self-funded (fee out of the companion).
  const A = harness("setup: sign tx A (self-funded, hot key posts [101,201], epoch 8)",
    () => sign(post(w, { prices: [101n, 201n], epoch: 8 }), [w.server]));
  // tx B: same oracle + companion boxes, self-funded, different prices/epoch; genuinely signed by the hot key.
  const B = harness("setup: sign tx B (self-funded, same boxes, prices [999999,1], epoch 12345, hot key)",
    () => sign(post(w, { prices: [999999n, 1n], epoch: 12345 }), [w.server]));

  if (A && B) {
    info(`tx A id=${A.signed.id}`);
    info(`tx B id=${B.signed.id}`);
    info(`tx A ${shapeOf(w, A.eip12)}; tx B ${shapeOf(w, B.eip12)}; server-key UTxOs=${w.server.utxos.toArray().length}`);
    info(`A.inputs[1] (companion) boxId=${A.signed.inputs[1].boxId.slice(0, 16)}..  B.inputs[1] boxId=${B.signed.inputs[1].boxId.slice(0, 16)}..  same box: ${A.signed.inputs[1].boxId === B.signed.inputs[1].boxId}`);
    info(`A companion proof ${proofLen(proofOf(A.signed, 1))}, B companion proof ${proofLen(proofOf(B.signed, 1))}, identical: ${proofOf(A.signed, 1) === proofOf(B.signed, 1)}`);

    check("L1 control: tx A, companion input [1] verifies", verify(1, A.signed, A.eip12), true);
    for (let i = 0; i < A.signed.inputs.length; i++) {
      if (i === 1) continue;
      check(`L1 control: tx A, input [${i}] (${i === 0 ? "oracle" : "extra input"}) verifies`, verify(i, A.signed, A.eip12), true);
    }
    try { SR.validate_tx(srTx(A.signed), SR_CTX, srBoxes(A.eip12), SR.ErgoBoxes.from_boxes_json([])); info("info: sigma-rust validate_tx(tx A) — full stateless+stateful validation: OK"); }
    catch (e) { info(`info: sigma-rust validate_tx(tx A) error: ${short(e?.message ?? e)}`); }

    check("L2 control: tx B (hot key signed), companion input [1] verifies", verify(1, B.signed, B.eip12), true);
    for (let i = 0; i < B.signed.inputs.length; i++) {
      if (i === 1) continue;
      check(`L2 control: tx B, input [${i}] (${i === 0 ? "oracle" : "extra input"}) verifies`, verify(i, B.signed, B.eip12), true);
    }
    try { SR.validate_tx(srTx(B.signed), SR_CTX, srBoxes(B.eip12), SR.ErgoBoxes.from_boxes_json([])); info("info: sigma-rust validate_tx(tx B) — full stateless+stateful validation: OK"); }
    catch (e) { info(`info: sigma-rust validate_tx(tx B) error: ${short(e?.message ?? e)}`); }

    // Harness control for the mutation path itself: identical code path, B's OWN proof written back.
    check("L3 harness control: tx B passed through the proof-swap code path with its OWN companion proof verifies",
      verify(1, withProof(B.signed, 1, proofOf(B.signed, 1)), B.eip12), true);

    // THE TEST: B with only the companion proofBytes replaced by A's.
    const lifted = withProof(B.signed, 1, proofOf(A.signed, 1));
    const reparsedId = harness("L3 setup: proof-swapped tx B still parses in sigma-rust with an unchanged tx id",
      () => { const t = srTx(lifted); if (t.id().to_str() !== B.signed.id) throw new Error("id changed"); return t.id().to_str(); });
    if (reparsedId) info(`swapped tx id=${reparsedId} (== tx B id)`);
    check("L3 THE TEST: tx B with companion proof lifted from tx A — companion input [1]", verify(1, lifted, B.eip12), false);
    // (wave 1 used the attacker's P2PK fee input [2] here; self-funded txs have no such input, so the untouched
    // oracle input [0] — whose script sigma-rust evaluates against this same tx and context — plays that role.)
    check("L3 side: in that same swapped tx the untouched oracle input [0] still verifies (tx is otherwise intact)",
      verify(0, lifted, B.eip12), true);
    check("L3 converse: tx A with companion proof lifted from tx B — companion input [1]",
      verify(1, withProof(A.signed, 1, proofOf(B.signed, 1)), A.eip12), false);

    check("L4: tx B with an EMPTY proof on the companion input [1]", verify(1, withProof(B.signed, 1, ""), B.eip12), false);
  }
}

// ───────────────────────────── Hash gate (current) ─────────────────────────────
section("HASH gate (current CompanionAuthorityContract.es) — contrast");
{
  const w = world({ gate: "hash" });
  info(`companion ergoTree blake2b256[0..8]=${treeHash(w.companionTree)}; oracle = ORIGINAL OracleContractV2.es (contrast only)`);
  // The operator's pending tx is only BUILT (what a mempool observer sees), never signed or mined here.
  const victimTx = post(w, { payer: w.server, prices: [101n, 201n], epoch: 8, ext: preimageExt() });
  const lifted = liftExtension(victimTx);
  info(`preimage lifted from the operator's pending tx extension: ${lifted[0] === preimageExt()[0].toHex() ? "matches the secret" : "MISMATCH"}`);
  const X = harness("setup: sign the attacker's tx (lifted preimage, prices [999999,1], epoch 12345) with the ATTACKER key only",
    () => sign(post(w, { payer: w.attacker, prices: [999999n, 1n], epoch: 12345, ext: lifted }), [w.attacker]));
  if (X) {
    info(`attacker tx id=${X.signed.id}; companion proof ${proofLen(proofOf(X.signed, 1))} (empty = script reduced to true, no signature involved)`);
    check("L5: attacker tx, companion input [1] verifies on sigma-rust (vulnerability cross-confirmed)", verify(1, X.signed, X.eip12), true);
    check("L5: attacker tx, oracle input [0] verifies on sigma-rust", verify(0, X.signed, X.eip12), true);
    for (let i = 2; i < X.signed.inputs.length; i++) check(`L5: attacker tx, attacker fee input [${i}] verifies`, verify(i, X.signed, X.eip12), true);
    try { SR.validate_tx(srTx(X.signed), SR_CTX, srBoxes(X.eip12), SR.ErgoBoxes.from_boxes_json([])); info("info: sigma-rust validate_tx(attacker tx) — full validation: OK"); }
    catch (e) { info(`info: sigma-rust validate_tx(attacker tx) error: ${short(e?.message ?? e)}`); }
  }
}

const passed = out.filter((l) => l.startsWith("PASS")).length;
const total = out.filter((l) => l.startsWith("PASS") || l.startsWith("FAIL")).length;
const text = `SUMMARY ${passed}/${total} checks matched expectation\n` + out.join("\n") + "\n";
writeFileSync(new URL("./lift.result", import.meta.url), text);
console.log(text);
