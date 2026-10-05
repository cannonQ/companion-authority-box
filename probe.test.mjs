// Companion Authority probe — offline MockChain, throwaway keys, real sigmastate.
// No node, no wallet, no mainnet. Run: npm test
//
// Part A reproduces the replay Kushti described against the CURRENT contract
// (hash preimage gate). Part B runs the same attacks against the hot-key
// candidate in ./CompanionAuthorityHotKey.es, plus owner-path liveness and
// stolen-hot-key attacks through the oracle contract's companion path.
//
// Wave 2: the candidate's baseline post is SELF-FUNDED — INPUTS = [oracle,
// companion], OUTPUTS = [oracle', companion', miner fee] — and the server party
// owns no box at all in every hot-key world. Every part-B attack also lands in
// the THIEF LEDGER at the end (ERG + token delta of everything the thief holds).
//
// Section F runs the refresh-fee path (context var 1 = 1): the posting key pays a refresh's miner fee out of the
// authority box, rate-limited on the R8 fee stamp; posts are rate-limited on the R7 post stamp (no creation-height lock).
//
// Every check states its expected outcome up front. "FINDING" = an attack that
// is ACCEPTED (expected so); "KNOWN LIMIT" = a documented rejection of
// something an operator might want to do.
import { readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { compile } from "@fleet-sdk/compiler";
import { MockChain, mockUTxO, mockBlockchainStateContext, BLOCKCHAIN_PARAMETERS } from "@fleet-sdk/mock-chain";
import { ProverBuilder$ } from "sigmastate-js/main";
import { OutputBuilder, TransactionBuilder, ErgoUnsignedInput, RECOMMENDED_MIN_FEE_VALUE, SAFE_MIN_BOX_VALUE, FEE_CONTRACT } from "@fleet-sdk/core";
import { SInt, SLong, SColl, SByte, SGroupElement, decode } from "@fleet-sdk/serializer";
import { blake2b256, hex } from "@fleet-sdk/crypto";

const ORIGINALS = new URL("./reference/", import.meta.url);
const HASH_GATE_SRC = readFileSync(new URL("CompanionAuthorityContract.es", ORIGINALS), "utf-8");
const ORACLE_V2_SRC = readFileSync(new URL("OracleContractV2.es", ORIGINALS), "utf-8");
const HOT_KEY_SRC = readFileSync(new URL("./CompanionAuthorityHotKey.es", import.meta.url), "utf-8");
// The AUDITED (fixed) oracle contract: F-1/F-3/F-4/F-6/V-2 applied, new compile constants authorityNftId + authorityScriptHash.
const ORACLE_V2_VALUEFIX_SRC = readFileSync(new URL("./OracleContractV2-valuefix.es", import.meta.url), "utf-8");
// Byte-for-byte snapshot of the version that ran on mainnet on 2026-10-03 (before the two-pass audit).
const ORACLE_V2_VALUEFIX_PRE_SRC = readFileSync(new URL("./OracleContractV2-valuefix.pre-audit.es", import.meta.url), "utf-8");
// Pre-audit authority snapshot (no `epochLength > mempoolSlack` guard). Used ONLY by the pre-audit contrast rows (R2/D2
// pre-audit controls, T6c), always paired with ORACLE_V2_VALUEFIX_PRE_SRC.
const HOT_KEY_PRE_SRC = readFileSync(new URL("./CompanionAuthorityHotKey.pre-audit.es", import.meta.url), "utf-8");
const md5 = (s) => createHash("md5").update(s).digest("hex");

const out = [];
function check(name, got, want) {
  const accepted = got.startsWith("ACCEPTED");
  out.push(`${accepted === want ? "PASS" : "FAIL"}  ${name}\n      want=${want ? "ACCEPTED" : "REJECTED"}  got=${got}`);
}
const section = (t) => out.push(`\n== ${t} ==`);
const info = (t) => out.push(`      ${t}`);

// ── Drift guard: the PRE-AUDIT snapshot (OracleContractV2-valuefix.pre-audit.es, md5 1cb85f6a...) must be the original
// plus exactly one conjunct in companionSafe. The FIXED file deliberately differs (audit P3-P8); its md5 is printed.
const VALUE_FIX_ANCHOR = "output.tokens(1)._2 >= SELF.tokens(1)._2";
const VALUE_FIX_ADDITION = " &&\n                      output.value >= SELF.value";
{
  section("V. OracleContractV2-valuefix drift guard (pre-audit snapshot vs original; fixed file md5 printed)");
  const anchors = ORACLE_V2_SRC.split(VALUE_FIX_ANCHOR).length - 1;
  const expected = ORACLE_V2_SRC.replace(VALUE_FIX_ANCHOR, VALUE_FIX_ANCHOR + VALUE_FIX_ADDITION);
  const a = ORACLE_V2_SRC.split("\n"), b = ORACLE_V2_VALUEFIX_PRE_SRC.split("\n");
  let pre = 0; while (pre < a.length && a[pre] === b[pre]) pre++;
  let suf = 0; while (suf < a.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const changed = [...a.slice(pre, a.length - suf).map((l) => `-${pre + 1}:${JSON.stringify(l.trim())}`),
                   ...b.slice(pre, b.length - suf).map((l, i) => `+${pre + 1 + i}:${JSON.stringify(l.trim())}`)];
  const PRE_MD5 = "1cb85f6ad24b66243e4a4a9c3296ba6f";
  const ok = anchors === 1 && ORACLE_V2_VALUEFIX_PRE_SRC === expected && md5(ORACLE_V2_VALUEFIX_PRE_SRC) === PRE_MD5;
  out.push(`${ok ? "PASS" : "FAIL"}  V1 pre-audit snapshot == original with ONE added conjunct \`output.value >= SELF.value\` in companionSafe, md5 ${PRE_MD5}\n` +
    `      anchors-in-original=${anchors}  lines(original/pre-audit)=${a.length}/${b.length}  snapshot md5=${md5(ORACLE_V2_VALUEFIX_PRE_SRC)}  diff: ${changed.join("  ")}`);
  out.push(`      FIXED OracleContractV2-valuefix.es md5=${md5(ORACLE_V2_VALUEFIX_SRC)} (${ORACLE_V2_VALUEFIX_SRC.split("\n").length} lines); ` +
    `CompanionAuthorityHotKey.es md5=${md5(HOT_KEY_SRC)}; the fixed oracle is NOT drift-guarded against the original (the audit changes it by design)`);
  if (!ok) { console.log(out.join("\n")); throw new Error("OracleContractV2-valuefix.pre-audit.es drifted from the original + one conjunct"); }
}

// Authority height lock = the contract's compile constant `epochLength`. Chosen 5, one block below the pool's epoch
// (POOL_EPOCH = 6: AutoDaemon.scala:32, DaemonConfig.scala:49, RefreshTxBuilder.scala:111-118). Section T shows why.
const EPOCH = 5;
const POOL_EPOCH = 6;
const H0 = 1_000_000;
const ERG = 1_000_000_000n;
const MIN_RENT = 10_000_000n;
const MAX_FEE_PER_EPOCH = 2_000_000n; // = the contract's maxFeePerEpoch (drift-guarded below) = 2 x POST_FEE; was 3000000 (raised daemon post fee)
// Intended fee an honest single-box post pays (operator, 2026-10-03: ~0.0015 ERG per ~4 KB oracle tx is enough; the
// raised daemon fees are not needed). Every honest post below pays this; the cap is 2x it. Wallet-paid owner txs keep
// Fleet's RECOMMENDED_MIN_FEE_VALUE (not capped by the contract).
const POST_FEE = 1_000_000n;
const fakeId = (b) => b.toString(16).padStart(2, "0").repeat(32);
const POOL_NFT = fakeId(0xa1), COMPANION_NFT = fakeId(0xa2), ORACLE_TOKEN = fakeId(0xa3), REWARD_TOKEN = fakeId(0xa4);
const COMPANION_NFT_2 = fakeId(0xb2), ORACLE_TOKEN_2 = fakeId(0xb3), ORACLE_TOKEN_3 = fakeId(0xc3);
const EXTRA_TOKEN = fakeId(0xe1), WALLET_TOKEN = fakeId(0xe2);
const PREIMAGE = hex.decode(fakeId(0x5e));
const bytes = (h) => SColl(SByte, typeof h === "string" ? hex.decode(h) : h);

function run(w, tx, signers) {
  try { w.chain.execute(tx, { signers, throw: true }); return "ACCEPTED"; }
  catch (e) { return "REJECTED: " + String(e.message || e).split("\n")[0].slice(0, 160); }
}

// The fixed oracle names its NFT constant `authorityNftId` (audit V-2) and pins the authority script by hash (audit F-01/F-3):
// `authorityScriptHash` = blake2b256 of the authority tree that world actually uses (compiled FIRST). Older sources keep
// `companionNftId` and take no hash.
const compileOracle = (src, nftId, authTree = HOT_KEY_TREE) => {
  const map = { poolNftId: bytes(POOL_NFT) };
  map[src.includes("authorityNftId") ? "authorityNftId" : "companionNftId"] = bytes(nftId);
  if (src.includes("authorityScriptHash")) map.authorityScriptHash = bytes(blake2b256(hex.decode(authTree)));
  return compile(src, { map }).toHex();
};
// The authority contract takes two compile constants: epochLength (Int) and poolNftId (Coll[Byte], the pool box's NFT;
// the refresh-fee path needs it at INPUTS(0)). Every authority tree in this suite is compiled with the suite's POOL_NFT.
const authMap = (E) => ({ epochLength: SInt(E), poolNftId: bytes(POOL_NFT) });
const authTreeOf = (src, E = EPOCH) => compile(src, { map: authMap(E) }).toHex();
const compileCompanion = (gate) => gate === "hash" ? compile(HASH_GATE_SRC, { map: { epochLength: SInt(EPOCH) } }).toHex() : authTreeOf(HOT_KEY_SRC);
const HOT_KEY_TREE = compileCompanion("hotkey");
// Pool stand-in (TEST-ONLY). No refresh or update contract is executed in this suite. This script holds the pool NFT and
// lets any tx spend it while it sits at INPUTS(0) and is recreated at OUTPUTS(0) with its NFT, script and value; the
// reward tokens it hands to collected oracle boxes may leave. It is what "a refresh-shaped tx" means below.
const POOL_STANDIN_SRC = `{
  sigmaProp(INPUTS(0).id == SELF.id && OUTPUTS(0).propositionBytes == SELF.propositionBytes &&
            OUTPUTS(0).tokens(0)._1 == SELF.tokens(0)._1 && OUTPUTS(0).value >= SELF.value)
}`;
const POOL_TREE = compile(POOL_STANDIN_SRC).toHex();
function addPool(chain) {
  const p = chain.addParty(POOL_TREE, "pool-standin");
  p.addUTxOs(mockUTxO({ ergoTree: POOL_TREE, value: ERG, creationHeight: H0 - 10,
    assets: [{ tokenId: POOL_NFT, amount: 1n }, { tokenId: REWARD_TOKEN, amount: 1000n }] }));
  return p;
}
const preAuthTreeFor = (E) => compile(HOT_KEY_PRE_SRC, { map: { epochLength: SInt(E) } }).toHex();

// gate: "hash" (current contract) | "hotkey" (candidate)
//   companionHeight / oracleHeight: creation heights of the two script boxes
//   fundHeight: if set, parties are funded with boxes created at that height (else at H0)
//   companionExtraAssets: tokens on the companion box after the NFT
//   second: add oracle Y (own script, bound to COMPANION_NFT_2, owner2) + companion B (NFT_2, hot key = server2)
//   twinOracle: add a second oracle box on the SAME oracle script as X (same companion NFT), token ORACLE_TOKEN_3
//   fundServer: give the server (and rotated server) key a wallet box. Default: only for the hash gate, so in every
//               hot-key world the hot key owns NOTHING (the "no wallet on the server" requirement).
//   postStamp / feeStamp: the hot-key box's R7 (post stamp) / R8 (fee stamp), both Int. Default = companionHeight, so
//               every row that set a creation height for the old creation-height lock now sets the same stamp.
//   stampRegs: override { R7, R8 } of the hot-key box ("none" = no R7/R8 at all, the pre-stamp box layout)
//   pool: add a pool box (POOL_NFT at tokens(0)) at the pool stand-in script, for refresh-shaped txs
function world({ gate, oracleSrc = ORACLE_V2_SRC, companionHeight = H0 - EPOCH, oracleHeight = H0 - 100,
                 fundHeight, companionExtraAssets = [], second = false, twinOracle = false, fundServer = gate === "hash", companionTreeOverride, companionValue = ERG / 10n,
                 postStamp = companionHeight, feeStamp = companionHeight, stampRegs, pool = false }) {
  const chain = new MockChain({ height: H0 });
  const owner = chain.newParty("owner-cold");
  const owner2 = chain.newParty("owner2-cold");
  const server = chain.newParty("server");       // hash gate: only pays fees. hotkey gate: its key IS the posting key
  const server2 = chain.newParty("server-rotated");
  const attacker = chain.newParty("attacker");
  for (const p of [owner, owner2, attacker, ...(fundServer ? [server, server2] : [])]) {
    if (fundHeight === undefined) p.addBalance({ nanoergs: ERG });
    else p.addUTxOs(mockUTxO({ ergoTree: p.ergoTree, value: ERG, creationHeight: fundHeight }));
  }

  const companionTree = companionTreeOverride ?? compileCompanion(gate);   // compiled FIRST: the fixed oracle pins its hash
  const oracleTree = compileOracle(oracleSrc, COMPANION_NFT, companionTree);
  const oracleParty = chain.addParty(oracleTree, "oracle-script");
  const companionParty = chain.addParty(companionTree, "companion-script");
  const oracleBoxOf = (tree, token, ownerKey) => mockUTxO({
    ergoTree: tree, value: ERG, creationHeight: oracleHeight,
    assets: [{ tokenId: token, amount: 1n }, { tokenId: REWARD_TOKEN, amount: 10n }],
    additionalRegisters: { R4: SGroupElement(ownerKey).toHex(), R5: SInt(7).toHex(), R6: SColl(SLong, [100n, 200n]).toHex() },
  });
  const stamps = gate === "hash" || stampRegs === "none" ? {}
    : stampRegs ?? { R7: SInt(postStamp).toHex(), R8: SInt(feeStamp).toHex() };
  const companionBoxOf = (nft, token, hot, extra = []) => mockUTxO({
    ergoTree: companionTree, value: companionValue, creationHeight: companionHeight,
    assets: [{ tokenId: nft, amount: 1n }, ...extra],
    additionalRegisters: {
      R4: SGroupElement(owner.key.publicKey).toHex(),
      R5: bytes(token).toHex(),
      R6: (gate === "hash" ? bytes(blake2b256(PREIMAGE)) : SGroupElement(hot)).toHex(),
      ...stamps,
    },
  });

  oracleParty.addUTxOs(oracleBoxOf(oracleTree, ORACLE_TOKEN, owner.key.publicKey));
  companionParty.addUTxOs(companionBoxOf(COMPANION_NFT, ORACLE_TOKEN, server.key.publicKey, companionExtraAssets));
  const oracleParties = [oracleParty];
  let oracleTreeY;
  if (second) {
    oracleTreeY = compileOracle(oracleSrc, COMPANION_NFT_2, companionTree);
    const p = chain.addParty(oracleTreeY, "oracle-Y-script");
    p.addUTxOs(oracleBoxOf(oracleTreeY, ORACLE_TOKEN_2, owner2.key.publicKey));
    oracleParties.push(p);
    companionParty.addUTxOs(companionBoxOf(COMPANION_NFT_2, ORACLE_TOKEN_2, server2.key.publicKey));
  }
  if (twinOracle) oracleParty.addUTxOs(oracleBoxOf(oracleTree, ORACLE_TOKEN_3, owner.key.publicKey));
  const poolParty = pool ? addPool(chain) : undefined;
  return { chain, owner, owner2, server, server2, attacker, oracleTree, oracleTreeY, companionTree, oracleParty, oracleParties, companionParty, gate, poolParty };
}

const oracleBox = (w, token = ORACLE_TOKEN) =>
  w.oracleParties.flatMap((p) => p.utxos.toArray()).find((b) => b.assets[0]?.tokenId === token);
const companionBox = (w, nft = COMPANION_NFT) => w.companionParty.utxos.toArray().find((b) => b.assets[0]?.tokenId === nft);

// Oracle input with its output-index context var; oracle output that copies the box with new R5/R6.
const oracleIn = (ob, outIndex) => new ErgoUnsignedInput(ob).setContextExtension({ 0: SInt(outIndex) });
function oracleOut(ob, { prices = [101n, 201n], epoch = 8, value, assets, r4, tree } = {}) {
  const o = new OutputBuilder(value ?? ob.value, tree ?? ob.ergoTree).addTokens(assets ?? ob.assets);
  if (r4 !== "omit") o.setAdditionalRegisters({ R4: r4 ?? ob.additionalRegisters.R4, R5: SInt(epoch), R6: SColl(SLong, prices) });
  return o;
}
// Faithful successor of a companion box (overrides per field), shaped as a POST successor by default: on a box that
// carries stamps, R7 := the post stamp (`stamp`, default = the successor's creation height = the build height, which is
// what the old creation-height lock read) and R8 is carried over. r7 / r8 / r9 override; r9 is unpinned junk space.
function successorOf(w, cb, { value, assets, r4, r5, r6, r7, r8, r9, height, stamp } = {}) {
  const hasStamps = cb.additionalRegisters.R7 !== undefined;
  const regs = {
    R4: r4 ?? cb.additionalRegisters.R4, R5: r5 ?? cb.additionalRegisters.R5, R6: r6 ?? cb.additionalRegisters.R6,
    R7: r7 ?? (hasStamps ? SInt(stamp ?? height ?? w.chain.height) : undefined),
    R8: r8 ?? cb.additionalRegisters.R8, R9: r9,
  };
  for (const k of Object.keys(regs)) if (regs[k] === undefined) delete regs[k];
  const s = new OutputBuilder(value ?? cb.value, w.companionTree).addTokens(assets ?? cb.assets).setAdditionalRegisters(regs);
  if (height !== undefined) s.setCreationHeight(height);
  return s;
}
// Int value of a stamp register (R7 / R8) of a box.
const stampOf = (b, r) => Number(decode(b.additionalRegisters[r]).data);
function build(w, { inputs, outputs, payer, height = w.chain.height }) {
  return new TransactionBuilder(height)
    .from(inputs, { ensureInclusion: true })
    .to(outputs)
    .sendChangeTo(payer.address)
    .payFee(RECOMMENDED_MIN_FEE_VALUE)
    .build();
}

// Posting tx: INPUTS = [oracle, companion, fee...], OUTPUTS = [oracle', companion', (change), fee].
// `ext` is the companion input's context extension (the preimage, for the hash gate).
function post(w, { payer, prices, epoch = 8, ext, oracleValue, succR6, succR4, succValue, succAssets, succR7,
                   oracleAssets, oracleR4, oracleTree, outIndex, withOracle = true, succFirst = false, height }) {
  const ob = oracleBox(w), cb = companionBox(w);
  const companionIn = new ErgoUnsignedInput(cb);
  if (ext) companionIn.setContextExtension(ext);
  const succ = successorOf(w, cb, { value: succValue, assets: succAssets, r4: succR4, r6: succR6, r7: succR7, stamp: height });
  if (!withOracle) return build(w, { inputs: [companionIn, ...payer.utxos.toArray()], outputs: [succ], payer, height });
  const oOut = oracleOut(ob, { prices, epoch, value: oracleValue, assets: oracleAssets, r4: oracleR4, tree: oracleTree });
  const outputs = succFirst ? [succ, oOut] : [oOut, succ];
  return build(w, {
    inputs: [oracleIn(ob, outIndex ?? (succFirst ? 1 : 0)), companionIn, ...payer.utxos.toArray()], outputs, payer, height,
  });
}

// Owner path: spends ONLY the companion box (+ owner fee box). mode: rotate | reclaim | burn | custom
function ownerTx(w, { mode, newR6, outputs, cb = companionBox(w), payer = w.owner }) {
  const b = new TransactionBuilder(w.chain.height)
    .from([new ErgoUnsignedInput(cb), ...payer.utxos.toArray()], { ensureInclusion: true })
    .sendChangeTo(payer.address)
    .payFee(RECOMMENDED_MIN_FEE_VALUE);
  if (mode === "rotate") {
    // carries R7/R8 when the box has them (an owner rotate does not move the stamps)
    const { R7, R8 } = cb.additionalRegisters;
    b.to(new OutputBuilder(cb.value, w.companionTree).addTokens(cb.assets).setAdditionalRegisters({
      R4: cb.additionalRegisters.R4, R5: cb.additionalRegisters.R5, R6: newR6, ...(R7 !== undefined ? { R7 } : {}), ...(R8 !== undefined ? { R8 } : {}),
    }));
  } else if (mode === "reclaim") {
    b.to(new OutputBuilder(cb.value, w.owner.address).addTokens(cb.assets)); // NFT back to the cold wallet
  } else if (mode === "burn") {
    b.burnTokens({ tokenId: COMPANION_NFT, amount: 1n });
  } else if (mode === "custom") {
    b.to(outputs(cb));
  }
  return b.build();
}

// What a mempool observer sees: the companion input's context extension of an unsigned/broadcast tx.
const liftExtension = (tx) => tx.toEIP12Object().inputs[1].extension;
const preimageExt = (p = PREIMAGE) => ({ 0: bytes(p) });
const tokenAmount = (party, tokenId) => party.balance.tokens.find((t) => t.tokenId === tokenId)?.amount ?? 0n;

// ── Thief ledger. "Thief" = every non-owner key in the world: the (stolen) server hot key, the rotated server key, and
// the attacker's own wallet (the thief's address of choice for change / skims). Miner-fee boxes are NOT counted as
// thief holdings: a thief who also mines the block collects the fee — that is the bounded residual, reported per tx.
const ledger = [];
const thieves = (w) => [w.server, w.server2, w.attacker];
function holdings(w) {
  let erg = 0n; const tok = {};
  for (const p of thieves(w)) {
    erg += p.balance.nanoergs;
    for (const t of p.balance.tokens) tok[t.tokenId] = (tok[t.tokenId] ?? 0n) + t.amount;
  }
  return { erg, tok };
}
const sumFee = (txs) => txs.flatMap((t) => t.toEIP12Object().outputs).filter((b) => b.ergoTree === FEE_CONTRACT)
  .reduce((s, b) => s + BigInt(b.value), 0n);
function record(name, before, after, got, txs, { expectGain = false } = {}) {
  const dTok = {};
  for (const id of new Set([...Object.keys(before.tok), ...Object.keys(after.tok)])) {
    const d = (after.tok[id] ?? 0n) - (before.tok[id] ?? 0n);
    if (d !== 0n) dTok[id] = d;
  }
  const list = Array.isArray(txs) ? txs : [txs];
  ledger.push({ name, got, dErg: after.erg - before.erg, dTok, fee: got.startsWith("ACCEPTED") ? sumFee(list) : 0n, expectGain });
}
// Attribution for a rejection: reduce the tx with sigmastate (same context MockChain.execute builds, no secrets) and
// print what EACH input's script reduced to, keys named. "ProveDlog(owner)" alone = that input's non-owner paths are
// FALSE; "COR(hotKey, owner)" = posting conditions TRUE, only a signature missing; "TrivialProp(true)" = satisfied.
function why(w, tx) {
  const eip = tx.toEIP12Object();
  const names = new Map([["owner", w.owner], ["owner2", w.owner2], ["server", w.server], ["server2", w.server2], ["attacker", w.attacker],
                         ...(w.hot ?? []).map((p, i) => [`hot${i}`, p]).filter(([, p]) => p !== w.server)]
    .map(([n, p]) => [hex.encode(p.key.publicKey).slice(2), n]));
  const sum = (boxes) => boxes.flatMap((b) => b.assets).reduce((m, t) => ({ ...m, [t.tokenId]: (m[t.tokenId] ?? 0n) + BigInt(t.amount) }), {});
  const tin = sum(eip.inputs), tout = sum(eip.outputs);
  const burn = Object.entries(tin).filter(([id, a]) => a > (tout[id] ?? 0n)).map(([tokenId, a]) => ({ tokenId, amount: String(a - (tout[tokenId] ?? 0n)) }));
  let reduced;
  try {
    const ctx = mockBlockchainStateContext({ headers: { quantity: 10, fromHeight: w.chain.height, fromTimestamp: w.chain.timestamp } });
    reduced = ProverBuilder$.create(BLOCKCHAIN_PARAMETERS, 0).build().reduce(ctx, eip, eip.inputs, eip.dataInputs, burn, 0);
  } catch (e) { return `reduce threw: ${String(e.message || e).split("\n")[0].slice(0, 100)}`; }
  const arr = reduced._tx.Lorg_ergoplatform_sdk_ReducedTransaction__f_ergoTx.Lorg_ergoplatform_sdk_ReducedErgoLikeTransaction__f_reducedInputs.sci_ArraySeq$ofRef__f_unsafeArray;
  const items = arr.u ?? arr;
  return Array.from(items).map((ri, i) => {
    const v = ri.Lorg_ergoplatform_sdk_ReducedInputData__f_reductionResult.Lsigmastate_interpreter_Interpreter$ReductionResult__f_value;
    let str = String(v);
    const walk = (o, d = 0) => {
      if (!o || typeof o !== "object" || d > 12) return;
      if (o.Lsigma_crypto_Platform$Ecp__f_point) {
        const x = o.Lsigma_crypto_Platform$Ecp__f_point.x.toString(16).padStart(64, "0");
        str = str.split(String(o)).join(names.get(x) ?? "?key");
        return;
      }
      for (const k of Object.keys(o)) walk(o[k], d + 1);
    };
    walk(v);
    return `in${i} ${kindOf(w, eip.inputs[i].ergoTree)}=${str.replace(/ProveDlog\((\w+)\)/g, "$1").replace(/List\(|\)\)/g, (m) => (m === "List(" ? "" : ")"))}`;
  }).join(" | ");
}
// A part-B attack: run it, check the outcome, record the thief's balance delta; on rejection print the attribution.
function attack(w, name, tx, signers, want) {
  const before = holdings(w);
  const reason = why(w, tx);
  const got = run(w, tx, signers);
  check(name, got, want);
  if (!got.startsWith("ACCEPTED")) out.push(`      reduced: ${reason}`);
  record(name, before, holdings(w), got, tx);
  return got;
}
// Same, for a non-attack check whose rejection needs attributing (no ledger entry).
function checkWhy(w, name, tx, signers, want) {
  const reason = why(w, tx);
  const got = run(w, tx, signers);
  check(name, got, want);
  if (!got.startsWith("ACCEPTED")) out.push(`      reduced: ${reason}`);
}

// ───────────────────────────── Part A: current contract (hash preimage) ─────────────────────────────
section("A. CURRENT contract: blake2b256 preimage gate");
{
  const w = world({ gate: "hash" });
  check("A1 baseline: operator posts with preimage, no key on the companion or oracle input",
    run(w, post(w, { payer: w.server, prices: [101n, 201n], ext: preimageExt() }), [w.server]), true);
}
{
  const w = world({ gate: "hash" });
  check("A2 control: wrong preimage",
    run(w, post(w, { payer: w.attacker, prices: [1n, 1n], ext: preimageExt(hex.decode(fakeId(0x00))) }), [w.attacker]), false);
}
{
  // Kushti's case. The operator's tx is only BUILT (i.e. sitting in the mempool), never mined here.
  const w = world({ gate: "hash" });
  const victimTx = post(w, { payer: w.server, prices: [101n, 201n], ext: preimageExt() });
  const lifted = liftExtension(victimTx);
  check("A3 ATTACK same epoch: preimage lifted from the mempool tx, prices + epoch replaced, attacker pays fee",
    run(w, post(w, { payer: w.attacker, prices: [999999n, 1n], epoch: 12345, ext: lifted }), [w.attacker]), true);
}
{
  const w = world({ gate: "hash" });
  const victimTx = post(w, { payer: w.server, prices: [101n, 201n], ext: preimageExt() });
  const lifted = liftExtension(victimTx);
  run(w, victimTx, [w.server]);
  w.chain.newBlocks(EPOCH);
  check("A4 ATTACK next epoch: preimage read from the MINED tx still opens the companion",
    run(w, post(w, { payer: w.attacker, prices: [999999n, 1n], epoch: 9, ext: lifted }), [w.attacker]), true);
}
{
  const w = world({ gate: "hash" });
  const before = w.attacker.balance.nanoergs;
  const h0 = holdings(w);
  const tx = post(w, { payer: w.attacker, prices: [1n, 1n], ext: preimageExt(), oracleValue: MIN_RENT });
  const res = run(w, tx, [w.attacker]);
  check("A5 ATTACK skim: oracle box 1 ERG -> 0.01 ERG, difference to attacker", res, true);
  out.push(`      attacker balance delta: ${w.attacker.balance.nanoergs - before} nanoERG`);
  record("A5 (contrast: CURRENT hash-gate contract, no key needed) oracle skim", h0, holdings(w), res, tx, { expectGain: true });
}
{
  const w = world({ gate: "hash" });
  run(w, post(w, { payer: w.attacker, prices: [1n, 1n], ext: preimageExt() }), [w.attacker]);
  w.chain.newBlocks(1);
  check("A6 lockout: after the attacker's post, the real operator is height-locked out of that epoch",
    run(w, post(w, { payer: w.server, prices: [101n, 201n], ext: preimageExt() }), [w.server]), false);
}
section("A. owner path on the current contract");
{
  const w = world({ gate: "hash" });
  check("A7 owner rotates R6 with the cold key (no preimage supplied)",
    run(w, ownerTx(w, { mode: "rotate", newR6: bytes(blake2b256(hex.decode(fakeId(0x77)))) }), [w.owner]), true);
  w.chain.newBlocks(EPOCH);
  check("A7b old preimage is dead after rotation",
    run(w, post(w, { payer: w.attacker, prices: [1n, 1n], ext: preimageExt() }), [w.attacker]), false);
}
{
  const w = world({ gate: "hash" });
  check("A8 owner reclaims box + NFT to the cold wallet", run(w, ownerTx(w, { mode: "reclaim" }), [w.owner]), true);
}
{
  const w = world({ gate: "hash" });
  check("A9 KNOWN LIMIT (current contract): one-tx destroy + NFT burn is impossible (eager successor(0) throws); reclaim A8 works",
    run(w, ownerTx(w, { mode: "burn" }), [w.owner]), false);
}
{
  // Same eager-index bug: the reclaim output carries the NFT, but not at tokens(0), so the filter is empty.
  const w = world({ gate: "hash" });
  w.owner.addBalance({ nanoergs: SAFE_MIN_BOX_VALUE, tokens: [{ tokenId: WALLET_TOKEN, amount: 5n }] });
  const tx = ownerTx(w, { mode: "custom", outputs: (cb) => new OutputBuilder(cb.value, w.owner.address)
    .addTokens([{ tokenId: WALLET_TOKEN, amount: 5n }, ...cb.assets]) });
  check("A9b KNOWN LIMIT (current contract): reclaim into a wallet box where the NFT is not tokens(0) is rejected",
    run(w, tx, [w.owner]), false);
}

// ───────────────────────────── Part B: candidate (scoped hot key) ─────────────────────────────
// Constants the tests reason with are parsed from the contract source, so a contract edit cannot silently desync them.
const srcConst = (name) => {
  const m = HOT_KEY_SRC.match(new RegExp(`val ${name}\\s*=\\s*(\\d+)L?`));
  if (!m) throw new Error(`constant ${name} not found in CompanionAuthorityHotKey.es`);
  return m[1];
};
const SLACK = Number(srcConst("mempoolSlack"));
if (BigInt(srcConst("maxFeePerEpoch")) !== MAX_FEE_PER_EPOCH) throw new Error("maxFeePerEpoch drifted from the test constant");
if (!HOT_KEY_SRC.includes(`fromBase16("${FEE_CONTRACT}")`)) throw new Error("minerFeeProp in the contract != fleet FEE_CONTRACT");

// Self-funded posting tx (the wave-2 baseline):
//   INPUTS  = [oracle (ctx var 0 = outIndex), companion, ...extraInputs]
//   OUTPUTS = [oracle', companion' (value - fee by default), ...extraOutputs, minerFee]
// Change is only created if the inputs leave something over; it goes to `changeTo` (the thief's address by default).
// fee: null => no payFee (the caller supplies the miner-fee box in extraOutputs).
// Successor R7 (post stamp) defaults to the successor's creation height (succHeight, else the build height `height`), so
// rows written for the old creation-height lock drive the post stamp the same way; succStamp moves R7 alone.
// companionExt: context extension on the companion input (e.g. { 1: SInt(1) } selects the refresh-fee path).
function spost(w, { prices = [101n, 201n], epoch = 8, fee = POST_FEE, oracleValue, oracleAssets, oracleR4,
                    oracleTree, outIndex, succValue, succAssets, succR4, succR5, succR6, succR7, succR8, succR9, succHeight, succStamp,
                    succFirst = false, withOracle = true, extraInputs = [], extraOutputs = [], changeTo = w.attacker.address, height,
                    companionExt, cb = companionBox(w), ob = oracleBox(w) } = {}) {
  const succ = successorOf(w, cb, { value: succValue ?? cb.value - (fee ?? 0n), assets: succAssets, r4: succR4, r5: succR5, r6: succR6,
                                   r7: succR7, r8: succR8, r9: succR9, height: succHeight, stamp: succStamp ?? succHeight ?? height });
  const companionIn = new ErgoUnsignedInput(cb);
  if (companionExt) companionIn.setContextExtension(companionExt);
  let inputs, outputs;
  if (!withOracle) {
    inputs = [companionIn, ...extraInputs];
    outputs = [succ, ...extraOutputs];
  } else {
    const oOut = oracleOut(ob, { prices, epoch, value: oracleValue, assets: oracleAssets, r4: oracleR4, tree: oracleTree });
    outputs = [...(succFirst ? [succ, oOut] : [oOut, succ]), ...extraOutputs];
    inputs = [oracleIn(ob, outIndex ?? (succFirst ? 1 : 0)), companionIn, ...extraInputs];
  }
  return buildSF(w, { inputs, outputs, fee, changeTo, height });
}
function buildSF(w, { inputs, outputs, fee = POST_FEE, changeTo = w.attacker.address, height = w.chain.height }) {
  const b = new TransactionBuilder(height).from(inputs, { ensureInclusion: true }).to(outputs).sendChangeTo(changeTo);
  if (fee !== null) b.payFee(fee);
  return b.build();
}
const kindOf = (w, tree) => tree === POOL_TREE ? "pool" : tree === w.oracleTree || w.oracleTrees?.includes(tree) ? "oracle" : tree === w.oracleTreeY ? "oracleY" : tree === w.companionTree ? "companion"
  : tree === FEE_CONTRACT ? "minerFee" : tree === w.attacker.ergoTree ? "THIEF" : tree.startsWith("0008cd") ? "P2PK" : "other";

section("B. CANDIDATE contract: proveDlog(hotKey) gate — self-funded posting is the baseline");
{
  const w = world({ gate: "hotkey" });
  const cb = companionBox(w);
  const tx = spost(w, { prices: [101n, 201n] });
  const o = tx.toEIP12Object();
  const serverBoxes = w.server.utxos.toArray().length;
  const shape = `inputs=[${o.inputs.map((b) => kindOf(w, b.ergoTree))}] outputs=[${o.outputs.map((b) => kindOf(w, b.ergoTree))}]`;
  attack(w, "B0 baseline: self-funded post, hot key signs, server owns no box, no P2PK input, no change output", tx, [w.server], true);
  out.push(`      ${shape}  server-key UTxOs=${serverBoxes}  companion value ${cb.value} -> ${companionBox(w).value} (= miner fee ${sumFee([tx])})`);
}
{
  const w = world({ gate: "hotkey" });
  checkWhy(w, "B0 control: identical tx, nobody signs", spost(w, { prices: [101n, 201n] }), [], false);
}
{
  // Deliberate choice: no change output for anyone. Consequence: the server cannot pay fees from a wallet and take change.
  const w = world({ gate: "hotkey", fundServer: true });
  const tx = post(w, { payer: w.server, prices: [101n, 201n] });
  checkWhy(w, "B1 KNOWN LIMIT (deliberate; was the wave-1 baseline): server wallet pays the fee and takes change -> output rule rejects it",
    tx, [w.server], false);
  check("B1 control: identical tx once the companion owner co-signs (owner path)", run(w, tx, [w.server, w.owner]), true);
}
{
  const w = world({ gate: "hotkey" });
  const donor = w.attacker.utxos.toArray()[0];
  const tx = spost(w, { extraInputs: [donor], succValue: companionBox(w).value, fee: donor.value });
  attack(w, "B1b extra fee input with NO change output (all of it becomes miner fee): accepted — the rule constrains outputs, not inputs",
    tx, [w.server, w.attacker], true);
}
{
  const w = world({ gate: "hotkey" });
  const tx = spost(w, { prices: [999999n, 1n], epoch: 12345 });
  attack(w, "B2 ATTACK same epoch: attacker builds the self-funded post with own prices, no hot key", tx, [w.attacker], false);
  check("B2 control: the identical tx is valid once the hot key co-signs", run(w, tx, [w.attacker, w.server]), true);
}
{
  const w = world({ gate: "hotkey" });
  run(w, spost(w, { prices: [101n, 201n] }), [w.server]);
  w.chain.newBlocks(EPOCH);
  attack(w, "B3 ATTACK next epoch: nothing reusable was revealed by the mined post",
    spost(w, { prices: [999999n, 1n], epoch: 9 }), [w.attacker], false);
}

section("B. what a STOLEN hot key can and cannot do (companion contract)");
{
  const w = world({ gate: "hotkey" });
  attack(w, "B4a hot key rewrites R6 to another key (self-rotation / hijack)",
    spost(w, { prices: [1n, 1n], succR6: SGroupElement(w.attacker.key.publicKey) }), [w.server], false);
}
{
  const w = world({ gate: "hotkey" });
  attack(w, "B4b hot key rewrites R4 owner key",
    spost(w, { prices: [1n, 1n], succR4: SGroupElement(w.attacker.key.publicKey) }), [w.server], false);
}
{
  // Review R3i / R3i2: the successor's R5 (bound oracle-token id) is pinned too.
  const w = world({ gate: "hotkey" });
  attack(w, "B4e (review R3i) hot key rebinds successor R5 to another oracle-token id",
    spost(w, { prices: [1n, 1n], succR5: bytes(ORACLE_TOKEN_2) }), [w.server], false);
  attack(w, "B4e2 (review R3i2) hot key writes a wrong-typed successor R5 (Int instead of Coll[Byte])",
    spost(w, { prices: [1n, 1n], succR5: SInt(1) }), [w.server], false);
  check("B4e control: same post, successor R5 kept", run(w, spost(w, { prices: [1n, 1n] }), [w.server]), true);
}
{
  const w = world({ gate: "hotkey" });
  attack(w, "B4c hot key drains companion ERG beyond the per-epoch fee allowance (rest to the thief's address)",
    spost(w, { prices: [1n, 1n], succValue: MIN_RENT }), [w.server], false);
}
{
  const w = world({ gate: "hotkey" });
  const cb = companionBox(w);
  attack(w, "B4c2 hot key pays allowance + 1 nanoERG as miner fee (no change output; only valueSafe can reject it)",
    spost(w, { prices: [1n, 1n], succValue: cb.value - MAX_FEE_PER_EPOCH - 1n, fee: MAX_FEE_PER_EPOCH + 1n }), [w.server], false);
}
{
  const w = world({ gate: "hotkey" });
  run(w, spost(w, { prices: [1n, 1n] }), [w.server]);
  w.chain.newBlocks(1);
  attack(w, "B4d hot key posts twice inside one epoch (post-stamp R7 lock; was the creation-height lock)", spost(w, { prices: [2n, 2n] }), [w.server], false);
}
{
  const w = world({ gate: "hotkey" });
  attack(w, "B5a (was FINDING) ORIGINAL oracle contract: stolen hot key skims oracle-box ERG to its own address",
    spost(w, { prices: [1n, 1n], oracleValue: MIN_RENT }), [w.server], false);
}
{
  // Isolation: the skim goes to the miner fee, so there is no change output. The original oracle contract has no value
  // check, the companion's valueSafe and output rule are satisfied — only the companion's oracle value pin can reject it.
  const w = world({ gate: "hotkey" });
  const cb = companionBox(w), ob = oracleBox(w);
  attack(w, "B5a2 ORIGINAL oracle contract: oracle ERG skimmed into the miner fee (a mining thief) — only the oracle value pin rejects it",
    spost(w, { prices: [1n, 1n], oracleValue: MIN_RENT, succValue: cb.value - POST_FEE,
               fee: POST_FEE + ob.value - MIN_RENT }), [w.server], false);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  attack(w, "B5b oracle value fix: same skim attempt", spost(w, { prices: [1n, 1n], oracleValue: MIN_RENT }), [w.server], false);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  attack(w, "B5c oracle value fix: normal self-funded post still works", spost(w, { prices: [101n, 201n] }), [w.server], true);
}
{
  const w = world({ gate: "hotkey" });
  const cb = companionBox(w);
  attack(w, `B5d (was FINDING) hot key pockets the fee allowance: successor = value - ${MAX_FEE_PER_EPOCH}, fee ${POST_FEE}, ${MAX_FEE_PER_EPOCH - POST_FEE} change to the thief`,
    spost(w, { prices: [1n, 1n], succValue: cb.value - MAX_FEE_PER_EPOCH }), [w.server], false);
}
{
  const w = world({ gate: "hotkey" });
  const cb = companionBox(w);
  attack(w, `B5d control: same successor value, the whole ${MAX_FEE_PER_EPOCH} allowance paid as miner fee (the maximum a post can cost)`,
    spost(w, { prices: [1n, 1n], succValue: cb.value - MAX_FEE_PER_EPOCH, fee: MAX_FEE_PER_EPOCH }), [w.server], true);
}

section("B. stolen hot key vs the ORACLE contract's companion path (valuefix oracle; control = oracle owner co-signs)");
// The `owner` party is both the oracle owner and the companion owner, so each control opens both owner paths.
// Since wave 2 the companion's oracle pass-through pin (same script, tokens, value) ALSO rejects C1a-c and C3 on its
// own; the `reduced:` line under each attack shows which input blocks (C2 and C5a are blocked by the oracle alone).
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  // The stripped tokens need an ERG-carrying change box: the thief adds a box from its own wallet to carry them home.
  const tx = spost(w, { prices: [1n, 1n], oracleAssets: [{ tokenId: ORACLE_TOKEN, amount: 1n }], extraInputs: w.attacker.utxos.toArray() });
  attack(w, "C1a strip ALL reward tokens from the oracle box (output.tokens.size >= 2 fails)", tx, [w.server, w.attacker], false);
  check("C1a control: identical tx with the oracle owner's signature", run(w, tx, [w.server, w.attacker, w.owner]), true);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  const tx = spost(w, { prices: [1n, 1n], oracleAssets: [{ tokenId: ORACLE_TOKEN, amount: 1n }, { tokenId: REWARD_TOKEN, amount: 9n }],
                        extraInputs: w.attacker.utxos.toArray() });
  attack(w, "C1b reduce reward tokens 10 -> 9", tx, [w.server, w.attacker], false);
  check("C1b control: identical tx with the oracle owner's signature", run(w, tx, [w.server, w.attacker, w.owner]), true);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  w.attacker.addBalance({ nanoergs: SAFE_MIN_BOX_VALUE, tokens: [{ tokenId: EXTRA_TOKEN, amount: 10n }] });
  const tokenBox = w.attacker.utxos.toArray().find((b) => b.assets.length);
  const tx = spost(w, { prices: [1n, 1n], extraInputs: [tokenBox],
    oracleAssets: [{ tokenId: ORACLE_TOKEN, amount: 1n }, { tokenId: EXTRA_TOKEN, amount: 10n }] });
  attack(w, "C1c swap reward tokens for a different token id (same amount)", tx, [w.server, w.attacker], false);
  check("C1c control: identical tx with the oracle owner's signature", run(w, tx, [w.server, w.attacker, w.owner]), true);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  const tx = spost(w, { prices: [1n, 1n], oracleR4: SGroupElement(w.server.key.publicKey) });
  attack(w, "C2 change oracle R4 (owner key) to the thief's key", tx, [w.server], false);
  check("C2 control: identical tx with the oracle owner's signature", run(w, tx, [w.server, w.owner]), true);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  const tx = spost(w, { prices: [1n, 1n], oracleTree: w.attacker.ergoTree });
  attack(w, "C3 move the oracle token (and box) to a different script (thief's P2PK)", tx, [w.server], false);
  check("C3 control: owner co-signs -> STILL rejected (isSimpleCopy binds the script on every path)", run(w, tx, [w.server, w.owner]), false);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  const tx = spost(w, { prices: [1n, 1n], oracleR4: "omit" }); // registers are dense: no R4 => no R5/R6
  attack(w, "C4 oracle output with R4 missing (no registers)", tx, [w.server], false);
  check("C4 control: owner co-signs -> STILL rejected (companionSafe R4.get throws / isSimpleCopy needs R4)", run(w, tx, [w.server, w.owner]), false);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  const tx = spost(w, { prices: [1n, 1n], outIndex: 1 }); // OUTPUTS(1) is the companion successor
  attack(w, "C5a oracle outIndex var points at the companion successor instead of the oracle output", tx, [w.server], false);
  check("C5a control: owner co-signs -> STILL rejected (pointed-at box must hold the oracle token)", run(w, tx, [w.server, w.owner]), false);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  attack(w, "C5b oracle outIndex var out of range", spost(w, { prices: [1n, 1n], outIndex: 7 }), [w.server], false);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  const tx = spost(w, { withOracle: false });
  attack(w, "C6a spend the companion with the oracle box NOT among the inputs (oracleIns.size == 1 fails)", tx, [w.server], false);
  check("C6a control: identical tx with the companion owner's signature (owner path)", run(w, tx, [w.server, w.owner]), true);
}
{
  // Pools where every oracle box carries the SAME oracle-token id (EIP-23 style): the companion binds a token ID, not a
  // box. Simulated by giving the thief one token of that id (stands in for any other oracle's token). Was FINDING
  // (accepted, value-neutral for a P2PK stand-in). Since review F1 the companion also requires the oracle box's R4 to be
  // the companion owner's key; this P2PK stand-in has no R4, so the typed read throws inside the guard (None.get).
  // The R2 block below is the same attack with a stand-in that DOES carry an R4 (on the owner's oracle script).
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  w.attacker.addBalance({ nanoergs: SAFE_MIN_BOX_VALUE, tokens: [{ tokenId: ORACLE_TOKEN, amount: 1n }] });
  const thiefBox = w.attacker.utxos.toArray().find((b) => b.assets.length);
  const cb = companionBox(w);
  const tx = buildSF(w, { inputs: [thiefBox, new ErgoUnsignedInput(cb)],
    outputs: [new OutputBuilder(thiefBox.value, w.attacker.address).addTokens(thiefBox.assets),
              successorOf(w, cb, { value: cb.value - POST_FEE })] });
  check("C6b control: identical tx without the hot key", run(w, tx, [w.attacker]), false);
  attack(w, "C6b (was FINDING) hot key + a same-id P2PK stand-in box (no R4) as \"the oracle\": oracle R4 must be the companion owner's key -> rejected",
    tx, [w.attacker, w.server], false);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  w.attacker.addBalance({ nanoergs: SAFE_MIN_BOX_VALUE, tokens: [{ tokenId: ORACLE_TOKEN, amount: 1n }] });
  const thiefBox = w.attacker.utxos.toArray().find((b) => b.assets.length);
  const cb = companionBox(w);
  const skim = MAX_FEE_PER_EPOCH - POST_FEE;
  const tx = buildSF(w, { inputs: [thiefBox, new ErgoUnsignedInput(cb)],
    outputs: [new OutputBuilder(thiefBox.value + skim, w.attacker.address).addTokens(thiefBox.assets),
              successorOf(w, cb, { value: cb.value - MAX_FEE_PER_EPOCH })] });
  attack(w, `C6c same stand-in, but it comes out ${MAX_FEE_PER_EPOCH - POST_FEE} richer (allowance pocketed via the 'oracle' output) — pass-through value pin`,
    tx, [w.attacker, w.server], false);
}
{
  // The exact wave-1 C6b transaction (thief's token box out at SAFE_MIN_BOX_VALUE, attacker pays the fee, change).
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  w.attacker.addBalance({ nanoergs: SAFE_MIN_BOX_VALUE, tokens: [{ tokenId: ORACLE_TOKEN, amount: 1n }] });
  const thiefBox = w.attacker.utxos.toArray().find((b) => b.assets.length);
  const cb = companionBox(w);
  const tx = build(w, {
    inputs: [thiefBox, new ErgoUnsignedInput(cb), ...w.attacker.utxos.toArray().filter((b) => b !== thiefBox)],
    outputs: [new OutputBuilder(SAFE_MIN_BOX_VALUE, w.attacker.address).addTokens(thiefBox.assets), successorOf(w, cb)],
    payer: w.attacker,
  });
  attack(w, "C6d the exact wave-1 C6b tx (attacker-paid fee + change output) is now rejected by the output rule", tx, [w.attacker, w.server], false);
}
{
  // Review R2. Operator C holds one unit of the pool's shared oracle-token id (simulated by a second unit of ORACLE_TOKEN)
  // and parks it in a box at A's ORACLE SCRIPT address (anyone can pay to any address) with R4 = C's own key. Before F1
  // the hot key's post into this box was ACCEPTED: A's real oracle box missed the epoch, and C (no hot key) could then
  // withdraw the box's reward tokens through the oracle-owner path. Now the companion requires oracle R4 == its own R4.
  // pre: run on the PRE-AUDIT pair (CompanionAuthorityHotKey.pre-audit.es + OracleContractV2-valuefix.pre-audit.es).
  // ownerR4: the planted box's R4 is the owner's key instead of the attacker C's (the single-difference control).
  const plantedWorld = ({ pre = false, ownerR4 = false } = {}) => {
    const w = pre ? world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_PRE_SRC, companionTreeOverride: preAuthTreeFor(EPOCH) })
                  : world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
    const planted = mockUTxO({ ergoTree: w.oracleTree, value: MIN_RENT * 2n, creationHeight: H0 - 5,
      assets: [{ tokenId: ORACLE_TOKEN, amount: 1n }, { tokenId: REWARD_TOKEN, amount: 1n }],
      additionalRegisters: { R4: SGroupElement((ownerR4 ? w.owner : w.attacker).key.publicKey).toHex(), R5: SInt(7).toHex(), R6: SColl(SLong, [1n, 1n]).toHex() } });
    w.oracleParty.addUTxOs(planted);
    const real = w.oracleParty.utxos.toArray().find((b) => b !== planted && b.additionalRegisters.R4 === SGroupElement(w.owner.key.publicKey).toHex());
    return { w, planted, real };
  };
  {
    const { w, planted, real } = plantedWorld();
    // exactly what an honest daemon builds if it picks the planted box
    attack(w, "R2 (was FINDING, review) hot key A posts into a box PLANTED on A's oracle script (shared token id, R4 = C): companion rejects (oracle R4 != owner)",
      spost(w, { ob: planted, prices: [101n, 201n] }), [w.server], false);
    check("R2 control: same world, same companion box, honest post on A's REAL oracle box (R4 = owner), hot key only",
      run(w, spost(w, { ob: real, prices: [101n, 201n] }), [w.server]), true);
  }
  {
    const { w, planted } = plantedWorld();
    // Was the ACCEPTED control (pre-audit, only the companion input blocked it). Re-based after the audit: the fixed
    // oracle's path 3 requires the NFT input's R4 == the oracle box's R4 (owner != C), so the owner co-sign no longer opens it.
    checkWhy(w, "R2 planted tx once the companion owner co-signs: REJECTED — the planted box is now blocked by the oracle contract (path-3 R4 check: authority R4 = owner != planted R4 = C; reduced `in0 oracle=attacker`) as well as the authority contract",
      spost(w, { ob: planted, prices: [101n, 201n] }), [w.server, w.owner], false);
  }
  {
    // Single-difference control for the R2 attack: the SAME planted box (same script, value, tokens, R5/R6, height),
    // except R4 = the owner's key, i.e. the honest box. Same tx shape, hot key only.
    const { w, planted } = plantedWorld({ ownerR4: true });
    checkWhy(w, "R2 control (single difference): identical planted box and tx with R4 = the owner's key (the honest box), hot key only — fixed pair",
      spost(w, { ob: planted, prices: [101n, 201n] }), [w.server], true);
  }
  {
    const { w, planted } = plantedWorld({ pre: true });
    checkWhy(w, "R2 contrast (PRE-AUDIT pair): the original control — identical planted tx (R4 = C) once the companion owner co-signs — is ACCEPTED pre-audit (only the companion input blocked it then)",
      spost(w, { ob: planted, prices: [101n, 201n] }), [w.server, w.owner], true);
  }
}

section("B. cross-oracle / multi-companion / layout attacks on the candidate");
{
  // Oracle X is bound to companion A (stolen hot key); oracle Y is compiled with COMPANION_NFT_2.
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, second: true });
  const ox = oracleBox(w), oy = oracleBox(w, ORACLE_TOKEN_2), ca = companionBox(w);
  const tx = buildSF(w, {
    inputs: [oracleIn(ox, 0), oracleIn(oy, 1), new ErgoUnsignedInput(ca)],
    outputs: [oracleOut(ox, { prices: [1n, 1n] }), oracleOut(oy, { prices: [1n, 1n] }), successorOf(w, ca, { value: ca.value - POST_FEE })],
  });
  attack(w, "D1a companion A (stolen hot key) used to post oracle Y, which is bound to a different companion NFT", tx, [w.server], false);
  checkWhy(w, "D1a2 oracle Y's owner co-signs: companion A's output rule still rejects (oracle Y's output is neither A's oracle nor a fee box)",
    tx, [w.server, w.owner2], false);
  check("D1a control: identical tx with oracle Y's owner AND companion A's owner", run(w, tx, [w.server, w.owner2, w.owner]), true);
}
{
  // Two oracle boxes on the SAME oracle script (same companion NFT baked in), different oracle tokens.
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, twinOracle: true });
  const ox = oracleBox(w), o3 = oracleBox(w, ORACLE_TOKEN_3), ca = companionBox(w);
  const tx = buildSF(w, {
    inputs: [oracleIn(ox, 0), oracleIn(o3, 1), new ErgoUnsignedInput(ca)],
    outputs: [oracleOut(ox, { prices: [1n, 1n] }), oracleOut(o3, { prices: [1n, 1n] }), successorOf(w, ca, { value: ca.value - POST_FEE })],
  });
  attack(w, "D1b (was FINDING) one companion spend posts a second oracle box compiled with its NFT id (not the R5-bound one)", tx, [w.server], false);
  check("D1b control: identical tx once the companion owner co-signs (both oracle inputs pass via companionSafe)",
    run(w, tx, [w.server, w.owner]), true);
}
{
  // Two real companions in one tx.
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, second: true });
  const ox = oracleBox(w), oy = oracleBox(w, ORACLE_TOKEN_2), ca = companionBox(w), cbB = companionBox(w, COMPANION_NFT_2);
  const tx = buildSF(w, {
    inputs: [oracleIn(ox, 0), oracleIn(oy, 1), new ErgoUnsignedInput(ca), new ErgoUnsignedInput(cbB)],
    outputs: [oracleOut(ox, { prices: [1n, 1n] }), oracleOut(oy, { prices: [1n, 1n] }),
              successorOf(w, ca, { value: ca.value - POST_FEE }), successorOf(w, cbB)],
  });
  attack(w, "D2 two companions in one tx, only A's hot key held: companion B / oracle Y do not ride along", tx, [w.server], false);
  checkWhy(w, "D2b KNOWN LIMIT (deliberate): the same batch with BOTH hot keys is rejected too — one post per tx (output rule)",
    tx, [w.server, w.server2], false);
  // Was the ACCEPTED control (pre-audit). Re-based after the audit: oracle Y's R4 is owner2 but companion B's R4 is owner,
  // so the fixed oracle's path-3 R4 check fails for Y and Y falls back to proveDlog(owner2).
  checkWhy(w, "D2 identical tx with both hot keys + the companions' owner: REJECTED — oracle Y (R4 = owner2) is now blocked by the fixed oracle's path-3 R4 check (companion B's R4 = owner != owner2; reduced `in1 oracleY=owner2`)",
    tx, [w.server, w.server2, w.owner], false);
  checkWhy(w, "D2 control (single difference: signer set): identical tx with both hot keys + the companions' owner + oracle Y's owner (owner2) — fixed pair",
    tx, [w.server, w.server2, w.owner, w.owner2], true);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_PRE_SRC, companionTreeOverride: preAuthTreeFor(EPOCH), second: true });
  const ox = oracleBox(w), oy = oracleBox(w, ORACLE_TOKEN_2), ca = companionBox(w), cbB = companionBox(w, COMPANION_NFT_2);
  const tx = buildSF(w, {
    inputs: [oracleIn(ox, 0), oracleIn(oy, 1), new ErgoUnsignedInput(ca), new ErgoUnsignedInput(cbB)],
    outputs: [oracleOut(ox, { prices: [1n, 1n] }), oracleOut(oy, { prices: [1n, 1n] }),
              successorOf(w, ca, { value: ca.value - POST_FEE }), successorOf(w, cbB)],
  });
  checkWhy(w, "D2 contrast (PRE-AUDIT pair): the original control — identical tx with both hot keys + the companions' owner — is ACCEPTED pre-audit",
    tx, [w.server, w.server2, w.owner], true);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  const tx = spost(w, { prices: [101n, 201n], succFirst: true });
  check("D3 control: identical tx without the hot key", run(w, tx, []), false);
  // Was ACCEPTED ("position-independent") on the pre-audit oracle. Flipped BY DESIGN by audit F-1 (fix P3,
  // `INPUTS(outIndex).id == SELF.id`): the oracle input at INPUTS(0) may only name OUTPUTS(0). Builder rule: same index.
  attack(w, "D3 successor at OUTPUTS(0), oracle output at OUTPUTS(1) (outIndex=1): REJECTED by the oracle's same-index binding (audit F-1/P3; was accepted pre-audit)", tx, [w.server], false);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, companionExtraAssets: [{ tokenId: EXTRA_TOKEN, amount: 5n }] });
  attack(w, "D4 (was FINDING) extra tokens held by the companion (beyond the NFT) taken by the hot-key holder (to its change address)",
    spost(w, { prices: [1n, 1n], succAssets: [{ tokenId: COMPANION_NFT, amount: 1n }], extraInputs: w.attacker.utxos.toArray() }),
    [w.server, w.attacker], false);
}
{
  // Isolation: the extra tokens go into the miner-fee box (no change output) — only the token-list pin can reject it.
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, companionExtraAssets: [{ tokenId: EXTRA_TOKEN, amount: 5n }] });
  const cb = companionBox(w);
  const feeBox = new OutputBuilder(POST_FEE, FEE_CONTRACT).addTokens([{ tokenId: EXTRA_TOKEN, amount: 5n }]);
  attack(w, "D4b extra tokens moved into the miner-fee box (no change output; only the token-list pin rejects it)",
    spost(w, { prices: [1n, 1n], succAssets: [{ tokenId: COMPANION_NFT, amount: 1n }], succValue: cb.value - POST_FEE,
               fee: null, extraOutputs: [feeBox] }), [w.server], false);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, companionExtraAssets: [{ tokenId: EXTRA_TOKEN, amount: 5n }] });
  attack(w, "D4 control: successor keeps the full token list -> post accepted", spost(w, { prices: [1n, 1n] }), [w.server], true);
}

section("B. post-stamp lock (R7) vs HEIGHT (E1) and mempool slack — rebased from the creation-height lock: same rows, R7 is the clock");
const IDLE = 10;
const HC = H0 - IDLE * EPOCH;
const idleWorld = () => world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, companionHeight: HC, oracleHeight: HC, fundHeight: HC });
{
  // The exact wave-1 E1 attack starts with a successor stamp of SELF + EPOCH (stale, far below HEIGHT). That first
  // post is rejected, so the box never moves and the back-to-back chain cannot start: one attempt is the whole test.
  // Rebased: the stamp is R7 (the tx is still built at that height, so the creation height matches it as before).
  const w = idleWorld();
  const before = holdings(w);
  const sh = stampOf(companionBox(w), "R7") + EPOCH;
  const tx = spost(w, { prices: [1n, 1n], height: sh });
  const reason = why(w, tx);
  const got = run(w, tx, [w.server]);
  check(`E1 (was FINDING) after ${IDLE} idle epochs: the stale-stamp chain cannot start — its first post (successor R7 = SELF.R7 + ${EPOCH}) is rejected (wave-1 attack replayed on the R7 stamp)`, got, false);
  out.push(`      HEIGHT=${w.chain.height + 1} succR7=${sh}${got.startsWith("ACCEPTED") ? "" : `  reduced: ${reason}`}`);
  record("E1 (was FINDING) stale-height chain, first post", before, holdings(w), got, tx);
}
{
  // Pins MockChain's HEIGHT (= chain.height + 1, the block being built) and the in-contract `R7 <= HEIGHT`.
  // Rebased: was "successor creationHeight = HEIGHT + 1 (contract repeats the consensus rule)". R7 is not a consensus
  // field, so here the contract's bound is the only one; the successor's creation height stays the build height.
  const w = idleWorld();
  attack(w, "E1b successor post stamp R7 = HEIGHT + 1 (future-dated; only the contract bounds R7)",
    spost(w, { succStamp: w.chain.height + 2 }), [w.server], false);
  attack(w, "E1b control: successor post stamp R7 = HEIGHT", spost(w, { succStamp: w.chain.height + 1 }), [w.server], true);
}
{
  // New with the stamp: the successor's creation height is no longer read by the authority contract.
  const w = idleWorld();
  attack(w, `E1b2 successor creationHeight stale (= SELF + ${EPOCH} - 1, far below HEIGHT) but R7 = HEIGHT: accepted (creation height not checked)`,
    spost(w, { succHeight: HC + EPOCH - 1, succStamp: w.chain.height + 1 }), [w.server], true);
  const w2 = idleWorld();
  attack(w2, "E1b3 successor creationHeight = HEIGHT but R7 left at SELF.R7 (stamp not advanced): rejected",
    spost(w2, { succHeight: w2.chain.height + 1, succR7: SInt(HC) }), [w2.server], false);
}
{
  // Rebased: was "successor creationHeight = HEIGHT - slack - 1 / HEIGHT - slack"; same window, on R7.
  const w = idleWorld();
  attack(w, `E1c successor post stamp R7 = HEIGHT - ${SLACK + 1} (one block older than the slack window)`,
    spost(w, { succStamp: w.chain.height + 1 - SLACK - 1 }), [w.server], false);
  attack(w, `E1c control: successor post stamp R7 = HEIGHT - ${SLACK}`, spost(w, { succStamp: w.chain.height + 1 - SLACK }), [w.server], true);
}
{
  // Best thief strategy after a long idle: at every block, post with the OLDEST post stamp R7 the contract allows
  // (max(SELF.R7 + EPOCH, HEIGHT - SLACK)). Compared with an honest server (stamp = chain tip) over the same window.
  const WINDOW = 3 * EPOCH;
  const simulate = (pick) => {
    const w = idleWorld();
    const start = w.chain.height, before = holdings(w), txs = [], posts = [];
    while (w.chain.height + 1 <= start + WINDOW) {
      const HEIGHT = w.chain.height + 1;
      const created = pick(stampOf(companionBox(w), "R7"), HEIGHT);
      if (created <= HEIGHT) {
        const tx = spost(w, { prices: [BigInt(HEIGHT), 1n], succStamp: created });
        if (run(w, tx, [w.server]) === "ACCEPTED") { posts.push(`${HEIGHT - start}:${created - start}`); txs.push(tx); continue; }
      }
      w.chain.newBlock();
    }
    return { posts, before, after: holdings(w), txs };
  };
  const thief = simulate((selfH, HEIGHT) => Math.max(selfH + EPOCH, HEIGHT - SLACK));
  const honest = simulate((selfH, HEIGHT) => (HEIGHT - 1 >= selfH + EPOCH ? HEIGHT - 1 : Infinity));
  const bound = 1 + Math.floor((WINDOW - 1 + SLACK) / EPOCH);
  const bad = thief.posts.length > honest.posts.length + 1 || thief.posts.length > bound;
  check(`E1d greedy thief after ${IDLE} idle epochs, ${WINDOW}-block window: more posts than honest+1 or than 1+floor((W-1+slack)/epoch)=${bound}`,
    bad ? `ACCEPTED (thief ${thief.posts.length})` : `REJECTED (thief ${thief.posts.length} posts, honest ${honest.posts.length}, bound ${bound})`, false);
  out.push(`      posts as blockOffset:postStampOffset — thief [${thief.posts.join(" ")}]  honest [${honest.posts.join(" ")}]`);
  out.push(`      allowance burned by the thief: ${thief.posts.length} x <= ${MAX_FEE_PER_EPOCH} (fee actually paid ${sumFee(thief.txs)})`);
  record(`E1d greedy thief, ${thief.posts.length} posts in ${WINDOW} blocks`, thief.before, thief.after, `ACCEPTED (${thief.posts.length} posts)`, thief.txs);
}
{
  const w = world({ gate: "hotkey" });
  const tx = spost(w, { prices: [101n, 201n] }); // built at tip h: successor R7 (and creationHeight) = h
  w.chain.newBlocks(SLACK - 1);
  check(`E3a legit post built at tip h sits in the mempool and is included in block h+${SLACK}`, run(w, tx, [w.server]), true);
}
{
  const w = world({ gate: "hotkey" });
  const tx = spost(w, { prices: [101n, 201n] });
  w.chain.newBlocks(SLACK);
  checkWhy(w, `E3b KNOWN LIMIT (by design): the same tx included in block h+${SLACK + 1} has expired and must be rebuilt`, tx, [w.server], false);
}
{
  // The daemon stamps outputs at tip - 1 (OracleBoxPoster.scala:117, :208; Kushti's propagation advice). A post built at
  // tip h is then stamped h-1 and lives for blocks h+1 .. h+SLACK-1. The authority box was last stamped (R7) one block
  // before the default world so that the lock (>= SELF.R7 + epoch) is met by the h-1 stamp.
  const w = world({ gate: "hotkey", companionHeight: H0 - EPOCH - 1 });
  const h = w.chain.height;
  const tx = spost(w, { prices: [101n, 201n], height: h - 1 });
  w.chain.newBlocks(SLACK - 2);
  check(`E3c daemon-stamped post (outputs at tip-1) built at tip h is included in block h+${SLACK - 1} (last block of its life)`, run(w, tx, [w.server]), true);
  const w2 = world({ gate: "hotkey", companionHeight: H0 - EPOCH - 1 });
  const h2 = w2.chain.height;
  const tx2 = spost(w2, { prices: [101n, 201n], height: h2 - 1 });
  w2.chain.newBlocks(SLACK - 1);
  checkWhy(w2, `E3d KNOWN LIMIT (by design): the same daemon-stamped tx in block h+${SLACK} has expired; the daemon rebuilds it (hot key on the server, no fee lost)`,
    tx2, [w2.server], false);
}
{
  // One day at ~2-minute blocks = 720 blocks. Greedy thief: at every block post with the OLDEST post stamp R7 the
  // contract allows (max(SELF.R7 + EPOCH, HEIGHT - SLACK)) and pay the WHOLE cap as miner fee every time.
  const DAY = 720;
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, companionHeight: HC, oracleHeight: HC, fundHeight: HC, companionValue: 2n * ERG });
  const start = w.chain.height, before = holdings(w), txs = [];
  let cb = companionBox(w);
  while (w.chain.height + 1 <= start + DAY) {
    const HEIGHT = w.chain.height + 1;
    const created = Math.max(stampOf(cb, "R7") + EPOCH, HEIGHT - SLACK);
    if (created <= HEIGHT) {
      const tx = spost(w, { prices: [BigInt(HEIGHT), 1n], succStamp: created, succValue: cb.value - MAX_FEE_PER_EPOCH, fee: MAX_FEE_PER_EPOCH, cb });
      if (run(w, tx, [w.server]) === "ACCEPTED") { txs.push(tx); cb = companionBox(w); continue; }
    }
    w.chain.newBlock();
  }
  const bound = 1 + Math.floor((DAY - 1 + SLACK) / EPOCH);
  const burned = sumFee(txs);
  const bad = txs.length > bound || burned > BigInt(bound) * MAX_FEE_PER_EPOCH;
  check(`E1e greedy thief over ${DAY} blocks (~1 day), paying the full cap each post: more than 1+floor((W-1+slack)/epoch)=${bound} posts or > ${bound} x cap burned`,
    bad ? `ACCEPTED (thief ${txs.length} posts, ${burned} burned)` : `REJECTED (thief ${txs.length} posts, ${burned} nanoERG burned to miners = ${Number(burned) / 1e9} ERG/day)`, false);
  record(`E1e greedy thief, ${txs.length} posts in ${DAY} blocks at the full cap`, before, holdings(w), `ACCEPTED (${txs.length} posts)`, txs);
}
{
  // Same day, TEST-ONLY variant with the lock at the pool's 6 blocks (for the operator's comparison).
  const DAY = 720;
  const tree6 = authTreeOf(HOT_KEY_SRC, POOL_EPOCH);
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, companionHeight: HC, oracleHeight: HC, fundHeight: HC, companionValue: 2n * ERG, companionTreeOverride: tree6 });
  const start = w.chain.height, txs = [];
  let cb = companionBox(w);
  while (w.chain.height + 1 <= start + DAY) {
    const HEIGHT = w.chain.height + 1;
    const created = Math.max(stampOf(cb, "R7") + POOL_EPOCH, HEIGHT - SLACK);
    if (created <= HEIGHT) {
      const tx = spost(w, { prices: [BigInt(HEIGHT), 1n], succStamp: created, succValue: cb.value - MAX_FEE_PER_EPOCH, fee: MAX_FEE_PER_EPOCH, cb });
      if (run(w, tx, [w.server]) === "ACCEPTED") { txs.push(tx); cb = companionBox(w); continue; }
    }
    w.chain.newBlock();
  }
  const bound = 1 + Math.floor((DAY - 1 + SLACK) / POOL_EPOCH);
  check(`E1f same day, TEST-ONLY lock = ${POOL_EPOCH}: more than ${bound} posts`, txs.length > bound ? `ACCEPTED (${txs.length})` :
    `REJECTED (thief ${txs.length} posts, ${sumFee(txs)} nanoERG = ${Number(sumFee(txs)) / 1e9} ERG/day)`, false);
}
{
  // Slack trade-off, measured on TEST-ONLY variants of this contract (only `mempoolSlack` differs; 4 = the real one).
  //   life    = blocks a daemon-stamped (tip-1) post stays includable;   a post that misses them must be rebuilt
  //   min gap = closest two consecutive greedy-thief posts can land (= epoch - slack); posts in 18 blocks
  for (const s of [2, 3, 4]) {
    const src = HOT_KEY_SRC.replace(/val mempoolSlack\s*=\s*\d+/, `val mempoolSlack   = ${s}`);
    if (src === HOT_KEY_SRC && s !== SLACK) throw new Error("slack variant did not apply");
    const tree = authTreeOf(src);
    let life = 0;
    for (let k = 1; k <= EPOCH; k++) {
      const w = world({ gate: "hotkey", companionHeight: H0 - EPOCH - 1, companionTreeOverride: tree });
      const tx = spost(w, { prices: [1n, 1n], height: w.chain.height - 1 });
      w.chain.newBlocks(k - 1);
      if (run(w, tx, [w.server]) === "ACCEPTED") life = k; else break;
    }
    const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, companionHeight: HC, oracleHeight: HC, fundHeight: HC, companionTreeOverride: tree });
    const start = w.chain.height, blocks = [];
    while (w.chain.height + 1 <= start + 3 * EPOCH) {
      const HEIGHT = w.chain.height + 1;
      const created = Math.max(stampOf(companionBox(w), "R7") + EPOCH, HEIGHT - s);
      if (created <= HEIGHT && run(w, spost(w, { prices: [1n, 1n], succStamp: created }), [w.server]) === "ACCEPTED") { blocks.push(HEIGHT - start); continue; }
      w.chain.newBlock();
    }
    const gaps = blocks.slice(1).map((b, i) => b - blocks[i]);
    const bound = 1 + Math.floor((3 * EPOCH - 1 + s) / EPOCH);
    const ok = life === s - 1 && Math.min(...gaps) === EPOCH - s && blocks.length <= bound;
    out.push(`${ok ? "PASS" : "FAIL"}  E4 slack=${s}${s === SLACK ? " (chosen)" : " (test-only variant)"}: daemon-stamped post lives ${life} block(s) (want slack-1=${s - 1}); ` +
      `greedy thief min inclusion gap ${Math.min(...gaps)} (want epoch-slack=${EPOCH - s}); ${blocks.length} posts in ${3 * EPOCH} blocks (bound ${bound}) at [${blocks.join(" ")}]`);
  }
}
out.push(`      (R7 is not a consensus field; E1-E3 hold because the contract itself checks R7 <= HEIGHT and`,
         `       R7 >= HEIGHT - ${SLACK}. MockChain's HEIGHT = chain.height + 1, as E1b/E1c's boundaries show.)`);

section("B. junk on the successor");
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  // Rebased: was "junk R7 (allowed: R7-R9 are not pinned)". R7/R8 are now the stamps, so the junk goes to R9.
  attack(w, "E2a hot key posts a successor with a junk R9 (allowed: R9 is not pinned; rebased from R7, now the post stamp)",
    spost(w, { prices: [1n, 1n], succR9: bytes(fakeId(0xff)) }), [w.server], true);
  check("E2b owner still reclaims the junked successor (hot key cannot brick the owner path)",
    run(w, ownerTx(w, { mode: "reclaim" }), [w.owner]), true);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  attack(w, "E2a2 (new) hot key writes a junk (Coll[Byte]) successor R7 instead of an Int stamp: rejected",
    spost(w, { prices: [1n, 1n], succR7: bytes(fakeId(0xff)) }), [w.server], false);
  attack(w, "E2a3 (new) hot key moves the fee stamp R8 on a post: rejected (a post keeps R8)",
    spost(w, { prices: [1n, 1n], succR8: SInt(w.chain.height) }), [w.server], false);
}
{
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC });
  w.attacker.addBalance({ nanoergs: SAFE_MIN_BOX_VALUE, tokens: [{ tokenId: EXTRA_TOKEN, amount: 1n }] });
  const tokenBox = w.attacker.utxos.toArray().find((b) => b.assets.length);
  const cb = companionBox(w);
  attack(w, "E2c hot key adds a junk token to the successor (token list pinned both ways now)",
    spost(w, { prices: [1n, 1n], extraInputs: [tokenBox], succAssets: [...cb.assets, { tokenId: EXTRA_TOKEN, amount: 1n }],
               succValue: cb.value - POST_FEE, fee: POST_FEE + tokenBox.value }), [w.server, w.attacker], false);
}

section("B. owner path on the candidate");
{
  const w = world({ gate: "hotkey" });
  check("B6a owner rotates the hot key with one cold-signed tx",
    run(w, ownerTx(w, { mode: "rotate", newR6: SGroupElement(w.server2.key.publicKey) }), [w.owner]), true);
  w.chain.newBlocks(EPOCH);
  attack(w, "B6b old hot key is dead after rotation", spost(w, { prices: [1n, 1n] }), [w.server], false);
  check("B6c new hot key posts (self-funded; the new server key owns no box either)",
    run(w, spost(w, { prices: [101n, 201n] }), [w.server2]), true);
}
{
  const w = world({ gate: "hotkey" });
  check("B7 owner reclaims box + NFT to the cold wallet", run(w, ownerTx(w, { mode: "reclaim" }), [w.owner]), true);
}
{
  const w = world({ gate: "hotkey" });
  check("B8 owner destroys the box and burns the NFT in one tx (successor bound inside the guard)", run(w, ownerTx(w, { mode: "burn" }), [w.owner]), true);
  const w2 = world({ gate: "hotkey" });
  const burnByHot = ownerTx(w2, { mode: "burn", payer: w2.attacker });
  attack(w2, "B8 control: burn paid by the thief's wallet, hot key signs", burnByHot, [w2.server, w2.attacker], false);
  check("B8 control: identical tx once the owner co-signs", run(w2, burnByHot, [w2.server, w2.attacker, w2.owner]), true);
}
section("B. owner-path liveness: other ways posting-path evaluation could throw");
{
  const w = world({ gate: "hotkey" });
  w.owner.addBalance({ nanoergs: SAFE_MIN_BOX_VALUE, tokens: [{ tokenId: WALLET_TOKEN, amount: 5n }] });
  const tx = ownerTx(w, { mode: "custom", outputs: (cb) => new OutputBuilder(cb.value, w.owner.address)
    .addTokens([{ tokenId: WALLET_TOKEN, amount: 5n }, ...cb.assets]) });
  check("L1 owner reclaims into a wallet box where the NFT is NOT tokens(0) (empty successor filter; cf. A9b)", run(w, tx, [w.owner]), true);
}
{
  const w = world({ gate: "hotkey" });
  const tx = ownerTx(w, { mode: "custom", outputs: (cb) => successorOf(w, cb, { r4: SGroupElement(w.owner2.key.publicKey) }) });
  check("L2 owner rotates the COLD key (same script; posting branch stops at the oracle checks, no typed successor read)", run(w, tx, [w.owner]), true);
}
{
  // Wave 1: rejected because the typed successor.R6 read ran unconditionally. Now the posting branch stops at the oracle
  // checks (no oracle box in an owner tx) before any typed read, so the owner may create such a box — and L3a2/L3a3 show
  // it stays recoverable by the owner and unusable by the hot key.
  const w = world({ gate: "hotkey" });
  const tx = ownerTx(w, { mode: "custom", outputs: (cb) => new OutputBuilder(cb.value, w.companionTree).addTokens(cb.assets)
    .setAdditionalRegisters({ R4: cb.additionalRegisters.R4, R5: cb.additionalRegisters.R5 }) });
  check("L3a (was KNOWN LIMIT) owner tx with a same-script NFT output missing R6 is now accepted", run(w, tx, [w.owner]), true);
  w.chain.newBlocks(EPOCH);
  attack(w, "L3a2 hot-key post from that R6-less box (structural checks pass, SELF.R6.get throws inside the guard)",
    spost(w, { prices: [1n, 1n], succR6: SGroupElement(w.server.key.publicKey) }), [w.server], false);
  check("L3a3 owner reclaims the R6-less box", run(w, ownerTx(w, { mode: "reclaim" }), [w.owner]), true);
}
{
  const w = world({ gate: "hotkey" });
  const tx = ownerTx(w, { mode: "custom", outputs: (cb) => new OutputBuilder(cb.value, w.companionTree).addTokens(cb.assets)
    .setAdditionalRegisters({ R4: cb.additionalRegisters.R4, R5: cb.additionalRegisters.R5, R6: bytes(blake2b256(PREIMAGE)) }) });
  check("L3b (was KNOWN LIMIT) same, R6 wrong-typed (Coll[Byte] hash instead of GroupElement): now accepted", run(w, tx, [w.owner]), true);
  w.chain.newBlocks(EPOCH);
  attack(w, "L3b2 hot-key post from the wrong-typed-R6 box (typed SELF.R6 read throws inside the guard)",
    spost(w, { prices: [1n, 1n], succR6: SGroupElement(w.server.key.publicKey) }), [w.server], false);
  check("L3b3 owner rotates IN PLACE out of the wrong-typed-R6 box (same-script successor, R6 := GroupElement)",
    run(w, ownerTx(w, { mode: "rotate", newR6: SGroupElement(w.server2.key.publicKey) }), [w.owner]), true);
  const w3 = world({ gate: "hotkey" });
  check("L3 control: identical shape with R6 a GroupElement", run(w3, ownerTx(w3, { mode: "rotate", newR6: SGroupElement(w3.server2.key.publicKey) }), [w3.owner]), true);
}
// Review R1: SELF.R5 is read as soon as the tx has exactly one same-script NFT output, i.e. on every owner in-place
// rotate. A box with a missing or wrong-typed R5 cannot be rotated in place even with the cold key; reclaim works.
const wellFormedRotate = (w) => ownerTx(w, { mode: "custom", outputs: (cb) => new OutputBuilder(cb.value, w.companionTree).addTokens(cb.assets)
  .setAdditionalRegisters({ R4: SGroupElement(w.owner.key.publicKey), R5: bytes(ORACLE_TOKEN), R6: SGroupElement(w.server2.key.publicKey) }) });
for (const [id, label, regs] of [
  ["L3c", "R5 wrong-typed (Int instead of Coll[Byte])", (cb) => ({ R4: cb.additionalRegisters.R4, R5: SInt(5), R6: cb.additionalRegisters.R6 })],
  ["L3d", "R5 and R6 missing (R4 only)", (cb) => ({ R4: cb.additionalRegisters.R4 })],
]) {
  const w = world({ gate: "hotkey" });
  check(`${id} setup (${label}): owner creates the malformed same-script NFT box with the cold key`,
    run(w, ownerTx(w, { mode: "custom", outputs: (cb) => new OutputBuilder(cb.value, w.companionTree).addTokens(cb.assets)
      .setAdditionalRegisters(regs(cb)) }), [w.owner]), true);
  w.chain.newBlocks(EPOCH);
  checkWhy(w, `${id} KNOWN LIMIT (review R1, ${label}): owner rotate IN PLACE to well-formed R4/R5/R6, cold key supplied -> SELF.R5 read throws`,
    wellFormedRotate(w), [w.owner], false);
  check(`${id} control (${label}): owner reclaims the same box to the cold wallet`, run(w, ownerTx(w, { mode: "reclaim" }), [w.owner]), true);
}
{
  const w = world({ gate: "hotkey" });
  w.chain.newBlocks(EPOCH);
  check("L3c/L3d control: identical in-place rotate out of a WELL-FORMED box", run(w, wellFormedRotate(w), [w.owner]), true);
}
{
  // Migration from the hash-gate box to the hot-key script, done by the owner. The hash gate does not look at the new
  // box's registers (scriptPreserved=false short-circuits), so a forgotten R6 rewrite goes through...
  const w = world({ gate: "hash" });
  const migrate = (r6) => ownerTx(w, { mode: "custom", outputs: (cb) => new OutputBuilder(cb.value, HOT_KEY_TREE).addTokens(cb.assets)
    .setAdditionalRegisters({ R4: cb.additionalRegisters.R4, R5: cb.additionalRegisters.R5, R6: r6 }) });
  const hk = w.chain.addParty(HOT_KEY_TREE, "hotkey-script");
  check("L4a migration hash-gate -> hot-key script keeping the OLD R6 (hash) is accepted by the hash gate",
    run(w, migrate(w.companionParty.utxos.toArray()[0].additionalRegisters.R6), [w.owner]), true);
  const bad = hk.utxos.toArray()[0];
  const tx = new TransactionBuilder(w.chain.height)
    .from([new ErgoUnsignedInput(bad), ...w.owner.utxos.toArray()], { ensureInclusion: true })
    .to(new OutputBuilder(bad.value, w.owner.address).addTokens(bad.assets))
    .sendChangeTo(w.owner.address).payFee(RECOMMENDED_MIN_FEE_VALUE).build();
  check("L4b (was KNOWN LIMIT) ...and the owner can now reclaim that box (R6 is never read on an owner reclaim)",
    run(w, tx, [w.owner]), true);
  const w2 = world({ gate: "hash" });
  const hk2 = w2.chain.addParty(HOT_KEY_TREE, "hotkey-script");
  run(w2, ownerTx(w2, { mode: "custom", outputs: (cb) => new OutputBuilder(cb.value, HOT_KEY_TREE).addTokens(cb.assets)
    .setAdditionalRegisters({ R4: cb.additionalRegisters.R4, R5: cb.additionalRegisters.R5, R6: SGroupElement(w2.server.key.publicKey) }) }), [w2.owner]);
  const good = hk2.utxos.toArray()[0];
  const tx2 = new TransactionBuilder(w2.chain.height)
    .from([new ErgoUnsignedInput(good), ...w2.owner.utxos.toArray()], { ensureInclusion: true })
    .to(new OutputBuilder(good.value, w2.owner.address).addTokens(good.assets))
    .sendChangeTo(w2.owner.address).payFee(RECOMMENDED_MIN_FEE_VALUE).build();
  check("L4 control: migration with R6 rewritten to a GroupElement -> owner reclaims fine", run(w2, tx2, [w2.owner]), true);
}
{
  // "Topping up" by sending ERG straight to the companion P2S address: no NFT, no registers.
  const w = world({ gate: "hotkey" });
  const topUp = mockUTxO({ ergoTree: w.companionTree, value: ERG, creationHeight: H0 - 1 });
  w.companionParty.addUTxOs(topUp);
  const tx = new TransactionBuilder(w.chain.height)
    .from([new ErgoUnsignedInput(topUp), ...w.owner.utxos.toArray()], { ensureInclusion: true })
    .to(new OutputBuilder(topUp.value, w.owner.address))
    .sendChangeTo(w.owner.address).payFee(RECOMMENDED_MIN_FEE_VALUE).build();
  check("L5 KNOWN LIMIT: a plain ERG top-up sent to the companion address (no NFT, no R4) is unrecoverable even by the owner (no R4 = no owner)",
    run(w, tx, [w.owner]), false);
}
{
  // Same top-up but carrying R4 = owner key: no NFT, so `myNft` is the empty guard value and only PATH B applies.
  const w = world({ gate: "hotkey" });
  const topUp = mockUTxO({ ergoTree: w.companionTree, value: ERG, creationHeight: H0 - 1,
    additionalRegisters: { R4: SGroupElement(w.owner.key.publicKey).toHex() } });
  w.companionParty.addUTxOs(topUp);
  const toThief = new TransactionBuilder(w.chain.height)
    .from([new ErgoUnsignedInput(topUp), ...w.attacker.utxos.toArray()], { ensureInclusion: true })
    .to(new OutputBuilder(topUp.value, w.attacker.address))
    .sendChangeTo(w.attacker.address).payFee(RECOMMENDED_MIN_FEE_VALUE).build();
  attack(w, "L5c hot key tries to sweep a no-NFT top-up box (R4 = owner) to the thief", toThief, [w.server, w.attacker], false);
  const tx = new TransactionBuilder(w.chain.height)
    .from([new ErgoUnsignedInput(topUp), ...w.owner.utxos.toArray()], { ensureInclusion: true })
    .to(new OutputBuilder(topUp.value, w.owner.address))
    .sendChangeTo(w.owner.address).payFee(RECOMMENDED_MIN_FEE_VALUE).build();
  check("L5b a no-NFT top-up that carries R4 = owner key IS recoverable by the owner (SELF.tokens(0) is guarded)", run(w, tx, [w.owner]), true);
}

// ───────────────────────────── Q: option (a) — four authority boxes, four posts per epoch ─────────────────────────────
// The operator runs 4 oracle boxes under ONE owner key, all with the pool's ONE oracle-token id. With this contract each
// post moves one oracle box, so option (a) = 4 authority boxes (same script), each R4 = owner, R5 = the shared oracle
// token id. R4 and R5 are therefore IDENTICAL on all four: nothing in the registers says which oracle box is whose.
// The only on-chain binding left is the oracle contract's compile-time companionNftId:
//   nft "shared":   one oracle script compiled with ONE NFT id; that id is minted with amount 4, one unit per authority box
//   nft "distinct": four NFTs; four oracle scripts, oracle box i on the script compiled with NFT i
//   hot "shared":   one hot key in R6 of all four;   hot "distinct": four hot keys (hot0 = the `server` party)
const NFT4 = [0, 1, 2, 3].map((i) => fakeId(0xd0 + i));
function fourWorld({ nft = "shared", hot = "distinct", tree = HOT_KEY_TREE, planted = false, pool = false } = {}) {
  const chain = new MockChain({ height: H0 });
  const owner = chain.newParty("owner-cold"), owner2 = chain.newParty("owner2-cold"), attacker = chain.newParty("attacker");
  const server = chain.newParty("server"), server2 = chain.newParty("server-rotated");
  const hotParties = hot === "shared" ? [server, server, server, server] : [server, chain.newParty("hot1"), chain.newParty("hot2"), chain.newParty("hot3")];
  for (const p of [owner, owner2, attacker]) p.addBalance({ nanoergs: ERG });
  const nftOf = (i) => (nft === "shared" ? COMPANION_NFT : NFT4[i]);
  const oracleTrees = [0, 1, 2, 3].map((i) => compileOracle(ORACLE_V2_VALUEFIX_SRC, nftOf(i), tree));
  const oracleParties = [...new Set(oracleTrees)].map((t, i) => chain.addParty(t, `oracle-script-${i}`));
  const authParty = chain.addParty(tree, "authority-script");
  for (let i = 0; i < 4; i++) {
    oracleParties[nft === "shared" ? 0 : i].addUTxOs(mockUTxO({ ergoTree: oracleTrees[i], value: ERG, creationHeight: H0 - 100,
      assets: [{ tokenId: ORACLE_TOKEN, amount: 1n }, { tokenId: REWARD_TOKEN, amount: 10n + BigInt(i) }],
      additionalRegisters: { R4: SGroupElement(owner.key.publicKey).toHex(), R5: SInt(7).toHex(), R6: SColl(SLong, [100n, 200n]).toHex() } }));
    authParty.addUTxOs(mockUTxO({ ergoTree: tree, value: ERG / 10n, creationHeight: H0 - EPOCH,
      assets: [{ tokenId: nftOf(i), amount: 1n }],
      additionalRegisters: { R4: SGroupElement(owner.key.publicKey).toHex(), R5: bytes(ORACLE_TOKEN).toHex(), R6: SGroupElement(hotParties[i].key.publicKey).toHex(),
                             R7: SInt(H0 - EPOCH).toHex(), R8: SInt(H0 - EPOCH).toHex() } }));
  }
  if (planted) oracleParties[0].addUTxOs(mockUTxO({ ergoTree: oracleTrees[0], value: MIN_RENT * 2n, creationHeight: H0 - 5,
    assets: [{ tokenId: ORACLE_TOKEN, amount: 1n }, { tokenId: REWARD_TOKEN, amount: 1n }],
    additionalRegisters: { R4: SGroupElement(attacker.key.publicKey).toHex(), R5: SInt(7).toHex(), R6: SColl(SLong, [1n, 1n]).toHex() } }));
  const poolParty = pool ? addPool(chain) : undefined;
  const w = { chain, owner, owner2, server, server2, attacker, hot: hotParties, companionTree: tree, oracleTree: oracleTrees[0], oracleTrees, authParty, oracleParties, nftOf, poolParty };
  return w;
}
// authority box i / oracle box j (j = owner's box with reward 10+j). Re-read after every tx (box ids change).
// qAuth: the authority box holding NFT #i (distinct-NFT worlds). qAuthAll: every authority box, insertion order.
const qAuth = (w, i) => w.authParty.utxos.toArray().find((b) => b.assets[0]?.tokenId === w.nftOf(i));
function qAuthAll(w) { return w.authParty.utxos.toArray().filter((b) => b.assets.length); }
const qOracle = (w, j) => w.oracleParties.flatMap((p) => p.utxos.toArray())
  .find((b) => b.additionalRegisters.R4 === SGroupElement(w.owner.key.publicKey).toHex() && b.assets[1].amount === 10n + BigInt(j));
function qpost(w, cb, ob, { fee = POST_FEE, ...rest } = {}) {
  return spost(w, { cb, ob, fee, ...rest });
}
section("Q. option (a): four authority boxes + four txs per epoch with the CURRENT contract");
info("binding available: R4 = owner and R5 = oracle token id are the SAME on all four boxes; only the oracle script's companionNftId differs (distinct NFTs). In the reduced lines hot0 = server.");
{
  // (a)-shared-NFT: each authority box can post ANY of the owner's four oracle boxes.
  const res = [];
  for (let j = 0; j < 4; j++) {
    const w = fourWorld({ nft: "shared" });
    res.push(attack(w, `Q1.${j} shared NFT id: authority box #0 (hot0) posts oracle box #${j}`, qpost(w, qAuthAll(w)[0], qOracle(w, j)), [w.hot[0]], true));
  }
}
{
  const w = fourWorld({ nft: "shared" });
  const a = qAuthAll(w);
  attack(w, "Q2 shared NFT id: authority #0 posts oracle box #0 ...", qpost(w, a[0], qOracle(w, 0)), [w.hot[0]], true);
  attack(w, "Q2 ... and authority #1 posts the SAME oracle box again in the next block (same epoch): accepted — two posts, two fees, boxes #1-#3 unposted",
    qpost(w, a[1], qOracle(w, 0), { prices: [9n, 9n] }), [w.hot[1]], true);
}
{
  const w = fourWorld({ nft: "distinct" });
  attack(w, "Q3 distinct NFTs: authority #0 posts ITS oracle box #0 (control)", qpost(w, qAuth(w, 0), qOracle(w, 0)), [w.hot[0]], true);
  const w2 = fourWorld({ nft: "distinct" });
  const tx = qpost(w2, qAuth(w2, 0), qOracle(w2, 1));
  attack(w2, "Q3b distinct NFTs: authority #0 posts oracle box #1 (its script wants NFT #1): rejected by the ORACLE contract", tx, [w2.hot[0]], false);
  check("Q3b control: identical tx with the owner's signature (oracle owner path)", run(w2, tx, [w2.hot[0], w2.owner]), true);
}
// Merge: authority boxes #0 and #1 both spent, ONE successor (the #0 one), box #1's ERG becomes miner fee.
function mergeTx(w, a0, a1, burnNft) {
  const ob = qOracle(w, 0);
  const b = new TransactionBuilder(w.chain.height)
    .from([oracleIn(ob, 0), new ErgoUnsignedInput(a0), new ErgoUnsignedInput(a1)], { ensureInclusion: true })
    .to([oracleOut(ob, { prices: [1n, 1n] }), successorOf(w, a0, { value: a0.value - POST_FEE })])
    .sendChangeTo(w.attacker.address).payFee(a1.value + POST_FEE);
  b.burnTokens({ tokenId: burnNft, amount: 1n });
  return b.build();
}
{
  // The real contract carries the fix (exactly one input holds this box's NFT id at tokens(0)): the merge is closed.
  const w = fourWorld({ nft: "shared", hot: "shared" });
  const [a0, a1] = qAuthAll(w);
  attack(w, `Q4 (shared NFT id + shared hot key): MERGE two authority boxes into one successor (box #1's ${a1.value} nanoERG -> miner fee) — closed by the NFT-input check`,
    mergeTx(w, a0, a1, COMPANION_NFT), [w.server], false);
  const w2 = fourWorld({ nft: "shared", hot: "shared" });
  attack(w2, "Q4 control: same world, the normal single post (one authority box) is accepted", qpost(w2, qAuthAll(w2)[0], qOracle(w2, 0)), [w2.server], true);
}
{
  const w = fourWorld({ nft: "shared", hot: "distinct" });
  const [a0, a1] = qAuthAll(w);
  const tx = mergeTx(w, a0, a1, COMPANION_NFT);
  attack(w, "Q4c shared NFT id, DISTINCT hot keys, hot0 stolen: merge rejected", tx, [w.hot[0]], false);
  // With the NFT-input check in the real contract, BOTH authority inputs reduce to owner (two inputs hold the NFT id).
  // Before that check, only box #1 failed (its successor R6 must equal hot1, the shared successor carries hot0).
  checkWhy(w, "Q4c2 same merge signed with hot0 AND hot1: still rejected (both authority inputs reduce to owner: two inputs hold the NFT id)", tx, [w.hot[0], w.hot[1]], false);
}
{
  const w = fourWorld({ nft: "distinct", hot: "shared" });
  attack(w, "Q4d DISTINCT NFTs + shared hot key: the merge is rejected (box #1 finds no successor carrying NFT #1)",
    mergeTx(w, qAuth(w, 0), qAuth(w, 1), NFT4[1]), [w.server], false);
}
{
  // Contrast: the TEST-ONLY pre-patch variant = the real contract with exactly the NFT-input check removed (the
  // contract as it was before the fix; `oneNftInput` := true). Same merge tx as Q4: accepted there, so that check is
  // what closes it.
  const PRE_FRAGMENT = "val oneNftInput = INPUTS.filter { (b: Box) =>\n      b.tokens.size > 0 && b.tokens(0)._1 == myNft\n    }.size == 1";
  if (HOT_KEY_SRC.split(PRE_FRAGMENT).length !== 2) throw new Error("NFT-input fragment not found exactly once");
  const pretree = authTreeOf(HOT_KEY_SRC.replace(PRE_FRAGMENT, "val oneNftInput = true"));
  info(`pre-patch variant ergoTree ${pretree.length / 2} B blake2b256[0..8]=${hex.encode(blake2b256(hex.decode(pretree))).slice(0, 16)}; ` +
       `real contract ${HOT_KEY_TREE.length / 2} B blake2b256[0..8]=${hex.encode(blake2b256(hex.decode(HOT_KEY_TREE))).slice(0, 16)}`);
  const w = fourWorld({ nft: "shared", hot: "shared", tree: pretree });
  const [a0, a1] = qAuthAll(w);
  const tx = mergeTx(w, a0, a1, COMPANION_NFT);
  const got = attack(w, `Q4-pre FINDING (contrast, TEST-ONLY pre-patch variant): the same MERGE is accepted; box #1's ${a1.value} nanoERG -> miner fee, one NFT unit burned`,
    tx, [w.server], true);
  check(`Q4b FINDING (contrast, pre-patch variant): the merge's miner fee ${sumFee([tx])} exceeds the per-post cap ${MAX_FEE_PER_EPOCH} (cap bound broken; thief nets ERG only if it mines)`,
    got.startsWith("ACCEPTED") && sumFee([tx]) > MAX_FEE_PER_EPOCH ? "ACCEPTED" : "REJECTED", true);
}
{
  // A stolen SHARED hot key reaches all four boxes: four posts in one epoch (one per authority box), four fees.
  for (const nft of ["shared", "distinct"]) {
    const w = fourWorld({ nft, hot: "shared" });
    const before = holdings(w), txs = [];
    let ok = 0;
    for (let i = 0; i < 4; i++) {
      const cb = nft === "shared" ? qAuthAll(w).find((b) => b.creationHeight === H0 - EPOCH) : qAuth(w, i);
      const tx = qpost(w, cb, qOracle(w, i), { prices: [666n, 666n], fee: MAX_FEE_PER_EPOCH });
      if (run(w, tx, [w.server]) === "ACCEPTED") { ok++; txs.push(tx); }
    }
    check(`Q5 ${nft} NFT, SHARED hot key stolen: thief posts all 4 oracle boxes in one epoch (4 txs, 4 x cap burned = ${sumFee(txs)})`, ok === 4 ? "ACCEPTED" : `REJECTED (${ok}/4)`, true);
    record(`Q5 ${nft} NFT, shared hot key: 4 posts in one epoch`, before, holdings(w), ok === 4 ? "ACCEPTED" : "REJECTED", txs);
  }
}
{
  // Distinct hot keys: stolen hot0 alone. distinct NFTs -> only oracle box #0; shared NFT -> any ONE box per epoch.
  const w = fourWorld({ nft: "distinct", hot: "distinct" });
  attack(w, "Q6a distinct NFTs + distinct keys, hot0 stolen: posting oracle box #2 through authority #2 needs hot2 -> rejected",
    qpost(w, qAuth(w, 2), qOracle(w, 2)), [w.hot[0]], false);
  attack(w, "Q6a control: hot0 posts its own box #0", qpost(w, qAuth(w, 0), qOracle(w, 0)), [w.hot[0]], true);
  const w2 = fourWorld({ nft: "shared", hot: "distinct" });
  attack(w2, "Q6b shared NFT + distinct keys, hot0 stolen: it posts oracle box #3 (any box, one per epoch via its own authority box)",
    qpost(w2, qAuthAll(w2)[0], qOracle(w2, 3)), [w2.hot[0]], true);
  w2.chain.newBlocks(1);
  attack(w2, "Q6b ... and cannot post a second box in the same epoch (its authority box is post-stamp-locked)",
    qpost(w2, qAuthAll(w2).find((b) => b.creationHeight > H0 - EPOCH), qOracle(w2, 2)), [w2.hot[0]], false);
}
{
  // Two authority boxes posting ONE oracle box in ONE tx.
  for (const nft of ["shared", "distinct"]) {
    const w = fourWorld({ nft, hot: "shared" });
    const a0 = nft === "shared" ? qAuthAll(w)[0] : qAuth(w, 0), a1 = nft === "shared" ? qAuthAll(w)[1] : qAuth(w, 1);
    const ob = qOracle(w, 0);
    const tx = buildSF(w, { inputs: [oracleIn(ob, 0), new ErgoUnsignedInput(a0), new ErgoUnsignedInput(a1)],
      outputs: [oracleOut(ob, { prices: [1n, 1n] }), successorOf(w, a0, { value: a0.value - POST_FEE }), successorOf(w, a1)] });
    attack(w, `Q7 ${nft} NFT: two authority boxes + their successors around ONE oracle box in one tx -> rejected`, tx, [w.server], false);
    check(`Q7 control (${nft}): identical tx with the owner's signature`, run(w, tx, [w.server, w.owner]), true);
  }
}
{
  const w = fourWorld({ nft: "shared", planted: true });
  const planted = w.oracleParties[0].utxos.toArray().find((b) => b.additionalRegisters.R4 === SGroupElement(w.attacker.key.publicKey).toHex());
  attack(w, "Q8 shared NFT: authority #2 posts a box PLANTED on the owner's oracle script (attacker R4) -> rejected (oracle R4 != owner)",
    qpost(w, qAuthAll(w)[2], planted), [w.hot[2]], false);
  attack(w, "Q8 control: authority #2 posts a real owner box", qpost(w, qAuthAll(w)[2], qOracle(w, 2)), [w.hot[2]], true);
}

// ───────────────────────────── T: real cadence timeline ─────────────────────────────
// The pool box is modelled from the deployed rules; every POST is a real MockChain tx through the authority contract and
// the valuefix oracle contract.
//   refresh contract (RefreshContract.es:12-31): poolIn.creationInfo._1 < HEIGHT - 6, oracle created >= HEIGHT - 12 and
//     R5 == pool epoch. Refresh outputs (pool box AND every collected oracle box) are stamped S; collected oracle boxes
//     keep R4 only (RefreshTxBuilder.scala:460-471), so the next epoch needs a new post.
//   daemon (AutoDaemon.scala:225-268, 304-307): refresh at tip t when t - poolCreated > 6 and enough fresh oracles; post
//     once per pool epoch as soon as the epoch is visible. Post stamp = tip - 1 (OracleBoxPoster.scala:208). Refresh stamp
//     S = tip - 1 when the tip is fresh, else tip (RefreshTxBuilder.scala:90-92): both are swept ("back" / "full").
//   inclusion: every tx built at tip t lands in block t+1 unless a scenario says otherwise. HEIGHT = t+1.
// Worst case under test: the refresh waits for THIS operator's datapoint (othersFresh = false), so any lateness of the
// operator's post shows up directly as refresh delay. "delay" = refresh tip - the daemon's earliest tip (poolCreated + 7).
const FRESH_WINDOW = 12, DAEMON_REFRESH_AGE = POOL_EPOCH + 1;
function cadence({ tree, epochs = 7, refreshStamp = "back", postStamp = "tip-1", lateEpoch = -1, lateBy = 0, missEpoch = -1, dropEpoch = -1,
                   blockEpoch = -1, blockFor = 0 }) {
  const w = world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, companionHeight: H0 - 50, oracleHeight: H0 - 50, fundHeight: H0 - 50,
                    companionTreeOverride: tree });
  let R = H0 - 1, k = 1, visibleAt = H0;                  // pool box of epoch 1 created at H0-1, visible from tip H0
  let oEpoch = null, oCreated = null, lastPosted = 0, pending = null, dropTx = null;
  const rows = [], problems = [];
  let row = { k, R, posts: [], blocked: 0 };
  while (rows.length < epochs) {
    const t = w.chain.height;
    if (pending && pending.block <= t) {                    // refresh landed: new pool box, oracle box collected (R4 only)
      rows.push(row);
      ({ R, k } = pending); visibleAt = pending.block; pending = null;
      const ob = oracleBox(w);
      w.oracleParty.utxos.remove(ob.boxId);
      w.oracleParty.addUTxOs(mockUTxO({ ergoTree: ob.ergoTree, value: ob.value, creationHeight: R,
        assets: [ob.assets[0], { tokenId: ob.assets[1].tokenId, amount: BigInt(ob.assets[1].amount) + 1n }],
        additionalRegisters: { R4: ob.additionalRegisters.R4 } }));
      oEpoch = null; oCreated = R;
      row = { k, R, posts: [], blocked: 0 };
      continue;
    }
    // refresh decision (needs THIS operator's datapoint unless its post was deliberately missed: then others refresh)
    const H = t + 1;
    const ours = oEpoch === k && oCreated >= H - FRESH_WINDOW;
    const blocked = k === blockEpoch && t < visibleAt + blockFor;    // other datapoints missing: the refresh cannot run yet
    if (!pending && !blocked && t - R >= DAEMON_REFRESH_AGE && (ours || k === missEpoch)) {
      if (!(R < H - POOL_EPOCH)) problems.push(`epoch ${k}: refresh contract epochOver false at HEIGHT ${H}`);
      Object.assign(row, { refreshTip: t, earliest: R + DAEMON_REFRESH_AGE, delay: t - (R + DAEMON_REFRESH_AGE),
                           margin: ours ? oCreated - (H - FRESH_WINDOW) : null, usedOurs: ours });
      pending = { block: t + 1, R: refreshStamp === "back" ? t - 1 : t, k: k + 1 };
      w.chain.newBlock();                                    // the daemon's tick returns after a refresh (no post)
      continue;
    }
    // post decision
    // re-post when our datapoint aged out (AutoDaemon.scala:263-265; countFreshOracles uses created >= tip - 2*6 + 1)
    const agedOut = lastPosted === k && oEpoch === k && oCreated < t - 2 * POOL_EPOCH + 1;
    const wantPost = (lastPosted !== k || agedOut) && k !== missEpoch && !(k === lateEpoch && t < visibleAt + lateBy);
    const stamp = postStamp === "tip" ? t : t - 1;
    if (wantPost) {
      if (k === dropEpoch && !row.dropped) {
        // first attempt is built but never mined; the daemon rebuilds once it can no longer be included
        dropTx = { tx: spost(w, { prices: [BigInt(k), 1n], epoch: k, height: t - 1 }), builtAt: t };
        row.dropped = true;
        w.chain.newBlocks(SLACK - 1);                        // tip = t + SLACK - 1: the dropped tx is dead from block t + SLACK
        const dead = run(w, dropTx.tx, [w.server]);
        row.droppedTxDeadAtBlock = `${w.chain.height + 1 - t}:${dead.startsWith("ACCEPTED") ? "STILL-VALID" : "rejected"}`;
        if (dead.startsWith("ACCEPTED")) { problems.push(`epoch ${k}: dropped tx still valid after its life`); }
        continue;
      }
      const tx = spost(w, { prices: [BigInt(k), 1n], epoch: k, height: stamp });
      const reason = why(w, tx);
      if (run(w, tx, [w.server]) === "ACCEPTED") {
        lastPosted = k; oEpoch = k; oCreated = stamp;
        row.posts.push({ stamp, block: t + 1 });
        continue;
      }
      row.blocked++;
      if (!/companion=owner/.test(reason)) problems.push(`epoch ${k}: post rejected at tip ${t} for a reason other than the authority lock: ${reason}`);
    }
    w.chain.newBlock();
    if (t > H0 + 40 * epochs) { problems.push("timeline did not progress"); break; }
  }
  return { rows, problems };
}
const fmtRows = (rows) => rows.map((r) => `e${r.k}[R=${r.R - H0} post=${r.posts.map((p) => `${p.stamp - H0}@${p.block - H0}`).join(",") || "-"}` +
  `${r.blocked ? ` lockWait=${r.blocked}` : ""}${r.droppedTxDeadAtBlock ? ` dropped(dead@+${r.droppedTxDeadAtBlock})` : ""} refresh@${r.refreshTip - H0}` +
  ` delay=${r.delay}${r.margin === null ? " (others)" : ` fresh+${r.margin}`}]`).join(" ");
section(`T. MODELLED: only the posts are real transactions; refresh and freshness verdicts come from the model, RefreshContract is not executed here. Cadence timeline on the pool's numbers (pool epochLength ${POOL_EPOCH}, authority lock ${EPOCH}, freshness HEIGHT-${FRESH_WINDOW}, daemon stamp tip-1, slack ${SLACK})`);
info("heights are offsets from H0; post=stamp@block; refresh@tip; delay = refresh tip - (poolCreated + 7); fresh+m = oracle stamp - (HEIGHT - 12)");
const treeFor = (E) => authTreeOf(HOT_KEY_SRC, E);
{
  for (const stamp of ["back", "full"]) {
    const { rows, problems } = cadence({ tree: HOT_KEY_TREE, refreshStamp: stamp });
    const bad = problems.length || rows.some((r) => r.delay !== 0 || r.blocked || r.margin === null || r.margin < 0 || r.posts.length !== 1);
    out.push(`${bad ? "FAIL" : "PASS"}  T1 normal cadence, refresh stamp ${stamp}: every epoch one post on the first attempt, no lock wait, every refresh at the earliest tip, datapoint fresh`);
    info(fmtRows(rows) + (problems.length ? `  PROBLEMS: ${problems.join("; ")}` : ""));
  }
}
{
  // Late post: the post for epoch 3 is held back lateBy blocks after epoch 3 becomes visible (API failure, dropped tx, ...).
  // The refresh of epoch 3 waits for it by construction (that delay is the operator's own lateness). Under test: the
  // epoch-4 post is still permitted inside epoch 4, every datapoint is fresh at its refresh, and the extra delay the
  // LOCK adds to the epoch-4 refresh.
  // postStamp "tip-1" = the daemon today; "tip" = a builder that stamps at the tip (TEST-ONLY comparison).
  const lastWait = {};
  for (const [E, postStamp] of [[EPOCH, "tip-1"], [POOL_EPOCH, "tip-1"], [POOL_EPOCH, "tip"], [POOL_EPOCH + 1, "tip-1"]]) {
    const tree = E === EPOCH ? HOT_KEY_TREE : treeFor(E);
    for (const stamp of ["back", "full"]) {
      const res = [];
      let worst = 0, okAll = true;
      for (let d = 0; d <= 8; d++) {
        const { rows, problems } = cadence({ tree, refreshStamp: stamp, postStamp, lateEpoch: 3, lateBy: d });
        const e4 = rows.find((r) => r.k === 4);
        const allPosted = rows.every((r) => r.posts.length === 1);
        const allFresh = rows.every((r) => r.margin !== null && r.margin >= 0);
        okAll &&= !problems.length && allPosted && allFresh;
        worst = Math.max(worst, e4.delay);
        res.push(`d=${d}:e4delay=${e4.delay}${e4.blocked ? `/wait${e4.blocked}` : ""}`);
        if (d === 8) lastWait[`${E}/${postStamp}/${stamp}`] = rows.filter((r) => r.k >= 4).map((r) => r.blocked);
        if (d === 8 && stamp === "back") info(`E=${E} post stamp ${postStamp}, refresh stamp ${stamp}, d=8 timeline: ${fmtRows(rows)}`);
        if (problems.length) info(`PROBLEMS d=${d}: ${problems.join("; ")}`);
      }
      // Bound: post k lands no later than the block the refresh is built at (t_r), so its stamp is <= t_r - 1 - delta
      // (delta = 1 for a tip-1 stamp, 0 for a tip stamp); post k+1 is then built no later than tip t_r - 1 + E and lands
      // by block t_r + E. The earliest refresh tip is R + 7 with R = t_r - 1 (back stamp) or t_r (full stamp). So the
      // lock adds no delay iff E <= 6 (back) / E <= 7 (full), whatever delta is. E = 7 is the test-only counter-example.
      // (A first hand prediction that E = 6 with a tip stamp delays by 1 was wrong: it mis-placed the build tip.)
      const want = E > POOL_EPOCH && stamp === "back" ? 1 : 0;
      out.push(`${okAll && worst === want ? "PASS" : "FAIL"}  T2 late epoch-3 post (held 0..8 blocks), authority epochLength=${E}${E === EPOCH ? " (chosen)" : " (test-only variant)"}, post stamp ${postStamp}, refresh stamp ${stamp}: ` +
        `every epoch posted + fresh at refresh; worst extra epoch-4 refresh delay from the lock = ${worst} block(s) (want ${want})`);
      info(res.join(" "));
    }
  }
  // Catch-up after a late post (d = 8, back-stamped refresh): the lock wait of each later epoch's post. With a lock of
  // E = 6 the back-stamped pool epoch is also 6 stamp-blocks, so the wait never shrinks and every later post lands in
  // the very block the refresh becomes possible (zero margin: one missed block = one block of refresh delay). E = 5
  // gains one block per epoch back.
  const w5 = lastWait[`${EPOCH}/tip-1/back`], w6 = lastWait[`${POOL_EPOCH}/tip-1/back`];
  const decays = w5.at(-1) === 0, persists = w6.at(-1) === w6[0] && w6[0] > 0;
  out.push(`${decays && persists ? "PASS" : "FAIL"}  T2c catch-up after the late post: lock wait per later epoch, E=${EPOCH} (chosen) [${w5.join(",")}] decays to 0; E=${POOL_EPOCH} (variant) [${w6.join(",")}] never shrinks`);
}
{
  const { rows, problems } = cadence({ tree: HOT_KEY_TREE, missEpoch: 3 });
  const e4 = rows.find((r) => r.k === 4);
  const bad = problems.length || e4.blocked || e4.posts.length !== 1 || e4.delay !== 0 || rows.some((r) => r.k !== 3 && (r.margin === null || r.margin < 0));
  out.push(`${bad ? "FAIL" : "PASS"}  T3 missed post (operator posts nothing in epoch 3; others refresh): epoch-4 post accepted on the first attempt, no lock wait, no delay`);
  info(fmtRows(rows) + (problems.length ? `  PROBLEMS: ${problems.join("; ")}` : ""));
}
{
  const { rows, problems } = cadence({ tree: HOT_KEY_TREE, dropEpoch: 3 });
  const e3 = rows.find((r) => r.k === 3), e4 = rows.find((r) => r.k === 4);
  const bad = problems.length || e3.posts.length !== 1 || !rows.every((r) => r.margin !== null && r.margin >= 0) || e4.delay > 1;
  out.push(`${bad ? "FAIL" : "PASS"}  T4 dropped post (epoch-3 tx never mined): dead after its ${SLACK - 1}-block life, rebuilt and accepted; every datapoint fresh; epoch-4 delay ${e4.delay} (want <= 1)`);
  info(fmtRows(rows) + (problems.length ? `  PROBLEMS: ${problems.join("; ")}` : ""));
}
{
  // Refresh of epoch 3 cannot run for 20 blocks (the other datapoints are missing). Our epoch-3 datapoint ages out
  // (> 12 blocks), the daemon re-posts inside the same epoch, and the lock must allow it (>= 12 blocks since the last post).
  const { rows, problems } = cadence({ tree: HOT_KEY_TREE, blockEpoch: 3, blockFor: 20 });
  const e3 = rows.find((r) => r.k === 3);
  const bad = problems.length || e3.posts.length !== 2 || e3.blocked || !rows.every((r) => r.margin !== null && r.margin >= 0);
  out.push(`${bad ? "FAIL" : "PASS"}  T5 refresh stalled 20 blocks: the epoch-3 datapoint ages out, the daemon's re-post in the same epoch is accepted with no lock wait, and the refresh uses a fresh datapoint`);
  info(fmtRows(rows) + (problems.length ? `  PROBLEMS: ${problems.join("; ")}` : ""));
}
{
  // Ported from review-r2-short-epoch.mjs (reviewer F1): the authority lock vs the SHORTEST pool epoch the deployed
  // RefreshContract allows. epochOver = poolIn.creationInfo._1 < HEIGHT - 6 (RefreshContract.es:13, :38) and
  // poolOut.creationInfo._1 >= HEIGHT - 4 (:268): a refresher landing at HEIGHT = R + 7 who stamps R' = HEIGHT - 4 = R + 3
  // gets a 3-block pool epoch. MODELLED: epochs become visible every `gap` blocks; the daemon posts as soon as an epoch is
  // visible (stamp tip-1, lands tip+1) and the post must land before the next refresh, i.e. by block V + gap - 1. Every
  // post is a real MockChain tx through this authority contract + the valuefix oracle contract; a rejected attempt must
  // reduce to companion=owner (the authority lock), else the row fails.
  const shortEpoch = (tree, gap, epochs = 12, oracleSrc = ORACLE_V2_VALUEFIX_SRC) => {
    const w = world({ gate: "hotkey", oracleSrc, companionHeight: H0 - 50, oracleHeight: H0 - 100, companionTreeOverride: tree });
    const marks = [], problems = [];
    let firstReason = null;
    let V = w.chain.height;
    for (let k = 1; k <= epochs; k++) {
      let posted = null;
      while (w.chain.height <= V + gap - 2) {
        const t = w.chain.height;
        const tx = spost(w, { prices: [BigInt(k), 1n], epoch: k, height: t - 1 });
        const reason = why(w, tx);
        if (run(w, tx, [w.server]) === "ACCEPTED") { posted = t - 1 - H0; w.chain.newBlock(); break; }
        firstReason ??= reason;
        if (!/companion=owner/.test(reason)) problems.push(`epoch ${k} tip ${t - H0}: ${reason}`);
        w.chain.newBlock();
      }
      marks.push(posted === null ? "MISS" : `s${posted}`);
      while (w.chain.height < V + gap) w.chain.newBlock();
      V += gap;
    }
    return { missed: marks.filter((m) => m === "MISS").length, marks, epochs, problems, firstReason };
  };
  // wantMiss: true = some misses expected, false = none, "all" = every epoch missed (fails closed).
  // pre: run on the PRE-AUDIT pair (CompanionAuthorityHotKey.pre-audit.es + OracleContractV2-valuefix.pre-audit.es).
  for (const [tag, label, E, gap, wantMiss, pre] of [
    ["T6a", "KNOWN LIMIT: pool epoch 3 blocks (refresher back-stamps HEIGHT-4 at the earliest HEIGHT), lock 5 (chosen): misses expected", EPOCH, 3, true],
    ["T6b", "CONTROL: pool epoch 6 blocks (daemon back-stamp cadence), lock 5 (chosen): no miss", EPOCH, POOL_EPOCH, false],
    ["T6c", `ISOLATION (runs on the PRE-AUDIT pair: the fixed authority contract refuses a lock at or below mempoolSlack ${SLACK}, see T6c2): pool epoch 3 blocks, TEST-ONLY lock 3: no miss (the lock is what misses)`, 3, 3, false, true],
    ["T6c2", `FIXED authority contract, pool epoch 3 blocks, TEST-ONLY lock 3 (<= mempoolSlack ${SLACK}): fails closed, posts nothing (epochLength > mempoolSlack guard)`, 3, 3, "all"],
    ["T6d", "KNOWN LIMIT: pool epoch 4 blocks (refresher stamps HEIGHT-3), lock 5 (chosen): misses expected", EPOCH, 4, true],
  ]) {
    const tree = pre ? preAuthTreeFor(E) : E === EPOCH ? HOT_KEY_TREE : treeFor(E);
    const { missed, marks, epochs, problems, firstReason } = shortEpoch(tree, gap, 12, pre ? ORACLE_V2_VALUEFIX_PRE_SRC : ORACLE_V2_VALUEFIX_SRC);
    const ok = !problems.length && (wantMiss === "all" ? missed === epochs : wantMiss ? missed > 0 : missed === 0);
    out.push(`${ok ? "PASS" : "FAIL"}  ${tag} ${label} — missed ${missed}/${epochs} epochs (miss rate ${(100 * missed / epochs).toFixed(0)}%)`);
    info(`[${marks.join(" ")}]` + (problems.length ? `  PROBLEMS: ${problems.join("; ")}` : ""));
    if (wantMiss === "all" && firstReason) info(`reduced: ${firstReason}`);
  }
}

// Section X contributed by odiseusme in issue #1. X1 PASS means the attack is ACCEPTED: it is why each operator
// must mint their own authority NFT (README, "Intended deployment"). X2 shows a post can carry its own top-up.
section("X. REVIEW: cross-operator, shared NFT id");
{
  const w = fourWorld({ nft: "shared" });
  // operator B (= w.attacker) holds a legit NFT unit; plants an authority box with A's owner key in R4, B's key in R6
  w.authParty.addUTxOs(mockUTxO({ ergoTree: w.companionTree, value: ERG / 10n, creationHeight: H0 - EPOCH,
    assets: [{ tokenId: COMPANION_NFT, amount: 1n }],
    additionalRegisters: { R4: SGroupElement(w.owner.key.publicKey).toHex(), R5: bytes(ORACLE_TOKEN).toHex(), R6: SGroupElement(w.attacker.key.publicKey).toHex(),
                           R7: SInt(H0 - EPOCH).toHex(), R8: SInt(H0 - EPOCH).toHex() } }));
  const planted = qAuthAll(w).find((b) => b.additionalRegisters.R6 === SGroupElement(w.attacker.key.publicKey).toHex());
  check("X1 operator B's planted authority box (R4 = A's owner key, R6 = B's key) posts junk into A's oracle box, signed by B only",
    run(w, qpost(w, planted, qOracle(w, 0), { prices: [1n, 1n] }), [w.attacker]), true);
}
{
  const w = fourWorld({ nft: "shared" });
  const cb = qAuthAll(w)[0];
  const fund = w.attacker.utxos.toArray()[0];
  check("X2 top-up inside a post: extra wallet input, all of it lands in the successor, no owner key",
    run(w, qpost(w, cb, qOracle(w, 0), { extraInputs: [new ErgoUnsignedInput(fund)], succValue: cb.value + fund.value - POST_FEE }), [w.hot[0], w.attacker]), true);
}

// ───────────────────────────── F: refresh-fee path (context var 1 = 1) ─────────────────────────────
// Refresh-shaped fee spend (the pool box is the TEST-ONLY stand-in above; no refresh contract runs here):
//   INPUTS  = [...lead, pool, oracle (collected via the valuefix collection path), authority (ctx var 1 = 1), ...extraInputs]
//   OUTPUTS = [...leadOutputs, pool', oracle' (reward + 1, R4 only), authority' (R7 kept, R8 = stamp), ...extraOutputs, minerFee]
// loss = what the authority box gives up (default POST_FEE); fee = the miner-fee box (default = loss). Leftover -> changeTo.
const MAX_REFRESH_FEE = BigInt(srcConst("maxRefreshFee"));
const poolBox = (w) => w.poolParty.utxos.toArray()[0];
function fpost(w, { loss = POST_FEE, fee, stamp, value, assets, r4, r5, r6, r7, r8, var1 = 1, withPool = true, withOracle = true,
                    oracleRewrite = false, lead = [], leadOutputs = [], extraInputs = [], extraOutputs = [], changeTo = w.attacker.address,
                    height = w.chain.height, cb = companionBox(w), ob = withOracle ? oracleBox(w) : undefined, pb = withPool ? poolBox(w) : undefined } = {}) {
  const inputs = [...lead], outputs = [...leadOutputs];
  const collected = withOracle && !oracleRewrite;
  if (withPool) {
    inputs.push(new ErgoUnsignedInput(pb));
    outputs.push(new OutputBuilder(pb.value, pb.ergoTree).addTokens([pb.assets[0],
      { tokenId: pb.assets[1].tokenId, amount: BigInt(pb.assets[1].amount) - (collected ? 1n : 0n) }]));
  }
  if (withOracle) {
    const idx = inputs.length;
    inputs.push(oracleIn(ob, idx));
    // collected: reward + 1, R4 only (the collection path). oracleRewrite: same tokens and value, a NEW datapoint in R5/R6
    // (the oracle contract's companion path, which only asks for the authority box among the inputs).
    outputs.push(oracleRewrite ? oracleOut(ob, { prices: [666n, 666n], epoch: 99 })
      : new OutputBuilder(ob.value, ob.ergoTree).addTokens([ob.assets[0], { tokenId: ob.assets[1].tokenId, amount: BigInt(ob.assets[1].amount) + 1n }])
        .setAdditionalRegisters({ R4: ob.additionalRegisters.R4 }));
  }
  const ci = new ErgoUnsignedInput(cb);
  if (var1 !== undefined) ci.setContextExtension({ 1: SInt(var1) });
  inputs.push(ci);
  outputs.push(successorOf(w, cb, { value: value ?? cb.value - loss, assets, r4, r5, r6,
    r7: r7 ?? cb.additionalRegisters.R7, r8: r8 ?? SInt(stamp ?? height) }));
  return buildSF(w, { inputs: [...inputs, ...extraInputs], outputs: [...outputs, ...extraOutputs], fee: fee === undefined ? loss : fee, changeTo, height });
}
const feeWorld = (o = {}) => world({ gate: "hotkey", oracleSrc: ORACLE_V2_VALUEFIX_SRC, pool: true, ...o });
const shapeOf = (w, tx) => { const o = tx.toEIP12Object(); return `inputs=[${o.inputs.map((b) => kindOf(w, b.ergoTree))}] outputs=[${o.outputs.map((b) => kindOf(w, b.ergoTree))}]`; };
// TEST-ONLY variants of the real contract with exactly one fee-path check switched off (each replacement must apply once).
const variantTree = (from, to) => {
  if (HOT_KEY_SRC.split(from).length !== 2) throw new Error(`variant fragment not found exactly once: ${from}`);
  return authTreeOf(HOT_KEY_SRC.replace(from, to));
};

section("F. REFRESH FEE path (posting key signs, context var 1 = 1 on the authority input): stand-in pool controls and attacks; no refresh contract accepts this branch yet");
info(`maxRefreshFee = ${MAX_REFRESH_FEE} (parsed from the contract); pool box = TEST-ONLY stand-in at INPUTS(0); no refresh contract is executed`);
{
  const w = feeWorld();
  const cb = companionBox(w);
  const tx = fpost(w);
  attack(w, "F1 refresh fee against a STAND-IN pool (no refresh contract accepts the fee branch yet): pool NFT box at INPUTS(0), oracle collected, authority var 1 = 1, R8 := stamp, loss = miner fee, posting key only", tx, [w.server], true);
  const s = companionBox(w);
  out.push(`      ${shapeOf(w, tx)}  authority ${cb.value} -> ${s.value} (miner fee ${sumFee([tx])}); R7 ${stampOf(cb, "R7")} -> ${stampOf(s, "R7")}, R8 ${stampOf(cb, "R8")} -> ${stampOf(s, "R8")}`);
}
{
  const w = feeWorld();
  checkWhy(w, "F1 control: identical tx, nobody signs", fpost(w), [], false);
}
{
  const w = feeWorld();
  attack(w, `F1b refresh fee (stand-in pool) paying the whole cap (loss = fee = ${MAX_REFRESH_FEE})`, fpost(w, { loss: MAX_REFRESH_FEE }), [w.server], true);
}
{
  // A top-up inside the fee spend: the successor ends up richer than SELF (loss < 0); allowed.
  const w = feeWorld();
  const cb = companionBox(w), donor = w.attacker.utxos.toArray()[0];
  attack(w, "F1c refresh fee with a top-up inside the tx (successor value > SELF; the donor's ERG lands in the successor)",
    fpost(w, { value: cb.value + donor.value - POST_FEE, fee: POST_FEE, extraInputs: [donor] }), [w.server, w.attacker], true);
}
{
  const w = feeWorld();
  attack(w, `F2 refresh fee over the cap: loss = fee = ${MAX_REFRESH_FEE + 1n} (control: F1b)`, fpost(w, { loss: MAX_REFRESH_FEE + 1n }), [w.server], false);
}
{
  // MockChain mines one block per accepted tx, so the next tx is built at tip h+1.
  const w = feeWorld();
  const h = w.chain.height;
  attack(w, "F3 setup: honest refresh fee at tip h (R8 := h)", fpost(w), [w.server], true);
  attack(w, `F3 two refresh fee spends inside one epoch: the second, at tip h+${w.chain.height - h} (R8 = h+${w.chain.height - h} < h + ${EPOCH}), is rejected`,
    fpost(w), [w.server], false);
  w.chain.newBlocks(h + EPOCH - w.chain.height);
  attack(w, `F3 control: the same spend at tip h+${w.chain.height - h} (R8 = h + ${EPOCH}) is accepted`, fpost(w), [w.server], true);
}
{
  // Fee-stamp window. Idle box (R8 far in the past), so only the HEIGHT window can reject.
  const idleFee = () => feeWorld({ companionHeight: HC, oracleHeight: HC, fundHeight: HC });
  let w = idleFee();
  attack(w, "F4a refresh fee with R8 = HEIGHT + 1 (future-dated fee stamp)", fpost(w, { stamp: w.chain.height + 2 }), [w.server], false);
  w = idleFee();
  attack(w, "F4a control: R8 = HEIGHT", fpost(w, { stamp: w.chain.height + 1 }), [w.server], true);
  w = idleFee();
  attack(w, `F4b refresh fee with R8 = HEIGHT - ${SLACK + 1} (older than the slack window)`, fpost(w, { stamp: w.chain.height + 1 - SLACK - 1 }), [w.server], false);
  w = idleFee();
  attack(w, `F4b control: R8 = HEIGHT - ${SLACK}`, fpost(w, { stamp: w.chain.height + 1 - SLACK }), [w.server], true);
  w = idleFee();
  attack(w, "F4c refresh fee with R8 not advanced (= SELF.R8)", fpost(w, { r8: SInt(HC) }), [w.server], false);
}
{
  const w = feeWorld();
  attack(w, "F5 refresh fee that also advances the post stamp R7 (a post-lock reset riding on the fee spend)",
    fpost(w, { r7: SInt(w.chain.height) }), [w.server], false);
  attack(w, "F5b refresh fee that writes a wrong-typed R7 (Coll[Byte])", fpost(w, { r7: bytes(fakeId(0xff)) }), [w.server], false);
}
{
  const w = feeWorld();
  attack(w, "F6a refresh fee rewrites R4 (owner key) to the thief's key", fpost(w, { r4: SGroupElement(w.attacker.key.publicKey) }), [w.server], false);
  attack(w, "F6b refresh fee rebinds R5 to another oracle-token id", fpost(w, { r5: bytes(ORACLE_TOKEN_2) }), [w.server], false);
  attack(w, "F6c refresh fee rewrites R6 (posting key) to the thief's key", fpost(w, { r6: SGroupElement(w.attacker.key.publicKey) }), [w.server], false);
}
{
  const w = feeWorld({ companionExtraAssets: [{ tokenId: EXTRA_TOKEN, amount: 5n }] });
  // The extra tokens leave with the thief's change; the thief's own box carries them (ERG for the change box).
  attack(w, "F7 refresh fee drops the extra tokens from the successor (to the thief's change box)",
    fpost(w, { assets: [{ tokenId: COMPANION_NFT, amount: 1n }], extraInputs: w.attacker.utxos.toArray() }), [w.server, w.attacker], false);
  attack(w, "F7 control: same world, successor keeps the full token list", fpost(w), [w.server], true);
}
{
  const w = feeWorld();
  attack(w, `F8 miner fee < loss: authority loses ${MAX_REFRESH_FEE}, miner fee ${POST_FEE}, the ${MAX_REFRESH_FEE - POST_FEE} difference to a thief change box`,
    fpost(w, { loss: MAX_REFRESH_FEE, fee: POST_FEE }), [w.server], false);
}
{
  const w = feeWorld();
  const donor = w.attacker.utxos.toArray()[0];
  attack(w, "F9 thief adds its own input and takes exactly its value back in a change box; miner fee = loss: accepted, nets nothing",
    fpost(w, { extraInputs: [donor], extraOutputs: [new OutputBuilder(donor.value, w.attacker.address)] }), [w.server, w.attacker], true);
}
{
  const w = feeWorld();
  const donor = w.attacker.utxos.toArray()[0];
  checkWhy(w, "F10a no pool box: INPUTS(0) is the thief's token-less wallet box (returned): rejected, and the guarded INPUTS(0) read does not throw (reduced: companion = owner)",
    fpost(w, { withPool: false, withOracle: false, lead: [donor], leadOutputs: [new OutputBuilder(donor.value, w.attacker.address)] }), [w.server, w.attacker], false);
  w.attacker.addBalance({ nanoergs: SAFE_MIN_BOX_VALUE, tokens: [{ tokenId: EXTRA_TOKEN, amount: 1n }] });
  const tokBox = w.attacker.utxos.toArray().find((b) => b.assets.length);
  attack(w, "F10b no pool box: INPUTS(0) carries a token that is not the pool NFT", fpost(w, { withPool: false, withOracle: false, lead: [tokBox],
    leadOutputs: [new OutputBuilder(tokBox.value, w.attacker.address).addTokens(tokBox.assets)] }), [w.server, w.attacker], false);
}
{
  // The second-post attack the pool-NFT check exists for: a fee spend in a NON-pool tx, plus the owner's oracle box,
  // which passes through the oracle contract's companion path (authority box present, same R4) with a new datapoint.
  const rewrite = (w) => spost(w, { prices: [666n, 666n], epoch: 99, companionExt: { 1: SInt(1) },
    succR7: companionBox(w).additionalRegisters.R7, succR8: SInt(w.chain.height) });
  const w = feeWorld();
  attack(w, "F11 refresh-fee path used to rewrite the owner's oracle box via the oracle's companion path in a non-pool tx (a second post per period)",
    rewrite(w), [w.server], false);
  const vtree = variantTree("val inPoolTx = firstTokenId == poolNftId", "val inPoolTx = true");
  const wv = feeWorld({ companionTreeOverride: vtree });
  const before = oracleBox(wv).additionalRegisters.R6;
  attack(wv, "F11 FINDING (contrast, TEST-ONLY variant without the pool-NFT check): the same rewrite is accepted — the posting key writes a datapoint the post lock never saw",
    rewrite(wv), [wv.server], true);
  out.push(`      variant ${vtree.length / 2} B; oracle R6 ${before} -> ${oracleBox(wv).additionalRegisters.R6}`);
}
{
  // KNOWN LIMIT outside this contract: inside a pool-NFT tx the owner's oracle box can still pass through the oracle
  // contract's companion path (new datapoint, same tokens and value) instead of being collected. Neither the authority
  // contract nor the oracle contract refuses that; the pool's refresh contract must (RefreshContractKeyless.es pins every
  // oracle-token input to R4-only + reward +2; the deployed RefreshContract.es does not). The stand-in pool here does not.
  const w = feeWorld();
  attack(w, "F11b KNOWN LIMIT (outside this contract): in a pool-NFT tx the fee spend lets the owner's oracle box take a NEW datapoint via the companion path; only the pool's refresh contract can refuse it",
    fpost(w, { oracleRewrite: true }), [w.server], true);
}
{
  // Two authority boxes, one shared NFT id and one shared posting key: merge into ONE successor, box #1's ERG -> miner fee.
  const w = fourWorld({ nft: "shared", hot: "shared", pool: true });
  const [a0, a1] = qAuthAll(w), pb = poolBox(w);
  const b = new TransactionBuilder(w.chain.height)
    .from([new ErgoUnsignedInput(pb), new ErgoUnsignedInput(a0).setContextExtension({ 1: SInt(1) }), new ErgoUnsignedInput(a1).setContextExtension({ 1: SInt(1) })], { ensureInclusion: true })
    .to([new OutputBuilder(pb.value, pb.ergoTree).addTokens(pb.assets),
         successorOf(w, a0, { value: a0.value - POST_FEE, r7: a0.additionalRegisters.R7, r8: SInt(w.chain.height) })])
    .sendChangeTo(w.attacker.address).payFee(a1.value + POST_FEE);
  b.burnTokens({ tokenId: COMPANION_NFT, amount: 1n });
  attack(w, `F12a shared NFT + shared key: MERGE two authority boxes through the fee path (box #1's ${a1.value} -> miner fee): rejected (NFT-input check)`, b.build(), [w.server], false);
}
{
  // Distinct NFTs (each box passes its NFT-input check), one shared posting key: both boxes take the fee path and each
  // counts the SAME miner-fee box as covering its own loss; the second loss leaves as change to the thief.
  const doubleCount = (w, fee) => {
    const a0 = qAuth(w, 0), a1 = qAuth(w, 1), pb = poolBox(w);
    return buildSF(w, {
      inputs: [new ErgoUnsignedInput(pb), new ErgoUnsignedInput(a0).setContextExtension({ 1: SInt(1) }), new ErgoUnsignedInput(a1).setContextExtension({ 1: SInt(1) })],
      outputs: [new OutputBuilder(pb.value, pb.ergoTree).addTokens(pb.assets),
                successorOf(w, a0, { value: a0.value - MAX_REFRESH_FEE, r7: a0.additionalRegisters.R7, r8: SInt(w.chain.height) }),
                successorOf(w, a1, { value: a1.value - MAX_REFRESH_FEE, r7: a1.additionalRegisters.R7, r8: SInt(w.chain.height) })],
      fee });
  };
  const w = fourWorld({ nft: "distinct", hot: "shared", pool: true });
  attack(w, `F12b distinct NFTs + shared key: two fee spends share ONE miner fee (${MAX_REFRESH_FEE}); the other ${MAX_REFRESH_FEE} -> thief change: rejected (only input at this script)`,
    doubleCount(w, MAX_REFRESH_FEE), [w.server], false);
  const vtree = variantTree("val oneScriptInput = INPUTS.filter { (b: Box) =>\n        b.propositionBytes == SELF.propositionBytes\n      }.size == 1",
    "val oneScriptInput = true");
  const wv = fourWorld({ nft: "distinct", hot: "shared", pool: true, tree: vtree });
  const before = holdings(wv);
  const tx = doubleCount(wv, MAX_REFRESH_FEE);
  const got = run(wv, tx, [wv.server]);
  check(`F12b FINDING (contrast, TEST-ONLY variant = the spec's checks without "only input at this script"): the double-count is accepted`, got, true);
  record(`F12b (contrast, TEST-ONLY variant without the one-script-input check) double-counted miner fee`, before, holdings(wv), got, tx, { expectGain: true });
  const w2 = fourWorld({ nft: "distinct", hot: "shared", pool: true });
  checkWhy(w2, `F12c KNOWN LIMIT (deliberate): two fee spends paying ${2n * MAX_REFRESH_FEE} in full are rejected too — one authority fee spend per tx`,
    doubleCount(w2, 2n * MAX_REFRESH_FEE), [w2.server], false);
}

section("F. owner path with missing / wrong-typed stamps; migration");
{
  const w = world({ gate: "hotkey", stampRegs: "none" });
  check("F13a owner reclaims a box with NO R7/R8 (the pre-stamp layout)", run(w, ownerTx(w, { mode: "reclaim" }), [w.owner]), true);
  const w2 = world({ gate: "hotkey", stampRegs: "none" });
  check("F13a owner rotates IN PLACE a box with NO R7/R8 (same-script successor, R6 := new key)",
    run(w2, ownerTx(w2, { mode: "rotate", newR6: SGroupElement(w2.server2.key.publicKey) }), [w2.owner]), true);
}
{
  const wrong = { R7: bytes(fakeId(0x07)).toHex(), R8: SLong(5n).toHex() };
  const w = world({ gate: "hotkey", stampRegs: wrong });
  check("F13b owner reclaims a box with wrong-typed R7 (Coll[Byte]) and R8 (Long)", run(w, ownerTx(w, { mode: "reclaim" }), [w.owner]), true);
  const w2 = world({ gate: "hotkey", stampRegs: wrong });
  check("F13b owner rotates IN PLACE a box with wrong-typed R7/R8", run(w2, ownerTx(w2, { mode: "rotate", newR6: SGroupElement(w2.server2.key.publicKey) }), [w2.owner]), true);
}
{
  const w = feeWorld({ stampRegs: "none" });
  attack(w, "F13c posting key posts from a box with NO R7/R8 (SELF.R7 read throws inside the guard)", spost(w), [w.server], false);
  attack(w, "F13c posting key takes the fee path on a box with NO R7/R8 (SELF.R8 read throws inside the guard)",
    fpost(w, { r7: SInt(w.chain.height) }), [w.server], false);
  // Migration: the owner writes R7/R8 in place; the posting key can then post.
  check("F13d migration: owner rewrites the box in place adding R7 = R8 = Int stamps",
    run(w, ownerTx(w, { mode: "custom", outputs: (cb) => new OutputBuilder(cb.value, w.companionTree).addTokens(cb.assets)
      .setAdditionalRegisters({ ...cb.additionalRegisters, R7: SInt(H0 - EPOCH), R8: SInt(H0 - EPOCH) }) }), [w.owner]), true);
  attack(w, "F13d ... and the posting key posts from the migrated box", spost(w), [w.server], true);
}

section("F. the two stamps are independent: a refresh fee spend does not move the posting lock");
{
  // Default world: R7 = R8 = h - EPOCH. MockChain mines one block per accepted tx, so each tx below is built at the
  // next tip. Under the old creation-height lock the fee spend at h+1 would have recreated the box and pushed the next
  // post to >= h+1+EPOCH.
  const w = feeWorld();
  const h = w.chain.height;
  const at = () => `h+${w.chain.height - h}`;
  attack(w, "F14a post at tip h (R7 := h)", spost(w), [w.server], true);
  const feeAt = w.chain.height;
  attack(w, `F14b refresh fee right after the post, at tip ${at()} (R8 := ${at()}; R7 and the post lock untouched; box recreated at ${at()})`, fpost(w), [w.server], true);
  attack(w, `F14c a post at tip ${at()} is still rejected: too soon after the PREVIOUS POST (the fee spend neither resets nor bypasses the post lock)`,
    spost(w, { prices: [2n, 2n] }), [w.server], false);
  w.chain.newBlocks(h + EPOCH - w.chain.height);
  const ok = feeAt + EPOCH > w.chain.height;   // this tip would fail the old creation-height lock
  attack(w, `F14d post at tip ${at()}: ${EPOCH} blocks after the previous post, ${w.chain.height - feeAt} after the fee spend that recreated the box — accepted` +
    (ok ? ` (the old creation-height lock would have refused it until h+${feeAt + EPOCH - h})` : " (HARNESS: does not separate old/new lock)"),
    spost(w, { prices: [3n, 3n] }), [w.server], ok);
  const s = companionBox(w);
  out.push(`      authority box now: created h+${s.creationHeight - h}, R7 = h+${stampOf(s, "R7") - h}, R8 = h+${stampOf(s, "R8") - h}`);
}
{
  const w = feeWorld();
  attack(w, "F14e refresh fee at tip h", fpost(w), [w.server], true);
  attack(w, "F14e ... and a post immediately after it (next block: MockChain mines one block per tx; the post stamp is untouched by the fee spend): accepted", spost(w), [w.server], true);
}
{
  const w = feeWorld();
  attack(w, "F15a post with context var 1 = 0 (any Int other than 1 selects the post path): accepted", spost(w, { companionExt: { 1: SInt(0) } }), [w.server], true);
  const w2 = feeWorld();
  attack(w2, "F15b post-shaped tx with context var 1 = 1 (selects the fee path; no pool NFT at INPUTS(0)): rejected", spost(w2, { companionExt: { 1: SInt(1) } }), [w2.server], false);
}
{
  // Worst case per authority box per day: a greedy thief with the posting key posts AND takes the fee path as often as the
  // two stamps allow (oldest stamp max(SELF + EPOCH, HEIGHT - SLACK) on each), paying the full cap on each spend.
  // Every fee spend sits in a refresh-shaped tx with the pool stand-in (in reality one valid refresh per spend is needed).
  const DAY = 720;
  const w = feeWorld({ companionHeight: HC, oracleHeight: HC, fundHeight: HC, companionValue: 2n * ERG });
  const start = w.chain.height, before = holdings(w), txs = [];
  let posts = 0, fees = 0;
  while (w.chain.height + 1 <= start + DAY) {
    const HEIGHT = w.chain.height + 1;
    let moved = false;
    let cb = companionBox(w);
    const ps = Math.max(stampOf(cb, "R7") + EPOCH, HEIGHT - SLACK);
    if (ps <= HEIGHT) {
      const tx = spost(w, { prices: [BigInt(HEIGHT), 1n], succStamp: ps, succValue: cb.value - MAX_FEE_PER_EPOCH, fee: MAX_FEE_PER_EPOCH, cb });
      if (run(w, tx, [w.server]) === "ACCEPTED") { txs.push(tx); posts++; moved = true; }
    }
    cb = companionBox(w);
    const fs = Math.max(stampOf(cb, "R8") + EPOCH, HEIGHT - SLACK);
    if (fs <= HEIGHT) {
      const tx = fpost(w, { stamp: fs, loss: MAX_REFRESH_FEE, withOracle: false, cb });
      if (run(w, tx, [w.server]) === "ACCEPTED") { txs.push(tx); fees++; moved = true; }
    }
    if (!moved) w.chain.newBlock();
  }
  const bound = 1 + Math.floor((DAY - 1 + SLACK) / EPOCH);
  const burned = sumFee(txs), cap = BigInt(bound) * (MAX_FEE_PER_EPOCH + MAX_REFRESH_FEE);
  const bad = posts > bound || fees > bound || burned > cap;
  check(`F16 greedy thief over ${DAY} blocks, posts + refresh fees at the full caps: more than ${bound} of either or > ${bound} x (maxFeePerEpoch + maxRefreshFee) = ${cap} burned`,
    bad ? `ACCEPTED (posts ${posts}, fee spends ${fees}, ${burned} burned)` : `REJECTED (posts ${posts}, fee spends ${fees}, ${burned} nanoERG burned to miners = ${Number(burned) / 1e9} ERG/day)`, false);
  record(`F16 greedy thief, ${posts} posts + ${fees} fee spends in ${DAY} blocks at the full caps`, before, holdings(w), `ACCEPTED (${posts + fees} spends)`, txs);
}

// ───────────────────────────── Thief ledger ─────────────────────────────
section("THIEF LEDGER: thief = server hot key + rotated key + attacker wallet; want dERG <= 0 and every dToken <= 0");
{
  const tokName = { [ORACLE_TOKEN]: "ORACLE", [REWARD_TOKEN]: "REWARD", [EXTRA_TOKEN]: "EXTRA", [COMPANION_NFT]: "NFT", [WALLET_TOKEN]: "WALLET" };
  for (const r of ledger) {
    const gain = r.dErg > 0n || Object.values(r.dTok).some((d) => d > 0n);
    const toks = Object.entries(r.dTok).map(([id, d]) => `${tokName[id] ?? id.slice(0, 8)}:${d}`).join(",") || "none";
    const status = r.got.startsWith("ACCEPTED") ? `accepted, miner fee in tx ${r.fee}` : "rejected";
    const label = r.expectGain ? "FINDING (contrast) " : gain ? "FINDING " : "";
    out.push(`${gain === r.expectGain ? "PASS" : "FAIL"}  LEDGER ${label}${r.name}\n` +
      `      want=${r.expectGain ? "thief nets value" : "thief nets nothing"}  got=dERG=${r.dErg} dTokens=${toks} (${status})`);
  }
}

const passed = out.filter((l) => l.startsWith("PASS")).length;
const total = out.filter((l) => l.startsWith("PASS") || l.startsWith("FAIL")).length;
const text = `SUMMARY ${passed}/${total} checks matched expectation\n` + out.join("\n") + "\n";
writeFileSync(new URL("./probe.result", import.meta.url), text);
console.log(text);
