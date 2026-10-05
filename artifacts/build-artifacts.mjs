// artifacts/build-artifacts.mjs — the compiler of record and the pinned contract trees.
//
//   node artifacts/build-artifacts.mjs           writes artifacts/manifest.json and artifacts/*.hex
//   node artifacts/build-artifacts.mjs --check   recompiles and exits 1 if anything differs
//
// Compiler of record: @fleet-sdk/compiler 0.12.0 (sigmastate-js 0.4.6), default options, which
// emits ErgoTree version 1 with segregated constants (header 0x19). The versions are pinned
// exactly in package.json and package-lock.json. The trees that ran on mainnet were built the
// same way (mainnet-smoke/smoke.mjs).
//
// The trees are TEMPLATES: pool and NFT ids are placeholders (32 x 0xa1 for poolNftId, 32 x 0xa2
// for authorityNftId). A deployment substitutes its own ids at the constant positions listed in
// the manifest; the byte layout is otherwise fixed. The authority template's blake2b256 is NOT
// what the oracle pins in a deployment: the deployed authority tree carries the real poolNftId,
// so the oracle's authorityScriptHash must be recomputed from the substituted authority tree.

import { readFileSync, writeFileSync } from "fs";
import { compile } from "@fleet-sdk/compiler";
import { SInt, SColl, SByte } from "@fleet-sdk/serializer";
import { blake2b256, hex } from "@fleet-sdk/crypto";

const ROOT = new URL("../", import.meta.url);
const OUT = new URL("./", import.meta.url);
const src = (f) => readFileSync(new URL(f, ROOT), "utf-8");
// Read the installed version straight from node_modules (the packages do not export package.json).
const ver = (p) => JSON.parse(readFileSync(new URL(`node_modules/${p}/package.json`, ROOT), "utf-8")).version;

const EPOCH_LENGTH = 5;
const POOL_NFT = new Uint8Array(32).fill(0xa1);
const AUTH_NFT = new Uint8Array(32).fill(0xa2);
const bytesC = (b) => SColl(SByte, b);

const describe = (tree) => {
  const bytes = hex.decode(tree.toHex());
  return {
    size: bytes.length,
    header: tree.toHex().slice(0, 2),
    blake2b256: hex.encode(blake2b256(bytes)),
    constants: tree.constants.map((c, i) => ({ index: i, type: c.type.toString(), value: hex.encode(c.toBytes()) })),
    hex: tree.toHex(),
  };
};

const authority = compile(src("CompanionAuthorityHotKey.es"), {
  map: { epochLength: SInt(EPOCH_LENGTH), poolNftId: bytesC(POOL_NFT) },
});
const authorityHash = blake2b256(hex.decode(authority.toHex()));
const oracle = compile(src("OracleContractV2-valuefix.es"), {
  map: { poolNftId: bytesC(POOL_NFT), authorityNftId: bytesC(AUTH_NFT), authorityScriptHash: bytesC(authorityHash) },
});

const manifest = {
  compiler: { package: "@fleet-sdk/compiler", version: ver("@fleet-sdk/compiler"), sigmastateJs: ver("sigmastate-js"),
              options: "defaults (ErgoTree v1, segregated constants)" },
  placeholders: { poolNftId: hex.encode(POOL_NFT), authorityNftId: hex.encode(AUTH_NFT) },
  compileConstants: { CompanionAuthorityHotKey: { epochLength: EPOCH_LENGTH, poolNftId: "placeholder" },
                      OracleContractV2_valuefix: { poolNftId: "placeholder", authorityNftId: "placeholder",
                                                   authorityScriptHash: "blake2b256 of the authority tree above" } },
  sources: { CompanionAuthorityHotKey: hex.encode(blake2b256(new TextEncoder().encode(src("CompanionAuthorityHotKey.es")))),
             OracleContractV2_valuefix: hex.encode(blake2b256(new TextEncoder().encode(src("OracleContractV2-valuefix.es")))) },
  trees: { CompanionAuthorityHotKey: describe(authority), OracleContractV2_valuefix: describe(oracle) },
};

const text = JSON.stringify(manifest, null, 2) + "\n";
const files = { "manifest.json": text,
                "CompanionAuthorityHotKey.template.hex": manifest.trees.CompanionAuthorityHotKey.hex + "\n",
                "OracleContractV2-valuefix.template.hex": manifest.trees.OracleContractV2_valuefix.hex + "\n" };

if (process.argv.includes("--check")) {
  let bad = 0;
  for (const [name, body] of Object.entries(files)) {
    let have = "";
    try { have = readFileSync(new URL(name, OUT), "utf-8"); } catch {}
    if (have !== body) { console.log(`DIFFERS  ${name}`); bad++; } else console.log(`same     ${name}`);
  }
  process.exit(bad ? 1 : 0);
} else {
  for (const [name, body] of Object.entries(files)) writeFileSync(new URL(name, OUT), body);
  for (const [k, t] of Object.entries(manifest.trees)) console.log(`${k}: ${t.size} B  blake2b256 ${t.blake2b256}`);
}
