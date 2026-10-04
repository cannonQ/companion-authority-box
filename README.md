# Companion Authority Box: oracle posting with no spending key on the server

An Ergo oracle operator's server today holds the wallet mnemonic, so a hacked server can take everything that mnemonic controls. This repo is a design, test suite and mainnet test for an alternative. The server keeps one **posting key**. That key can update the operator's own oracle box and spend nothing else.

> **Status: proof of concept, for review. Not audited to a passing standard. Not in use on any live pool.**
> Posting worked on mainnet with dummy tokens on 2026-10-03. Refresh is not covered (see [Limits](#limits-and-open-questions)).

![What sits where](docs/what-sits-where.svg)

## How it works

Next to the oracle box sits an **authority box**. It holds a singleton NFT and the ERG that pays the posting fees.

| Register | Holds |
| :--- | :--- |
| R4 | owner key (kept cold) |
| R5 | oracle token id |
| R6 | posting key (the only key on the server) |

A post spends the oracle box and the authority box together, signed by the posting key. The authority contract allows that only if:

- the oracle box comes back with the same script, tokens and value, and its R4 matches the authority box's R4;
- the only other outputs are the authority box itself and a miner fee. There is no change output and no wallet input;
- the authority box gives up at most 0.002 ERG and keeps its NFT and registers;
- at least `epochLength` blocks (5) have passed since the last post, and the post is mined within about 4 blocks of being built.

The owner key can always rotate the posting key, refill the box, or reclaim it.

This needs a modified oracle contract. The oracle box accepts a post only when an authority box is among the inputs, meaning a box that holds the NFT, sits at the authority contract's script (checked by hash), and carries the same owner key as the oracle box. Each oracle box's output must sit at the same index as its input, and its token list and value must be unchanged. Existing oracle boxes cannot use it as they are.

The posting key is a plain secp256k1 secret generated on the server. It signs locally and never leaves the server. It is not derived from the owner's mnemonic and has no funded address. It is valid only because the owner key wrote its public half into R6.

![Daemon today vs new](docs/daemon-today-vs-new.svg)

### Why a signature and not a hash preimage

The original idea (April 2026, [`reference/CompanionAuthorityContract.es`](reference/CompanionAuthorityContract.es)) gated the authority box with a hash preimage. A preimage seen in the mempool can be replayed onto another transaction; `probe.test.mjs` part A reproduces that. A signature is bound to the exact transaction, so it cannot be lifted.

## Files

| Path | What it is |
| :--- | :--- |
| [`CompanionAuthorityHotKey.es`](CompanionAuthorityHotKey.es) | Authority contract, current version (audit fixes applied). Compile constant `epochLength` |
| [`OracleContractV2-valuefix.es`](OracleContractV2-valuefix.es) | Modified oracle contract, current version. Compile constants `poolNftId`, `authorityNftId`, `authorityScriptHash` |
| `*.pre-audit.es` | The exact versions that ran on mainnet on 2026-10-03, before the audit fixes |
| [`reference/`](reference/) | Earlier designs the suites compare against: the hash-preimage authority contract and the first companion-path oracle contract |
| [`probe.test.mjs`](probe.test.mjs) | Main suite: replay reproduction, stolen-posting-key attacks with a thief ledger, height-lock and fee-cap bounds, owner-path liveness |
| [`lift.test.mjs`](lift.test.mjs) | Cross-checks with real signatures (sigmastate-js prover, sigma-rust `validate_tx`) |
| [`mainnet-smoke/smoke.mjs`](mainnet-smoke/smoke.mjs) | The CLI that ran the mainnet test. Dry run by default; `--check` and `--broadcast` are explicit |
| `mainnet-smoke/state.json`, `mainnet-smoke/txs/` | Recorded state and signed transactions from the 2026-10-03 run (public keys and txids only) |
| [`mainnet-smoke/smoke.offline.test.mjs`](mainnet-smoke/smoke.offline.test.mjs) | Offline test of the CLI against a mock node, including a secrets-leak check |

## Running the tests

Node 18+. Dependencies are pinned, because interpreter versions matter.

```bash
npm ci
node probe.test.mjs                      # 244/244
node lift.test.mjs                       # 16/16
node mainnet-smoke/smoke.offline.test.mjs   # 50/50
```

All three are offline and need no node, wallet or keys. Each check states its expected outcome up front: "FINDING" marks an attack that is expected to be accepted, and "KNOWN LIMIT" marks a documented rejection. The probe and lift suites also write their output to `*.result`.

To repeat the mainnet test yourself, point `SMOKE_DIR` at an empty directory so the recorded run is left alone. Then run `NODE_URL=http://<your-node>:9053 node mainnet-smoke/smoke.mjs plan` and follow its printed steps. It makes throwaway keys in `$SMOKE_DIR/.keys.json` (mode 600, ignored by git). Never reuse a real wallet key.

## Mainnet test, 2026-10-03

Heights 1,886,816 to 1,886,833. Throwaway test address `9eu8UkTqEbZiymeeaDLAUckKYWh7b1Ybr966fEiHuhkLE1sRZD7`. 0.1 ERG in, 0.081 ERG back, 0.019 ERG net. These ran on the `*.pre-audit.es` contracts. Rejected transactions never reached the chain, so they do not show on an explorer; their signed JSON is in `mainnet-smoke/txs/`.

| # | Step | Result | Transaction ID |
| :---: | :--- | :--- | :--- |
| 1 | Mint dummy oracle token ×2 | mined 1,886,816 | e76fecde4f06a2898c5406b7abb51ec83f3fdc848c71322fa0dfec928811a7d5 |
| 2 | Mint dummy reward token ×10 | mined 1,886,816 | b5c5ff2f2e84bd4c633fdb3173dc3eac37ebebbef4cbb48963b359b8276c4e9e |
| 3 | Mint dummy authority NFT ×1 | mined 1,886,816 | fc9361ee6d77e4c570226542a58e61c3077cd05156ee200b13b2b2c81eaf4cb7 |
| 4 | Setup: oracle box + authority box | mined 1,886,816 | e05f6a650220e47a75ecb8f78b0f20d89043a4936dedd5d05f16f4df4612aa2b |
| 5 | First post, posting key only | mined 1,886,821 | c7fbad1b32c7036ae59cfb0c3b0e60203102612270311af192f9ae72d139702a |
| 6 | Bad post: before the 5-block lock | rejected, script false | 8bd2ebb1e84254f258c2adaf9e8ffb3503bbded1266bdefb21964cca39b7b200 |
| 7 | Bad post: extra output to the owner address | rejected, script false | fe95fa99ce9c4defc97d05b0f931e8aea58f6f832c3ad2a0114d6cd0bbfa6a08 |
| 8 | Bad post: 0.003 ERG fee, over the 0.002 cap | rejected, script false | 1b6a3a9409a7915d336375d590e8e7dcb65c247500d61bc882d41ff25f4511d7 |
| 9 | Second post, posting key only | mined 1,886,826 | 06607392304cd5bc62a222aa1114c4709ff623f4324d8264e4905e47e2d38694 |
| 10 | Rotate: owner key replaces the posting key | mined 1,886,828 | 84e530a1e05af0b21232495bdf97ba240b1789658ab57288c253890186c083bb |
| 11 | Bad post: signed with the old posting key | rejected, script false | 7dfb4b72618186836fd38d135de4256f8fd907e408852004241297b6c93b6791 |
| 12 | Third post, new posting key | mined 1,886,832 | 62623b07b1ba0001d728a8615a2ff4d5c2e3e6de74c7e68258f8c64faf6ff2e9 |
| 13 | Reclaim with the owner key | mined 1,886,833 | ee1f3f13fde4873ee4eca29dcd6556878dc753ed23cdf6e4d3ea38181f932382 |

A post is 1,560 bytes: inputs are the oracle box and the authority box, and outputs are the oracle box, the authority box (0.011 → 0.010 ERG) and a 0.001 ERG miner fee.

What this showed:

- **No wallet key is needed to post.** Three posts were mined, each signed only by a key that owns no box.
- **Miners include a script-paid fee with no change output.** All three posts landed inside their window at 0.001 ERG.
- **The limits hold on a real node.** Early posts, a change output, an over-cap fee and a rotated-out key were each rejected.
- **The owner key keeps control.** It rotated the posting key in place and reclaimed everything at the end.

## Limits and open questions

- **A stolen posting key is not harmless.** It can post wrong prices until the owner rotates it, and burn up to the fee cap per post to miners. It cannot move ERG or tokens to an address of its choosing.
- **Refresh is not covered.** Refresh still needs an oracle owner key, as in the standard refresh contract. A version without it exists only in a simulator and is not in this repo.
- **Audit status.** An EKB two-pass audit was run, and all High and Medium findings from it were fixed and re-tested. The re-audit found no High and **one Medium still open**: a stray authority NFT unit could let someone add one rate-limited poster until the owner seizes it. A setup rule covers it today (mint exactly one unit straight into the authority box). A tested contract fix is not applied yet, because it would burn the NFT on reclaim.
- **Token stranding.** The oracle contract pins the authority contract by script hash, so any change to the authority contract changes the oracle script. An oracle token can never leave its script, so tokens on the old script stay there. Options under discussion: move the lock, slack and fee cap into an authority-box register, and give the oracle contract an owner exit.
- **One oracle token stays behind in the test.** The dummy oracle box keeps 0.01 ERG and its oracle token for good, because the oracle contract never lets that token leave its script.
- **Adoption on an existing pool.** This means a new oracle contract (and new oracle tokens) plus a new refresh contract, introduced through the pool's update mechanism. The pool NFT stays the same. This comes from reading EIP-23 and oracle-core, not from a test against a deployed pool.

Review, attacks and counter-proposals are welcome. Please open an issue.
