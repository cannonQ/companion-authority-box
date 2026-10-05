# Authority box invariants

What `CompanionAuthorityHotKey.es` and `OracleContractV2-valuefix.es` guarantee together, what they
don't, and the setup rules those guarantees depend on. Every invariant names the test sections that
pin it (`probe.test.mjs`, unless another suite is named). If an invariant here and the contract
disagree, the contract is right and this file is wrong.

## Keys

- **Owner key** (authority R4 = oracle R4): kept offline. Can do anything with both boxes.
- **Posting key** (authority R6): on the operator's server. It can spend ERG, but only within the
  limits below, and only to miners. It can never send ERG or tokens to an address it chooses.

## What a stolen posting key CANNOT do

| # | Invariant | Why it holds | Pinned by |
|---|---|---|---|
| I1 | Change the oracle box's R4 (owner key), so it cannot take the seat | Oracle companion path requires successor R4 == R4; posting branch checks it too | section B (stolen hot key; oracle companion path) |
| I2 | Move the oracle token, the reward tokens or the authority NFT anywhere else | Both contracts pin the full token list on their non-owner paths | section B (stolen hot key), section Q |
| I3 | Take ERG out of the oracle box | Successor value must not fall (companion path); passThrough (posting branch) | section B (oracle companion path) |
| I4 | Send the authority box's ERG to any address it chooses (given setup rule 2) | Posting branch: every other output is a miner-fee box. Fee branch: miner-fee outputs must total at least the box's loss, and only one input may sit at this script | section F (F12, F12b, F12c) |
| I5 | Spend more than the caps | Post: at most 0.002 ERG per post, posts at least epochLength apart (R7 stamp). Fee branch: at most 0.002 ERG per spend, at least epochLength apart (R8 stamp). Both stamps must lie in [HEIGHT − mempoolSlack, HEIGHT] | E1 rows (post-stamp lock), section F |
| I6 | Exceed 0.58 ERG/day burn from one authority box (lock 5, slack 4: 145 posts + 145 fee spends × 0.002 ERG) | Follows from I5; measured | E1e, F16 |
| I7 | Post into another operator's oracle box | Oracle R4 must equal authority R4; the oracle script compiles in this operator's authority NFT id | section B (cross-oracle attacks), X1 (why each operator mints their own NFT) |
| I8 | Block the owner path | Typed register reads sit behind structural guards; a box with missing or wrong-typed R7/R8 stays owner-spendable | section B (owner-path liveness), section F (missing / wrong-typed stamps) |
| I9 | Use the fee branch outside a pool transaction | The fee branch requires the pool NFT at INPUTS(0) | section F |

**Status of the refresh-fee branch:** no refresh contract accepts it yet. The keyless refresh written so
far (AVL, not public) requires every non-oracle output to keep its input's value, so an authority box
that paid a fee is rejected there. The section F rows run against a stand-in pool box. The EIP-23 keyless
refresh (next) has to be written to accept it.

## What a stolen posting key CAN do (until the owner's recovery transaction)

- Post wrong datapoints into the operator's own oracle box, at the posting rate.
- Post first in each window and lock out the honest daemon (they share the rate limit).
- Write registers the contracts leave free (oracle R5 onward, e.g. R7 = a refresh key of its choice; authority R9).
- Burn up to the caps in I6 to miners.
- Leave junk that makes the oracle box uncollectable until the owner or the next honest post rewrites it.
- Act as a refresher wherever the pool's refresh contract accepts its R7 key (the blast radius depends on that refresh contract, not on these two).

## Recovery

One owner-signed transaction: give the authority box a new posting key (R6), and rewrite the oracle
box through its owner path (clear or rewrite R5 onward). Both contracts allow this today. Not yet a
test row.

## Setup rules the invariants depend on

1. **One authority NFT per operator, minted as exactly one unit straight into the authority box.** A
   loose unit lets someone plant a rate-limited poster for that operator's box (open audit Medium).
2. **One authority box per posting key.** I4's fee-branch argument assumes no other box under the same
   posting key, on a different script, sits in the same transaction. Two boxes on different scripts
   (another `epochLength`, another compiler, an old box during a migration) could both count one miner
   fee, and the second box's loss (up to 0.002 ERG per stamp window) would leave as change to the thief.
   Rotate an old box's R6 before replacing it. A structural fix (each box needs its own fee output,
   tagged with its box id) is an option for the next contract round, untested.
3. **Never send plain ERG to the authority script.** A box without the authority registers can never be
   spent. Top up through a post or a fee spend.
4. **The pool's refresh and update transactions decide what happens to oracle boxes inside them.**
   The fee branch only guarantees the authority box's side. Inside a pool transaction, the oracle box can
   still pass through the companion path unless the refresh/update contract pins oracle successors.
5. **The refresh box must not fund miner fees** in a transaction that uses the fee branch. Otherwise its
   ERG could cover the fee and free the authority box's loss as change. The keyless refresh design keeps
   the refresh box's value from falling.

## Not covered by these invariants

- The price: datapoints are only as good as the server's data source and the pool's aggregation.
- The refresh contract's own rules (fee source, pins, blast radius); see the refresh design.
- The owner key: anyone holding it controls both boxes.
