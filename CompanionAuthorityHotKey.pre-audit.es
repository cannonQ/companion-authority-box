{
  // Companion Authority Box — scoped hot-key variant (PROBE CANDIDATE, not deployed)
  //
  // Diff from spikes/CompanionAuthorityContract.es: the blake2b256 preimage
  // gate on R6 is replaced by proveDlog of a posting-only key in R6. A
  // signature commits to the transaction bytes, so it cannot be lifted from
  // the mempool (or from chain history) onto a different transaction.
  //
  // Target property: whoever steals the hot key can move no ERG and no
  // tokens to an address of their choosing. The only value that can leave
  // this box is miner fee, at most maxFeePerEpoch per post. Successive
  // posts' creation heights step by >= epochLength, so any window of W
  // blocks holds at most 1 + (W - 1 + mempoolSlack) / epochLength posts
  // (one per epoch on average; idle epochs do not accumulate). The server
  // needs no wallet: a post spends only [oracle box, this box] and pays the
  // fee out of this box.
  //
  // Registers: R4 = owner key (GroupElement), R5 = bound oracle token id
  //            (Coll[Byte]), R6 = hot key (GroupElement). tokens(0) = NFT.
  //            Assumption: R4 is ALSO the bound oracle box's R4 (the oracle
  //            owner key). A post is accepted only against an oracle box
  //            whose R4 equals this box's R4.
  //
  // PATH A: Posting — proveDlog(hotKey) + the exact posting shape below.
  // PATH B: Owner (cold signature) — proveDlog(R4). Reclaim, rotate, destroy.
  //
  // Only R4 is read unconditionally. Every posting-only read sits inside an
  // `if` branch, which is evaluated lazily. A wrong-typed register read
  // THROWS, and a throw outside the guard kills PATH B as well (wave 1 L4b:
  // a box with a non-GroupElement R6 was unspendable even by the owner).
  // Reclaim and destroy always work. An in-place rotate needs a well-typed
  // R5: SELF.R5 is read as soon as the tx has exactly one same-script output
  // carrying the NFT, so a missing or wrong-typed R5 blocks an in-place
  // rotate even with the cold key (review R1); reclaim such a box instead.
  //
  // A post also requires exactly one INPUT holding this box's NFT id at
  // tokens(0) (this box). Without it, two authority boxes sharing one NFT id
  // and one hot key could be merged into a single successor and the second
  // box's ERG would leave as miner fee (probe Q4). The check is a pure filter
  // inside the posting branch: it cannot throw and never touches PATH B.
  //
  // Oracle output registers R5+ are deliberately unpinned; R7 must stay
  // writable by the post (RefreshContractKeyless.es reads it); a key written
  // there by a stolen hot key survives a hot-key rotation until that oracle
  // box is reposted or collected.
  //
  // BUILDER RULES (off-chain; the contract cannot enforce them):
  //  - the posting builder selects oracle boxes by known box id, or validates
  //    shape first (tokens.size >= 2, tokens(1) = reward id, value >= oracle
  //    minimum, typed R4 = owner); a malformed box at the oracle script with
  //    R4 = owner makes the post fail (multi.test.mjs BUILDER RULE rows);
  //  - the multi builder keeps oracle outputs in input order;
  //  - owner tooling builds rotates from an explicit input list (authority
  //    box + plain ERG boxes only).

  val ownerPubKey    = SELF.R4[GroupElement].get
  // 0.002 ERG = 2x the intended single-box post fee (0.001 ERG). The daemon's
  // raised post fee (OracleBoxPoster MINER_FEE, 0.003 ERG) is not needed
  // (operator, 2026-10-03); this is a ceiling, not the fee paid.
  val maxFeePerEpoch = 2000000L

  // A post stamped s (successor creationHeight = s) can be included in
  // blocks s .. s+mempoolSlack. The daemon stamps tip-1, so a post built
  // at tip h lives for blocks h+1 .. h+mempoolSlack-1 (3 blocks here).
  // Must stay < epochLength (compile constant, 5).
  // The deployed refresh contract allows a pool epoch as short as 3 blocks
  // when a refresher back-stamps (RefreshContract.es:13, :38, :268), and a
  // 5-block lock then misses up to every other epoch (KNOWN LIMIT, probe
  // T6); under daemon-timed refreshes (6-block epochs) none are missed.
  val mempoolSlack   = 4

  // Standard miner-fee proposition (feeProposition(720)); same bytes on
  // mainnet and testnet.
  val minerFeeProp   = fromBase16("1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304")

  // `if`, not `&&`: SELF.tokens(0) throws on a box without tokens (e.g. an
  // ERG top-up that carries R4), and that throw would kill PATH B.
  val myNft = if (SELF.tokens.size > 0) SELF.tokens(0)._1 else Coll[Byte]()

  // A successor carries this NFT at tokens(0) AND keeps this script. An
  // owner reclaim (NFT to a wallet) or a burn never matches, so for those
  // transactions nothing below is evaluated and PATH B depends on R4 alone.
  // An owner in-place rotate does match, so it reads SELF.R5 below and needs
  // a well-typed R5.
  val successors = OUTPUTS.filter { (b: Box) =>
    b.tokens.size > 0 && b.tokens(0)._1 == myNft &&
    b.propositionBytes == SELF.propositionBytes
  }

  val posting = if (successors.size == 1) {
    val successor     = successors(0)
    val oracleTokenId = SELF.R5[Coll[Byte]].get

    // The bound oracle box is spent and recreated exactly once, with the
    // same script, the same token list and the same value: a value-neutral
    // pass-through, so no oracle ERG can be skimmed (wave 1 B5a) and no
    // companion ERG can be parked in it. The token id alone does not
    // identify the owner's box: where every oracle box shares one token id,
    // anyone holding a unit can plant a box at the owner's oracle-script
    // address with their own R4, and a post into it gives them the owner's
    // datapoint and that epoch's reward (wave 1 C6b, review R2). The oracle
    // R4 check in the guard below closes this.
    val oracleIns  = INPUTS.filter  { (b: Box) => b.tokens.size > 0 && b.tokens(0)._1 == oracleTokenId }
    val oracleOuts = OUTPUTS.filter { (b: Box) => b.tokens.size > 0 && b.tokens(0)._1 == oracleTokenId }
    // Exactly one input carries this NFT (this box): closes the Q4 merge.
    val oracleOk = INPUTS.filter { (b: Box) => b.tokens.size > 0 && b.tokens(0)._1 == myNft }.size == 1 &&
                   oracleIns.size == 1 && oracleOuts.size == 1 && {
      val oIn  = oracleIns(0)
      val oOut = oracleOuts(0)
      val passThrough = oOut.propositionBytes == oIn.propositionBytes &&
                        oOut.tokens == oIn.tokens &&
                        oOut.value == oIn.value

      // Output rule: besides the successor and the oracle box, every output
      // is a miner-fee box. There is no change output, so nothing this box
      // gives up (<= maxFeePerEpoch) can reach an address the signer picks
      // (wave 1 B5d). Deliberate consequence: an external fee payer cannot
      // take change, and two posts cannot share one tx (wave 1 D1b, D2).
      val onlyFeeElse = OUTPUTS.forall { (b: Box) =>
        b.id == successor.id || b.id == oOut.id || b.propositionBytes == minerFeeProp
      }
      passThrough && onlyFeeElse
    }

    // The full token list is pinned, not just the NFT (wave 1 D4).
    val tokensKept = successor.tokens == SELF.tokens
    val valueSafe  = successor.value >= SELF.value - maxFeePerEpoch

    // Height lock tied to HEIGHT (wave 1 E1). Successor creation heights must
    // step by >= epochLength, AND each must lie in [HEIGHT - mempoolSlack,
    // HEIGHT]. Without the HEIGHT window an idle box let the key post with
    // old creation heights back-to-back. `created <= HEIGHT` is also a
    // consensus rule; it is repeated here so the contract does not rely on it.
    val created  = successor.creationInfo._1
    val heightOk = created >= SELF.creationInfo._1 + epochLength &&
                   created <= HEIGHT &&
                   created >= HEIGHT - mempoolSlack

    // R6 (and the successor's typed registers) are read only once the
    // structural checks pass. Owner transactions without the oracle box stop
    // above, so a wrong-typed R6 cannot block an owner rotate either.
    if (oracleOk && tokensKept && valueSafe && heightOk) {
      val hotKey = SELF.R6[GroupElement].get
      // The oracle box must belong to this companion's owner. Assumes the
      // companion owner key (R4 here) is the same key as the oracle box's
      // owner key (its R4); an operator using two different keys cannot post.
      val regsKept = oracleIns(0).R4[GroupElement].get == ownerPubKey &&
                     successor.R4[GroupElement].get == ownerPubKey &&
                     successor.R5[Coll[Byte]].get == oracleTokenId &&
                     successor.R6[GroupElement].get == hotKey
      sigmaProp(regsKept) && proveDlog(hotKey)
    } else sigmaProp(false)
  } else sigmaProp(false)

  // PATH A: posting (hot key signature bound to this exact transaction)
  // PATH B: owner (cold key — reclaim, rotate the hot key, destroy)
  posting || proveDlog(ownerPubKey)
}
