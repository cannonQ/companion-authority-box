{
  //////////////////////////////////////////////////////////
  // CompanionAuthorityHotKey.es — posting authority for one oracle owner
  //////////////////////////////////////////////////////////
  // Author: CannonQ (2026)
  //
  // Lets an always-online server post datapoints to its owner's oracle boxes
  // without holding the owner key or any wallet. The box carries an NFT that
  // OracleContractV2-valuefix.es accepts as its posting authority, the owner key
  // (kept offline) and a separate posting key. A post is signed with the posting
  // key, spends one oracle box together with this box, and pays the miner fee out
  // of this box's ERG. The script fences that key in: ERG and tokens can only go
  // back into the same two boxes or to the miner, this box may lose at most
  // maxFeePerEpoch per post, and successive posts are at least epochLength blocks
  // apart. The posting signature covers the whole transaction, so it cannot be
  // reused on a different one. The owner key can spend the box in any way.
  //
  // Box:
  //   value      nanoERG; the fund that pays post fees. Each post may lower it by
  //              at most maxFeePerEpoch.
  //   tokens(0)  the authority NFT; OracleContractV2-valuefix.es knows its id as
  //              authorityNftId. A post keeps the whole token list unchanged.
  //   R4 GroupElement  the owner key. It must also be the R4 (owner key) of the
  //                    oracle box being posted to; the oracle contract checks the
  //                    same equality from its side. R4 is read on every spend, so a
  //                    box at this address without a GroupElement R4 (for example
  //                    a plain ERG top-up) can never be spent.
  //   R5 Coll[Byte]    the oracle token id: the tokens(0) id that every oracle box
  //                    in the pool carries. It does not name one oracle box.
  //   R6 GroupElement  the posting key.
  //
  // Post (posting key signs):
  //   inputs       this box, the only input holding its NFT at tokens(0); exactly
  //                one oracle box (tokens(0) = the R5 id) whose R4 equals this
  //                box's R4. Further inputs are not refused, but with no change
  //                output their value can only go to the miner.
  //   outputs      exactly one successor at this script with the NFT at tokens(0):
  //                same tokens, same R4/R5/R6, value at most maxFeePerEpoch lower;
  //                exactly one oracle output with the same script, tokens and value
  //                as the oracle input; every other output a miner-fee box.
  //   data inputs  none.
  //   Checked here: also the successor's creation height, which must be at least
  //   epochLength above this box's and no more than mempoolSlack below HEIGHT.
  //   OracleContractV2-valuefix.es, spent alongside, checks from its side that this
  //   box's script hash equals its authorityScriptHash, that the oracle output sits
  //   at the same index as the oracle input and keeps R4; it leaves the datapoint
  //   registers (R5 onward) free for the post to write.
  //
  // Owner (owner key signs):
  //   inputs       this box, plus anything the owner adds.
  //   outputs      free: send the NFT and ERG to a wallet, recreate the box here
  //                with a new posting key in R6, or burn the NFT.
  //   data inputs  none.
  //   Checked here: only the owner signature, with one catch. If the transaction
  //   has exactly one output at this script carrying the NFT at tokens(0), this
  //   box's R5 is read, and a missing or wrong-typed R5 makes the script fail; such
  //   a box must be reclaimed to a wallet rather than recreated in place.
  //
  // Nuance: because R5 names a pool-wide token, this box may post to any oracle box
  // with that token and R4 = owner; the posting rate is limited per authority box,
  // not per oracle box. Neither contract pins the oracle output's R5 onward, so
  // whatever a post writes there stays until that oracle box is next spent;
  // changing the posting key does not clear it.
  //////////////////////////////////////////////////////////

  // Compile-time constant: epochLength: Int — the minimum gap, in blocks, between
  // the creation heights of successive posts.

  val ownerPubKey    = SELF.R4[GroupElement].get
  // 0.002 ERG: the most this box's value may fall across one post, leaving headroom
  // over a 0.001 ERG single-box fee. It is a ceiling, not the fee paid.
  val maxFeePerEpoch = 2000000L

  // A post whose successor has creation height s can be included in blocks s to
  // s + mempoolSlack. It must stay below epochLength; the guard before the posting
  // key is read refuses every post otherwise.
  val mempoolSlack   = 4

  // Standard miner-fee proposition (feeProposition(720)); same bytes on
  // mainnet and testnet.
  val minerFeeProp   = fromBase16("1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304")

  // `if`, not `&&`: SELF.tokens(0) throws on a box without tokens (e.g. an ERG
  // top-up that carries R4), and that throw would also block the owner path.
  val myNft = if (SELF.tokens.size > 0) SELF.tokens(0)._1 else Coll[Byte]()

  // A successor carries this NFT at tokens(0) AND keeps this script. An owner
  // reclaim (NFT to a wallet) or a burn never matches, so for those transactions
  // nothing in the posting branch runs and the owner path depends on R4 alone. An
  // owner in-place rewrite does match, so it reads SELF.R5 below and needs a
  // well-typed R5.
  val successors = OUTPUTS.filter { (b: Box) =>
    b.tokens.size > 0 && b.tokens(0)._1 == myNft &&
    b.propositionBytes == SELF.propositionBytes
  }

  val posting = if (successors.size == 1) {
    val successor     = successors(0)
    val oracleTokenId = SELF.R5[Coll[Byte]].get

    // The oracle box is spent and recreated exactly once, keeping its script, token
    // list and value, so a post can neither take ERG out of it nor park this box's
    // ERG in it. The token id alone does not identify the owner's box: every oracle
    // box in the pool shares it, so anyone holding a unit could create a box at the
    // oracle script with their own R4 and collect the owner's datapoint and reward
    // from a post into it. The oracle R4 check in the guard below refuses that.
    val oracleIns  = INPUTS.filter  { (b: Box) => b.tokens.size > 0 && b.tokens(0)._1 == oracleTokenId }
    val oracleOuts = OUTPUTS.filter { (b: Box) => b.tokens.size > 0 && b.tokens(0)._1 == oracleTokenId }
    // Exactly one input carries this NFT (this box). Otherwise two authority boxes
    // sharing one NFT id and posting key could be merged into a single successor,
    // and the second box's ERG would leave as miner fee.
    val oracleOk = INPUTS.filter { (b: Box) => b.tokens.size > 0 && b.tokens(0)._1 == myNft }.size == 1 &&
                   oracleIns.size == 1 && oracleOuts.size == 1 && {
      val oIn  = oracleIns(0)
      val oOut = oracleOuts(0)
      val passThrough = oOut.propositionBytes == oIn.propositionBytes &&
                        oOut.tokens == oIn.tokens &&
                        oOut.value == oIn.value

      // Besides the successor and the oracle box, every output is a miner-fee box.
      // With no change output, whatever this box gives up (at most maxFeePerEpoch)
      // can only reach the miner. It also means an outside fee payer cannot take
      // change, and two posts cannot share one transaction.
      val onlyFeeElse = OUTPUTS.forall { (b: Box) =>
        b.id == successor.id || b.id == oOut.id || b.propositionBytes == minerFeeProp
      }
      passThrough && onlyFeeElse
    }

    // The full token list is pinned, not just the NFT.
    val tokensKept = successor.tokens == SELF.tokens
    val valueSafe  = successor.value >= SELF.value - maxFeePerEpoch

    // Height lock tied to HEIGHT. Successor creation heights must step up by at least
    // epochLength, AND each must lie in [HEIGHT - mempoolSlack, HEIGHT]. Without the
    // HEIGHT window an idle box would let the key post back to back with old creation
    // heights. `created <= HEIGHT` is also a consensus rule; it is repeated here so
    // the contract does not rely on it.
    val created  = successor.creationInfo._1
    val heightOk = created >= SELF.creationInfo._1 + epochLength &&
                   created <= HEIGHT &&
                   created >= HEIGHT - mempoolSlack

    // R6 and the successor's typed registers are read only once the structural
    // checks pass. Owner transactions without an oracle box stop at the condition,
    // so a wrong-typed R6 cannot block an owner rewrite either.
    // `epochLength > mempoolSlack`: a lock compiled at or below the slack would let
    // two posts land at one HEIGHT; with this test such a box refuses every post.
    // The owner path is unaffected.
    if (epochLength > mempoolSlack && oracleOk && tokensKept && valueSafe && heightOk) {
      val hotKey = SELF.R6[GroupElement].get
      // The oracle box must belong to this box's owner: its R4 must be the same key
      // as R4 here, so the posting key cannot post to anyone else's oracle box.
      // The successor keeps R4, R5 and R6 unchanged.
      val regsKept = oracleIns(0).R4[GroupElement].get == ownerPubKey &&
                     successor.R4[GroupElement].get == ownerPubKey &&
                     successor.R5[Coll[Byte]].get == oracleTokenId &&
                     successor.R6[GroupElement].get == hotKey
      sigmaProp(regsKept) && proveDlog(hotKey)
    } else sigmaProp(false)
  } else sigmaProp(false)

  // Post: posting-key signature, which covers this exact transaction.
  // Owner: owner-key signature (reclaim, change the posting key, destroy).
  posting || proveDlog(ownerPubKey)
}
