{
  //////////////////////////////////////////////////////////
  // CompanionAuthorityHotKey.es — posting authority for one oracle owner
  //////////////////////////////////////////////////////////
  // Author: CannonQ (2026)
  //
  // Lets an always-online server post datapoints to its owner's oracle boxes, and
  // pay the miner fee of the pool refreshes it builds, without holding the owner
  // key or any wallet. The box carries an NFT that OracleContractV2-valuefix.es
  // accepts as its posting authority, the owner key (kept offline) and a separate
  // posting key. The posting key can spend the box two ways. A post spends one
  // oracle box together with this box and pays the miner fee out of this box's
  // ERG. A refresh fee spend joins a transaction that spends the pool box and pays
  // its miner fee out of this box's ERG. The script fences that key in: ERG and
  // tokens can only go back into this box or to the miner (for the refresh fee,
  // while this is the only authority box under its posting key; see Nuance);
  // a post may lower the
  // value by at most maxFeePerEpoch and a refresh fee spend by at most
  // maxRefreshFee; posts are at least epochLength blocks apart, and so are refresh
  // fee spends, each counted on its own stamp register. The posting signature
  // covers the whole transaction, so it cannot be reused on a different one. The
  // owner key can spend the box in any way.
  //
  // Box:
  //   value      nanoERG; the fund that pays post and refresh fees.
  //   tokens(0)  the authority NFT; OracleContractV2-valuefix.es knows its id as
  //              authorityNftId. A posting-key spend keeps the whole token list.
  //   R4 GroupElement  the owner key. It must also be the R4 (owner key) of the
  //                    oracle box being posted to; the oracle contract checks the
  //                    same equality from its side. R4 is read on every spend, so a
  //                    box at this address without a GroupElement R4 (for example
  //                    a plain ERG top-up) can never be spent.
  //   R5 Coll[Byte]    the oracle token id: the tokens(0) id that every oracle box
  //                    in the pool carries. It does not name one oracle box.
  //   R6 GroupElement  the posting key.
  //   R7 Int           post stamp: the height the last post wrote. Only a post
  //                    moves it.
  //   R8 Int           fee stamp: the height the last refresh fee spend wrote.
  //                    Only a refresh fee spend moves it.
  //   R6 to R8 are read only on the posting-key paths, after their shape checks: a
  //   box without them, or with other types there, cannot be used by the posting
  //   key but stays spendable by the owner.
  //
  // Post (posting key signs; context variable 1 absent, or an Int other than 1):
  //   inputs       this box, the only input holding its NFT at tokens(0); exactly
  //                one oracle box (tokens(0) = the R5 id) whose R4 equals this
  //                box's R4. Further inputs are not refused, but with no change
  //                output their value can only go to the miner.
  //   outputs      exactly one successor at this script with the NFT at tokens(0):
  //                same tokens, same R4/R5/R6/R8, value at most maxFeePerEpoch
  //                lower; exactly one oracle output with the same script, tokens
  //                and value as the oracle input; every other output a miner-fee
  //                box.
  //   data inputs  none.
  //   Checked here: also the successor's R7, which must be at least epochLength
  //   above this box's R7 and lie in [HEIGHT - mempoolSlack, HEIGHT]. The
  //   successor's creation height is not checked.
  //   OracleContractV2-valuefix.es, spent alongside, checks from its side that this
  //   box's script hash equals its authorityScriptHash, that the oracle output sits
  //   at the same index as the oracle input and keeps R4; it leaves the datapoint
  //   registers (R5 onward) free for the post to write.
  //
  // Refresh fee (posting key signs; context variable 1 = 1 on this input):
  //   inputs       INPUTS(0) holds poolNftId at tokens(0): the pool box, so the
  //                transaction is a refresh or a pool update. This box is the only
  //                input holding its NFT at tokens(0) and the only input at this
  //                script. Other inputs are not checked here.
  //   outputs      exactly one successor at this script with the NFT at tokens(0):
  //                same tokens, same R4/R5/R6/R7; it may hold at most
  //                maxRefreshFee less than this box (more is fine). The miner-fee
  //                outputs together hold at least what this box loses. Other
  //                outputs are not checked here.
  //   data inputs  not checked.
  //   Checked here: also the successor's R8, which must be at least epochLength
  //   above this box's R8 and lie in [HEIGHT - mempoolSlack, HEIGHT]. The pool's
  //   refresh or update contract, not this one, governs the oracle boxes such a
  //   transaction spends.
  //
  // Owner (owner key signs):
  //   inputs       this box, plus anything the owner adds.
  //   outputs      free: send the NFT and ERG to a wallet, recreate the box here
  //                with a new posting key in R6, or burn the NFT.
  //   data inputs  none.
  //   Checked here: only the owner signature, with one catch. If the transaction
  //   has exactly one output at this script carrying the NFT at tokens(0), this
  //   box's R5 is read, and a missing or wrong-typed R5 makes the script fail; such
  //   a box must be reclaimed to a wallet rather than recreated in place. The same
  //   case reads context variable 1 on this input: if the owner sets it, it must be
  //   an Int.
  //
  // Nuance: because R5 names a pool-wide token, this box may post to any oracle box
  // with that token and R4 = owner; the posting rate is limited per authority box,
  // not per oracle box. Neither contract pins the oracle output's R5 onward, so
  // whatever a post writes there stays until that oracle box is next spent;
  // changing the posting key does not clear it. The two stamps are independent: a
  // refresh fee spend never delays the next post, and in any epochLength window
  // the posting key can burn up to maxFeePerEpoch + maxRefreshFee (twice that
  // across the mempoolSlack edge). The owner sets R7 and R8 freely; a migrated box
  // needs both written as Ints before the posting key can use it. Keep one
  // authority box per posting key: two boxes on different scripts (another
  // epochLength, another compiler, an old box during a migration) under one
  // posting key could both count the same miner-fee output, and the second box's
  // loss would leave as change. Rotate an old box's R6 before replacing it.
  //////////////////////////////////////////////////////////

  // Compile-time constants:
  //   epochLength: Int       the minimum gap, in blocks, between successive post
  //                          stamps (R7), and between successive fee stamps (R8)
  //   poolNftId: Coll[Byte]  the pool box's singleton NFT id; a refresh fee spend
  //                          needs it at INPUTS(0)

  val ownerPubKey    = SELF.R4[GroupElement].get
  // 0.002 ERG: the most this box's value may fall across one post, leaving headroom
  // over a 0.001 ERG single-box fee. It is a ceiling, not the fee paid.
  val maxFeePerEpoch = 2000000L
  // 0.002 ERG: the most this box's value may fall across one refresh fee spend. It
  // is a ceiling, not the fee paid.
  val maxRefreshFee  = 2000000L

  // A spend whose successor stamp is s can be included in blocks s to
  // s + mempoolSlack. It must stay below epochLength; the guards before the posting
  // key is read refuse every posting-key spend otherwise.
  val mempoolSlack   = 4

  // Standard miner-fee proposition (feeProposition(720)); same bytes on
  // mainnet and testnet.
  val minerFeeProp   = fromBase16("1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304")

  // `if`, not `&&`: SELF.tokens(0) throws on a box without tokens (e.g. an ERG
  // top-up that carries R4), and that throw would also block the owner path.
  val myNft = if (SELF.tokens.size > 0) SELF.tokens(0)._1 else Coll[Byte]()

  // A successor carries this NFT at tokens(0) AND keeps this script. An owner
  // reclaim (NFT to a wallet) or a burn never matches, so for those transactions
  // nothing in the posting-key branches runs and the owner path depends on R4
  // alone. An owner in-place rewrite does match, so it reads SELF.R5 below and
  // needs a well-typed R5.
  val successors = OUTPUTS.filter { (b: Box) =>
    b.tokens.size > 0 && b.tokens(0)._1 == myNft &&
    b.propositionBytes == SELF.propositionBytes
  }

  val posting = if (successors.size == 1) {
    val successor     = successors(0)
    val oracleTokenId = SELF.R5[Coll[Byte]].get

    // Exactly one input carries this NFT (this box). Otherwise two authority boxes
    // sharing one NFT id and posting key could be merged into a single successor,
    // and the second box's ERG would leave as miner fee.
    val oneNftInput = INPUTS.filter { (b: Box) =>
      b.tokens.size > 0 && b.tokens(0)._1 == myNft
    }.size == 1

    // The full token list is pinned, not just the NFT.
    val tokensKept = successor.tokens == SELF.tokens

    // Context variable 1 (Int) = 1 selects the refresh fee spend; absent or any
    // other Int selects a post. The spender sets it, and the posting signature
    // covers it.
    val feeSpend = getVar[Int](1).getOrElse(0) == 1

    if (feeSpend) {
      // Guarded: a token-less box at INPUTS(0) gives an empty id, not a failure.
      val firstTokenId = if (INPUTS(0).tokens.size > 0) INPUTS(0).tokens(0)._1 else Coll[Byte]()
      // The pool NFT at INPUTS(0) makes this a refresh or a pool update, whose own
      // contracts govern the oracle boxes in it. Without this, the oracle contract's
      // companion path (which only asks for this box among the inputs) would let a
      // fee spend rewrite the owner's oracle box: a second post per period that
      // none of the post checks see.
      val inPoolTx = firstTokenId == poolNftId
      // The only input at this script. Two authority boxes under one posting key
      // (distinct NFTs, so each passes oneNftInput) could otherwise each count the
      // same miner-fee output as covering their own loss, and one loss would
      // leave as change.
      val oneScriptInput = INPUTS.filter { (b: Box) =>
        b.propositionBytes == SELF.propositionBytes
      }.size == 1
      // What this box gives up; negative when the transaction tops it up.
      val loss    = SELF.value - successor.value
      val feePaid = OUTPUTS.fold(0L, { (s: Long, b: Box) =>
        if (b.propositionBytes == minerFeeProp) s + b.value else s
      })
      // The miner-fee outputs must hold at least the loss. ERG is conserved, so
      // when no other input can hand ERG to the signer (in a refresh the pool's
      // contracts keep the pool, refresh and oracle boxes from shrinking), the
      // signer's other outputs hold at most the signer's own inputs: this box's
      // loss reaches the miner, not the signer.
      val feeOk = loss <= maxRefreshFee && feePaid >= loss

      // Typed reads only after the shape checks, as on a post.
      if (epochLength > mempoolSlack && oneNftInput && oneScriptInput && inPoolTx &&
          tokensKept && feeOk) {
        val hotKey   = SELF.R6[GroupElement].get
        val feeStamp = successor.R8[Int].get
        // Same clock as the post stamp (see below), on R8. R7 is carried over, so
        // a refresh fee spend never moves the posting lock.
        val stampOk  = feeStamp >= SELF.R8[Int].get + epochLength &&
                       feeStamp <= HEIGHT &&
                       feeStamp >= HEIGHT - mempoolSlack
        val regsKept = successor.R4[GroupElement].get == ownerPubKey &&
                       successor.R5[Coll[Byte]].get == oracleTokenId &&
                       successor.R6[GroupElement].get == hotKey &&
                       successor.R7[Int].get == SELF.R7[Int].get
        sigmaProp(stampOk && regsKept) && proveDlog(hotKey)
      } else sigmaProp(false)
    } else {
      // The oracle box is spent and recreated exactly once, keeping its script,
      // token list and value, so a post can neither take ERG out of it nor park
      // this box's ERG in it. The token id alone does not identify the owner's box:
      // every oracle box in the pool shares it, so anyone holding a unit could
      // create a box at the oracle script with their own R4 and collect the owner's
      // datapoint and reward from a post into it. The oracle R4 check in the guard
      // below refuses that.
      val oracleIns  = INPUTS.filter  { (b: Box) =>
        b.tokens.size > 0 && b.tokens(0)._1 == oracleTokenId
      }
      val oracleOuts = OUTPUTS.filter { (b: Box) =>
        b.tokens.size > 0 && b.tokens(0)._1 == oracleTokenId
      }
      val oracleOk = oneNftInput && oracleIns.size == 1 && oracleOuts.size == 1 && {
        val oIn  = oracleIns(0)
        val oOut = oracleOuts(0)
        val passThrough = oOut.propositionBytes == oIn.propositionBytes &&
                          oOut.tokens == oIn.tokens &&
                          oOut.value == oIn.value

        // Besides the successor and the oracle box, every output is a miner-fee
        // box. With no change output, whatever this box gives up (at most
        // maxFeePerEpoch) can only reach the miner. It also means an outside fee
        // payer cannot take change, and two posts cannot share one transaction.
        val onlyFeeElse = OUTPUTS.forall { (b: Box) =>
          b.id == successor.id || b.id == oOut.id || b.propositionBytes == minerFeeProp
        }
        passThrough && onlyFeeElse
      }

      val valueSafe = successor.value >= SELF.value - maxFeePerEpoch

      // R6 to R8 and the successor's typed registers are read only once the
      // structural checks pass. Owner transactions without an oracle box stop at
      // the condition, so wrong-typed R6 to R8 cannot block an owner rewrite either.
      // `epochLength > mempoolSlack`: a lock compiled at or below the slack would
      // let two posts land at one HEIGHT; with this test such a box refuses every
      // post. The owner path is unaffected.
      if (epochLength > mempoolSlack && oracleOk && tokensKept && valueSafe) {
        val hotKey = SELF.R6[GroupElement].get
        // Post stamp tied to HEIGHT. Successive R7 stamps must step up by at least
        // epochLength, AND each must lie in [HEIGHT - mempoolSlack, HEIGHT]. Without
        // the HEIGHT window an idle box would let the key post back to back with
        // old stamps, and without `<= HEIGHT` a future stamp would lock the next
        // post out. The successor's creation height is not checked: R7 is the
        // clock, so a refresh fee spend, which recreates the box, leaves it alone.
        val postStamp = successor.R7[Int].get
        val stampOk   = postStamp >= SELF.R7[Int].get + epochLength &&
                        postStamp <= HEIGHT &&
                        postStamp >= HEIGHT - mempoolSlack
        // The oracle box must belong to this box's owner: its R4 must be the same
        // key as R4 here, so the posting key cannot post to anyone else's oracle
        // box. The successor keeps R4, R5, R6 and the fee stamp R8 unchanged.
        val regsKept = oracleIns(0).R4[GroupElement].get == ownerPubKey &&
                       successor.R4[GroupElement].get == ownerPubKey &&
                       successor.R5[Coll[Byte]].get == oracleTokenId &&
                       successor.R6[GroupElement].get == hotKey &&
                       successor.R8[Int].get == SELF.R8[Int].get
        sigmaProp(stampOk && regsKept) && proveDlog(hotKey)
      } else sigmaProp(false)
    }
  } else sigmaProp(false)

  // Post / refresh fee: posting-key signature, which covers this exact transaction.
  // Owner: owner-key signature (reclaim, change the posting key, destroy).
  posting || proveDlog(ownerPubKey)
}
