{
  // AVL Oracle Contract V2 — with companion authority path
  // Based on EIP-0023 oracle_contract.es
  //
  // Oracle box: R4=GroupElement, R5=Int (epoch), R6=Coll[Long] (prices)
  // tokens(0)=Oracle Token, tokens(1)=Reward Tokens
  //
  // Compile constants: poolNftId, authorityNftId (the posting authority
  // box's NFT; NOT the daemon's analytics-box "companionNftId"), and
  // authorityScriptHash = blake2b256 of the compiled CompanionAuthorityHotKey.es
  // tree. Compile the authority contract FIRST; any change to it changes
  // this script.
  //
  // Spending paths (all three also need isSimpleCopy):
  //   1. Owner:      proveDlog(R4)
  //   2. Collection: pool NFT in INPUTS(0)
  //   3. Authority:  an input holding authorityNftId at tokens(0), at the
  //                  authority script, with R4 = this box's R4
  //
  // BUILDER RULE: every oracle box's output must be at the same index as its
  // input (context var 0 = its own input index). A swapped layout is rejected.
  //
  // ACCEPTED LOW RESIDUALS (audit 2026-10-03, not fixed on purpose):
  //  - F-5: a box with only the oracle token cannot be collected. The proposed
  //    fix (output.tokens.size == 2 in isSimpleCopy) was rejected: it breaks
  //    the reclaim layout that keeps the oracle box with the oracle token only.
  //  - V-1: an update tx (pool NFT at INPUTS(0) via the update path) can still
  //    reset datapoints through path 2. A refresh-NFT pin was rejected: it would
  //    tie this script to one refresh NFT and strand every oracle box when the
  //    refresh contract is replaced.

  // Guarded: a token-less box at INPUTS(0) gives an empty id, not a throw.
  val otherTokenId = if (INPUTS(0).tokens.size > 0) INPUTS(0).tokens(0)._1 else Coll[Byte]()

  val minStorageRent = 10000000L
  val selfPubKey = SELF.R4[GroupElement].get
  val outIndex = getVar[Int](0).get
  val output = OUTPUTS(outIndex)

  // INPUTS(outIndex).id == SELF.id: the named output is at this input's own
  // index, so two oracle inputs can never name the same output.
  val isSimpleCopy = INPUTS(outIndex).id == SELF.id                 &&
                     output.tokens(0) == SELF.tokens(0)               &&
                     output.propositionBytes == SELF.propositionBytes  &&
                     output.R4[GroupElement].isDefined                 &&
                     output.value >= minStorageRent

  // Exactly two tokens in and out: no third token can be swept or added.
  val collection = otherTokenId == poolNftId                    &&
                   SELF.tokens.size == 2                       &&
                   output.tokens.size == 2                     &&
                   output.tokens(1)._1 == SELF.tokens(1)._1    &&
                   output.tokens(1)._2 > SELF.tokens(1)._2     &&
                   output.R4[GroupElement].get == selfPubKey    &&
                   output.value >= SELF.value                   &&
                   ! (output.R5[Any].isDefined)

  val owner = proveDlog(selfPubKey)

  // Path 3: posting through the authority box (no preimage; no key on this
  // box). This contract RELIES on CompanionAuthorityHotKey.es for: the hot-key
  // signature, exactly one oracle input per post, the oracle pass-through,
  // no change output, the rate limit and the fee cap. It CHECKS itself: the
  // same-index output (isSimpleCopy), that the NFT input is at the authority
  // script (hash) with R4 = this box's R4, the full token list, and the value.
  // The owner path (proveDlog) may change R4 and the tokens; this path may not.
  val companionNftPresent = INPUTS.exists { (b: Box) =>
    b.tokens.size > 0 && b.tokens(0)._1 == authorityNftId &&
    blake2b256(b.propositionBytes) == authorityScriptHash &&
    b.R4[GroupElement].get == selfPubKey
  }
  val companionSafe = companionNftPresent                         &&
                      output.R4[GroupElement].get == selfPubKey    &&
                      output.tokens == SELF.tokens                 &&
                      output.value >= SELF.value

  isSimpleCopy && (owner || collection || sigmaProp(companionSafe))
}
