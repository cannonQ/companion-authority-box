{
  // AVL Oracle Contract V2 — with companion authority path
  // Based on EIP-0023 oracle_contract.es
  //
  // Oracle box: R4=GroupElement, R5=Int (epoch), R6=Coll[Long] (prices)
  // tokens(0)=Oracle Token, tokens(1)=Reward Tokens
  //
  // Spending paths:
  //   1. Owner:      proveDlog(R4)
  //   2. Collection: pool NFT in INPUTS(0)
  //   3. Companion:  companion authority NFT in INPUTS (NEW)

  val otherTokenId = INPUTS(0).tokens(0)._1

  val minStorageRent = 10000000L
  val selfPubKey = SELF.R4[GroupElement].get
  val outIndex = getVar[Int](0).get
  val output = OUTPUTS(outIndex)

  val isSimpleCopy = output.tokens(0) == SELF.tokens(0)               &&
                     output.propositionBytes == SELF.propositionBytes  &&
                     output.R4[GroupElement].isDefined                 &&
                     output.value >= minStorageRent

  val collection = otherTokenId == poolNftId                    &&
                   output.tokens(1)._1 == SELF.tokens(1)._1    &&
                   output.tokens(1)._2 > SELF.tokens(1)._2     &&
                   output.R4[GroupElement].get == selfPubKey    &&
                   output.value >= SELF.value                   &&
                   ! (output.R5[Any].isDefined)

  val owner = proveDlog(selfPubKey)

  // NEW: companion authority path
  // Check for companion NFT in any input box.
  // The companion box's own contract enforces preimage, self-replication,
  // height lock, and oracle token binding.
  //
  // IMPORTANT: companion path must also enforce:
  //   - R4 pubkey preserved (prevent oracle box takeover)
  //   - Reward tokens preserved (prevent reward stripping)
  // These checks are NOT in isSimpleCopy because the owner path
  // (proveDlog) intentionally allows the owner to change these.
  val companionNftPresent = INPUTS.exists { (b: Box) =>
    b.tokens.size > 0 && b.tokens(0)._1 == companionNftId
  }
  val companionSafe = companionNftPresent                         &&
                      output.R4[GroupElement].get == selfPubKey    &&
                      output.tokens.size >= 2                     &&
                      output.tokens(1)._1 == SELF.tokens(1)._1   &&
                      output.tokens(1)._2 >= SELF.tokens(1)._2

  isSimpleCopy && (owner || collection || sigmaProp(companionSafe))
}