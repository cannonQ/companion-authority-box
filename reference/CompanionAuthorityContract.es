{
  // Companion Authority Box — keyless oracle posting with hash preimage gate
  //
  // PATH A: Posting (hash preimage required, no proveDlog)
  //   Server proves knowledge of preimage via blake2b256 check.
  //   Self-replicating, drains ERG slowly for fees,
  //   can only be spent once per epochLength blocks.
  //
  // PATH B: Owner reclaim (cold signature)
  //   proveDlog(ownerPubKey) — can reclaim ERG, rotate preimage, or destroy.

  val ownerPubKey    = SELF.R4[GroupElement].get
  val oracleTokenId  = SELF.R5[Coll[Byte]].get
  val secretHash     = SELF.R6[Coll[Byte]].get
  val maxFeePerEpoch = 2500000L

  // Find successor (self-replication via NFT tracking)
  val myNft = SELF.tokens(0)._1
  val successor = OUTPUTS.filter { (b: Box) =>
    b.tokens.size > 0 && b.tokens(0)._1 == myNft
  }(0)

  // Self-replication invariants
  val nftPreserved    = successor.tokens(0) == SELF.tokens(0)
  val scriptPreserved = successor.propositionBytes == SELF.propositionBytes
  val ownerPreserved  = successor.R4[GroupElement].get == ownerPubKey
  val bindPreserved   = successor.R5[Coll[Byte]].get == oracleTokenId
  val hashPreserved   = successor.R6[Coll[Byte]].get == secretHash
  val valueSafe       = successor.value >= SELF.value - maxFeePerEpoch

  // Height lock: can only be spent once per epochLength blocks
  val heightLocked = successor.creationInfo._1 >= SELF.creationInfo._1 + epochLength

  // Verify an oracle box with the bound token is in the TX outputs
  val oraclePresent = OUTPUTS.exists { (b: Box) =>
    b.tokens.size > 0 && b.tokens(0)._1 == oracleTokenId
  }

  // Hash preimage gate: server must provide the secret as context variable
  val preimage    = getVar[Coll[Byte]](0).get
  val secretValid = blake2b256(preimage) == secretHash

  val selfReplicate = nftPreserved && scriptPreserved && ownerPreserved &&
                      bindPreserved && hashPreserved && valueSafe &&
                      heightLocked && oraclePresent

  // PATH A: posting (hash preimage — server must know the secret)
  // PATH B: owner reclaim (cold key — can also rotate the preimage hash)
  sigmaProp(selfReplicate && secretValid) || proveDlog(ownerPubKey)
}