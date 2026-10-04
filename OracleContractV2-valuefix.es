{
  //////////////////////////////////////////////////////////
  // OracleContractV2-valuefix.es — one operator's box in an oracle pool
  //////////////////////////////////////////////////////////
  // Author: CannonQ (2026)
  //
  // An oracle pool is a set of operator boxes, each holding one datapoint, plus a
  // pool box (marked by the singleton pool NFT) that periodically collects those
  // datapoints into a shared price record. This is one operator's box: it holds
  // the operator's oracle token, the reward tokens earned so far, and the latest
  // datapoint. It can be spent three ways: by the operator's owner key, by the
  // pool's refresh transaction collecting it, or by a post made through the
  // operator's authority box (CompanionAuthorityHotKey.es). On every path it is
  // recreated at this same script with its oracle token, so it never leaves.
  //
  // Box:
  //   value            nanoERG; at least 0.01 ERG in every successor, and no
  //                    lower than before on a collection or an authority post.
  //   tokens(0)        the operator's oracle token; id and quantity carried
  //                    unchanged on every path.
  //   tokens(1)        the reward token; each collection adds to it, and the
  //                    owner may withdraw it.
  //   R4 GroupElement  the operator's owner key; the owner path signs with it.
  //   R5 onward        the datapoint, written by whoever posts; this script never
  //                    reads them. The pool's refresh transaction reads R5 as an
  //                    Int (the pool epoch the datapoint is for, matched against
  //                    the pool box's epoch counter) and R6 as a Coll[Long] (one
  //                    value per price feed).
  //
  // On every path, context variable 0 on this input names an output index, and
  // that index must be this input's own index. The output there is the successor:
  // this script, tokens(0) unchanged, a GroupElement in R4, value >= 0.01 ERG.
  //
  // Owner (signed with the R4 key):
  //   inputs       this box, plus whatever the owner adds.
  //   outputs      the successor at this box's index. R4 may hold a new key; the
  //                reward tokens, the value above 0.01 ERG and R5 onward are the
  //                owner's to set. Other outputs are free.
  //   data inputs  none.
  //   Checked here: the R4 signature and the successor rules above, nothing more.
  //
  // Collection (the pool's refresh transaction; no signature checked here):
  //   inputs       INPUTS(0) the pool box, holding poolNftId at tokens(0);
  //                INPUTS(1) the refresh box; then the oracle boxes collected.
  //                The refresh box requires the owner key of one collected
  //                oracle box to sign.
  //   outputs      OUTPUTS(0) the pool box's successor, OUTPUTS(1) the refresh
  //                box's successor, then each oracle box's successor at its own
  //                input's index.
  //   data inputs  none.
  //   Checked here: this box and its successor hold exactly two tokens; the
  //   reward token keeps its id and its quantity strictly rises; R4 is unchanged;
  //   value does not fall; the successor has no R5, so the datapoint is cleared.
  //
  // Authority post (signed through CompanionAuthorityHotKey.es):
  //   inputs       this box and the operator's authority box, which holds the
  //                authorityNftId singleton at tokens(0).
  //   outputs      this box's successor at its own index, the authority box's
  //                successor, and miner-fee boxes only.
  //   data inputs  none.
  //   Checked here: some input carries authorityNftId at tokens(0), sits at the
  //   script whose blake2b256 hash is authorityScriptHash, and has R4 equal to
  //   this box's R4; the successor keeps R4, the exact token list, and value no
  //   lower. R5 onward (the new datapoint) are left to the poster.
  //
  // Nuance: the collection path only looks for the pool NFT at INPUTS(0), so any
  // spend of the pool box counts, not just a refresh. A box whose reward tokens
  // were withdrawn holds one token and cannot be collected until the owner adds
  // a second token entry back.
  //////////////////////////////////////////////////////////

  // Compile-time constants (each Coll[Byte]):
  //   poolNftId            the pool box's singleton NFT id
  //   authorityNftId       the authority box's singleton NFT id
  //   authorityScriptHash  blake2b256 of the compiled CompanionAuthorityHotKey.es

  // Guarded: a token-less box at INPUTS(0) gives an empty id, not a failure.
  val otherTokenId = if (INPUTS(0).tokens.size > 0) INPUTS(0).tokens(0)._1 else Coll[Byte]()

  // The successor's minimum value on every path, in nanoERG (0.01 ERG).
  val minStorageRent = 10000000L
  val selfPubKey = SELF.R4[GroupElement].get
  // Context variable 0: the index of this box's successor among the outputs.
  val outIndex = getVar[Int](0).get
  val output = OUTPUTS(outIndex)

  // Rules shared by all three paths. INPUTS(outIndex).id == SELF.id puts the
  // successor at this input's own index, so two oracle boxes spent together can
  // never both claim one output. tokens(0) is compared as an (id, quantity) pair.
  val isSimpleCopy = INPUTS(outIndex).id == SELF.id                 &&
                     output.tokens(0) == SELF.tokens(0)               &&
                     output.propositionBytes == SELF.propositionBytes  &&
                     output.R4[GroupElement].isDefined                 &&
                     output.value >= minStorageRent

  // Collection: the pool box must be at INPUTS(0). Exactly two tokens in and
  // out, so no third token can be swept or added; the reward count must rise;
  // and an absent R5 on the successor clears the datapoint for the next round.
  val collection = otherTokenId == poolNftId                    &&
                   SELF.tokens.size == 2                       &&
                   output.tokens.size == 2                     &&
                   output.tokens(1)._1 == SELF.tokens(1)._1    &&
                   output.tokens(1)._2 > SELF.tokens(1)._2     &&
                   output.R4[GroupElement].get == selfPubKey    &&
                   output.value >= SELF.value                   &&
                   ! (output.R5[Any].isDefined)

  val owner = proveDlog(selfPubKey)

  // Authority post: no signature is checked on this box. The posting key signs for
  // the authority box, and CompanionAuthorityHotKey.es enforces the post's shape.
  val companionNftPresent = INPUTS.exists { (b: Box) =>
    b.tokens.size > 0 && b.tokens(0)._1 == authorityNftId &&
    blake2b256(b.propositionBytes) == authorityScriptHash &&
    b.R4[GroupElement].get == selfPubKey
  }
  val companionSafe = companionNftPresent                         &&
                      output.R4[GroupElement].get == selfPubKey    &&
                      output.tokens == SELF.tokens                 &&
                      output.value >= SELF.value

  // The shared successor rules always apply, plus any one of the three paths.
  isSimpleCopy && (owner || collection || sigmaProp(companionSafe))
}
