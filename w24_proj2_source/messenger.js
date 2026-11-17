'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

// Constants used as the "info"/"data" strings for the various HMAC/HKDF
// derivations. Any fixed strings work here as long as sender and receiver
// agree on them - they just need to be distinct from one another so that
// a root-key derivation can never collide with a chain-key derivation, etc.
const RATCHET_STR = 'ratchet-str'
const CHAIN_KEY_STR = 'chain-key-str'
const MESSAGE_KEY_STR = 'message-key-str'

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    this.EGKeyPair = await generateEG()
    const certificate = {
      username,
      publicKey: this.EGKeyPair.pub
    }
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
    // The signature will be on the output of stringifying the certificate
    // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)

    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!isValid) {
      throw new Error('Certificate verification failed: signature is invalid, certificate may have been tampered with')
    }

    this.certs[certificate.username] = certificate

    // We can't derive the shared initial root key yet if we haven't
    // generated our own certificate/keypair - defer that (lazily, in
    // _ensureSession below) until this connection is actually used to
    // send or receive a message.
    this.conns[certificate.username] = {
      rootKey: null,
      DHs: null,
      // We don't know the other party's ratchet public key yet.
      DHr: null,
      sendingChainKey: null,
      receivingChainKey: null,
      theirPublicKey: certificate.publicKey,
      // Ns/Nr: number of messages sent/received on the current sending/
      // receiving chain. PN: length of the previous sending chain (sent in
      // the header so the receiver knows how many trailing messages from
      // that old chain it may still need to skip over).
      Ns: 0,
      Nr: 0,
      PN: 0,
      // Message keys for messages that arrived out of order and haven't
      // been consumed yet, keyed by [senderRatchetPublicKey][messageNumber].
      // EXTRA CREDIT: lets us decrypt messages that arrive delayed/
      // out-of-order instead of just throwing.
      mkSkipped: new Map()
    }
  }

  /**
   * Lazily finishes initializing a connection's root key the first time it
   * is actually needed (on the first send or receive). Both parties can
   * independently compute the same value from their own identity secret
   * key and the other party's identity public key (ECDH is symmetric), so
   * this serves as the shared initial root key before either side has sent
   * a single message.
   */
  async _ensureSession (conn) {
    if (conn.rootKey === null) {
      conn.rootKey = await computeDH(this.EGKeyPair.sec, conn.theirPublicKey)
      // Until we ratchet, our "current" DH ratchet keypair is just our
      // long-term identity keypair (mirrors Signal's RatchetInitBob, which
      // reuses Bob's existing keypair rather than generating a new one).
      conn.DHs = this.EGKeyPair
    }
  }

  /**
   * Performs a symmetric-key ("chain key") ratchet step.
   * Given the current chain key, derives the next chain key (via
   * HMACtoHMACKey, since it must remain usable for further HMACs) and a
   * message key (via HMACtoAESKey, since it must be usable with AES-GCM).
   */
  async _chainRatchet (chainKey) {
    const nextChainKey = await HMACtoHMACKey(chainKey, CHAIN_KEY_STR)
    const messageKey = await HMACtoAESKey(chainKey, MESSAGE_KEY_STR)
    return [nextChainKey, messageKey]
  }

  /**
   * Performs a Diffie-Hellman ("root key") ratchet step for the receiving
   * side: incorporates the other party's newly-seen ratchet public key,
   * then immediately generates our own new ratchet keypair and ratchets
   * again so that we are ready to send with a fresh chain too. This mirrors
   * the DHRatchet() routine from the Signal spec, which updates both CKr
   * and CKs together whenever the sender changes.
   */
  async _dhRatchet (conn, theirNewPublicKey) {
    conn.PN = conn.Ns
    conn.Ns = 0
    conn.Nr = 0
    conn.DHr = theirNewPublicKey

    const dhOutRecv = await computeDH(conn.DHs.sec, conn.DHr)
    const [rk1, ckr] = await HKDF(dhOutRecv, conn.rootKey, RATCHET_STR)
    conn.rootKey = rk1
    conn.receivingChainKey = ckr

    conn.DHs = await generateEG()
    const dhOutSend = await computeDH(conn.DHs.sec, conn.DHr)
    const [rk2, cks] = await HKDF(dhOutSend, conn.rootKey, RATCHET_STR)
    conn.rootKey = rk2
    conn.sendingChainKey = cks
  }

  /**
   * EXTRA CREDIT (out-of-order delivery): advances the receiving chain up
   * to (but not including) message number `until`, stashing each message
   * key we skip past along the way instead of discarding it, so that a
   * delayed message can still be decrypted whenever it eventually arrives.
   */
  async _skipMessageKeys (conn, until) {
    if (conn.receivingChainKey === null) {
      // No receiving chain yet (e.g. we are about to ratchet for the very
      // first time) - nothing to skip.
      return
    }
    if (conn.Nr > until) {
      // We've already advanced past `until` on this chain - the message
      // this was requested for is a replay (or otherwise invalid), not a
      // legitimately delayed message.
      throw new Error('Cannot skip backwards on receiving chain: message replay or invalid ordering detected')
    }

    let skippedForThisKey = conn.mkSkipped.get(conn.DHr)
    if (!skippedForThisKey) {
      skippedForThisKey = new Map()
      conn.mkSkipped.set(conn.DHr, skippedForThisKey)
    }

    while (conn.Nr < until) {
      const [newChainKey, messageKey] = await this._chainRatchet(conn.receivingChainKey)
      skippedForThisKey.set(conn.Nr, messageKey)
      conn.receivingChainKey = newChainKey
      conn.Nr += 1
    }
  }

  /**
   * EXTRA CREDIT (out-of-order delivery): if this message's key was
   * previously skipped over (because an earlier message arrived out of
   * order), decrypt with it directly. Returns null if no such key exists.
   */
  async _trySkippedMessageKeys (conn, header, ciphertext) {
    const skippedForThisKey = conn.mkSkipped.get(header.dh)
    if (!skippedForThisKey || !skippedForThisKey.has(header.n)) {
      return null
    }

    const messageKey = skippedForThisKey.get(header.n)
    skippedForThisKey.delete(header.n)
    if (skippedForThisKey.size === 0) {
      conn.mkSkipped.delete(header.dh)
    }

    const plaintextBuffer = await decryptWithGCM(messageKey, ciphertext, header.receiverIV, JSON.stringify(header))
    return bufferToString(plaintextBuffer)
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage (name, plaintext) {
    const conn = this.conns[name]
    if (!conn) {
      throw new Error(`Cannot send message: no certificate on file for ${name}`)
    }
    await this._ensureSession(conn)

    if (conn.DHr === null) {
      // This is the very first message ever sent on this connection, and
      // we haven't received anything from them either - we are the
      // "initiator". Bootstrap our sending chain (mirrors RatchetInitAlice):
      // treat their identity public key as their current ratchet key, and
      // generate ourselves a fresh ratchet keypair to ratchet against it.
      conn.DHr = conn.theirPublicKey
      conn.DHs = await generateEG()
      const dhOut = await computeDH(conn.DHs.sec, conn.DHr)
      const [rk, cks] = await HKDF(dhOut, conn.rootKey, RATCHET_STR)
      conn.rootKey = rk
      conn.sendingChainKey = cks
    }

    // n/pn: this message's number in the current chain, and how many
    // messages were sent on the previous chain (used by the receiver to
    // recover skipped message keys across a DH ratchet boundary).
    const n = conn.Ns
    const pn = conn.PN

    // Advance the sending chain: derive this message's key, and discard the
    // old chain key by overwriting it with the new one (O(1) storage).
    const oldChainKey = conn.sendingChainKey
    const [newChainKey, messageKey] = await this._chainRatchet(oldChainKey)
    conn.sendingChainKey = newChainKey
    conn.Ns += 1
    // Also need the raw bytes of the exact same message key to encrypt it
    // for the government below (HMACtoAESKey is deterministic given the
    // same chain key and info string, so this matches messageKey above).
    const messageKeyRaw = await HMACtoAESKey(oldChainKey, MESSAGE_KEY_STR, true)

    const receiverIV = genRandomSalt()
    const ivGov = genRandomSalt()

    // Encrypt the sending key under the government's public key using
    // (ElGamal key encapsulation + AES-GCM as the symmetric cipher).
    const govEphemeralKeyPair = await generateEG()
    const govDHOut = await computeDH(govEphemeralKeyPair.sec, this.govPublicKey)
    const govAESKey = await HMACtoAESKey(govDHOut, govEncryptionDataStr)
    const cGov = await encryptWithGCM(govAESKey, messageKeyRaw, ivGov)

    const header = {
      dh: conn.DHs.pub,
      pn,
      n,
      receiverIV,
      vGov: govEphemeralKeyPair.pub,
      cGov,
      ivGov
    }

    const ciphertext = await encryptWithGCM(messageKey, plaintext, receiverIV, JSON.stringify(header))

    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    const conn = this.conns[name]
    if (!conn) {
      throw new Error(`Cannot receive message: no certificate on file for ${name}`)
    }
    await this._ensureSession(conn)

    // EXTRA CREDIT: if this exact message was skipped over earlier (it
    // arrived out of order and a later message already consumed past it),
    // we'll already have its key stashed away - use it directly.
    const skippedPlaintext = await this._trySkippedMessageKeys(conn, header, ciphertext)
    if (skippedPlaintext !== null) {
      return skippedPlaintext
    }

    // If the header carries a ratchet public key we haven't seen before
    // (including the very first message on this connection, where DHr is
    // still null), the sender has started a new DH ratchet step.
    if (conn.DHr === null || conn.DHr !== header.dh) {
      // Before switching chains, stash any still-unreceived message keys
      // from the end of the OLD receiving chain (header.pn tells us how
      // many messages the sender sent on their previous chain).
      await this._skipMessageKeys(conn, header.pn)
      await this._dhRatchet(conn, header.dh)
    }

    if (!conn.receivingChainKey) {
      throw new Error('Cannot decrypt message: no receiving chain established (message out of order or dropped)')
    }

    // Catch up to this message's position in the chain, stashing any
    // intervening (still-missing) message keys along the way.
    await this._skipMessageKeys(conn, header.n)

    // Advance the receiving chain once more to get this message's own key,
    // and discard the old chain key.
    const [newChainKey, messageKey] = await this._chainRatchet(conn.receivingChainKey)
    conn.receivingChainKey = newChainKey
    conn.Nr += 1

    // decryptWithGCM throws if authentication fails - this is what catches
    // tampering and messages intended for someone else (the derived key
    // will be unrelated garbage).
    const plaintextBuffer = await decryptWithGCM(messageKey, ciphertext, header.receiverIV, JSON.stringify(header))

    return bufferToString(plaintextBuffer)
  }
};

module.exports = {
  MessengerClient
}
