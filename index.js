const Buffer = require('safe-buffer').Buffer
const assert = require('assert')
const Message = require('primea-message')
const secp256k1 = require('secp256k1')
const cbor = require('cbor')

/**
 * This implements basic functions relating to Dfinity Transactions
 * @param {Number} [version=0] - the tx version
 * @param {Number} [to=0] - the function reference
 * @param {Number} [caps=0] - the number of response capabilities this message has
 * @param {Number} [ticks=0] - the number of to allocate for this message
 * @param {Number} [ticksPrice=0] - the price by ticks
 * @param {Number} [nonce=0]
 * @param {Buffer} [data=0]
 * @param {Buffer} [publicKey=new Uint8Array(32)]
 * @param {Buffer} [signature=new Uint8Array([])]
 * @param {Number} [recovery=0]
 */
module.exports = class DfinityTx extends Message {
  /**
   * serializes the message
   * @return {Buffer}
   */
  serialize (includeSig = this.signature.length !== 0) {
    return Buffer.concat([
      cbor.encode(
        1,
        this.version,
        this.to,
        this.caps,
        this.ticks,
        this.ticksPrice,
        this.nonce,
        this.data
      ),
      includeSig ? this.signature : Buffer.from([]),
      includeSig ? Buffer.from([this.recovery]) : Buffer.from([])
    ])
  }

  /**
   * signs a message and returns the serialized and signed message
   * @param {Buffer} secretKey - a 32 bytes buffer to use as a secret key
   * @return {Promise} resolve with a Buffer containing the signed message
   */
  async sign (secretKey) {
    const serialized = this.serialize(false)
    const hash = await DfinityTx.hash(serialized)
    const sig = secp256k1.sign(hash, secretKey)
    this.signature = sig.signature
    this.recovery = sig.recovery
    return this.serialize()
  }

  /**
   * Recovers a public key from a signed message
   * @param {Buffer} serialized - the serialized message
   * @returns {Promise} resolves with a 32 byte public key
   */
  static async recoverPublicKey (hash, sig, recovery) {
    let publicKey
    try {
      publicKey = secp256k1.recover(hash, sig, recovery)
    } catch (e) {
      publicKey = false
    }
    return publicKey
  }

  /**
   * deserializes the message and returns a new instance of `DfinityTx`
   * @param {Buffer} raw - the serialized raw message
   * @return {Promise} resolve with a new instance of `DfinityTx`
   */
  static async deserialize (raw) {
    const isSigned = raw.length > 65
    const rawData = isSigned ? raw.subarray(0, -65) : raw
    const parts = cbor.decodeAllSync(rawData)
    const type = parts[0]
    assert.equal(type, 1, 'txs should start with type 1')

    const json = {
      version: parts[1],
      to: parts[2],
      caps: parts[3],
      ticks: parts[4],
      ticksPrice: parts[5],
      nonce: parts[6],
      data: parts[7]
    }

    if (!isSigned) { return new DfinityTx(json) }

    const sig = raw.subarray(-65)
    json.signature = sig.subarray(0, -1)
    json.recovery = sig.subarray(-1)[0]

    const hash = await DfinityTx.hash(rawData)
    json.publicKey = await DfinityTx.recoverPublicKey(hash, json.signature, json.recovery)

    return new DfinityTx(json)
  }

  static get defaults () {
    return {
      version: 0,
      to: 0,
      caps: 0,
      ticks: 0,
      ticksPrice: 0,
      nonce: 0,
      data: new Uint8Array([]),
      publicKey: new Uint8Array(32),
      signature: new Uint8Array([]),
      recovery: 0
    }
  }
}
