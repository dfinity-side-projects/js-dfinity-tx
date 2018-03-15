const EventEmitter = require('events')
const Buffer = require('safe-buffer').Buffer
const assert = require('assert')
const crypto = require('crypto')
const secp256k1 = require('secp256k1')
const cbor = require('cbor')
const NoFilter = require('nofilter')

/**
 * This implements basic functions relating to Dfinity Transactions
 * @param {Number} [version=0] - the tx version
 * @param {Buffer} [to=0] - the function reference
 * @param {Number} [caps=0] - the number of response capabilities this message has
 * @param {Number} [ticks=0] - the number of to allocate for this message
 * @param {Number} [ticksPrice=0] - the price by ticks
 * @param {Number} [nonce=0]
 * @param {Buffer} [data=0]
 * @param {Buffer} [publicKey=new Uint8Array(32)]
 * @param {Buffer} [signature=new Uint8Array([])]
 * @param {Number} [recovery=0]
 */
module.exports = class DfinityTx extends EventEmitter {
  constructor (opts = {}) {
    super()
    const defaults = this.constructor.defaults
    this._opts = Object.assign(defaults, opts)
    Object.keys(this._opts).forEach(key => {
      Object.defineProperty(this, key, {
        get: function () {
          return this._opts[key]
        },
        set: function (y) {
          this._opts[key] = y
        }
      })
    })
  }

  /**
   * serializes the message
   * @return {Buffer}
   */
  serialize (includeSig = this.signature.length !== 0) {
    const tag = new cbor.Tagged(44, [
      this.version,
      this.to,
      this.caps,
      this.ticks,
      this.ticksPrice,
      this.nonce,
      this.data
    ])

    return Buffer.concat([
      cbor.encode(tag),
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
    const hash = await DfinityTx._hash(serialized)
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
    const c = new cbor.Decoder()
    if (!Buffer.isBuffer(raw))
      raw = Buffer.from(raw)
    const s = new NoFilter(raw)

    // decode first object and assume the remainder is the signature
    const parser = c._parse()
    let state = parser.next()
    while (!state.done) {
      const b = s.read(state.value)
      if ((b == null) || (b.length !== state.value)) {
        throw new Error('Insufficient data')
      }
      state = parser.next(b)
    }
    const tag = cbor.Decoder.nullcheck(state.value)
    const isSigned = s.length > 0

    assert.equal(tag.tag, 44, 'txs should be tagged 44')

    const json = {
      version: tag.value[0],
      to: tag.value[1],
      caps: tag.value[2],
      ticks: tag.value[3],
      ticksPrice: tag.value[4],
      nonce: tag.value[5],
      data: tag.value[6]
    }

    if (!isSigned) { return new DfinityTx(json) }

    json.signature = s.read(64)
    json.recovery = s.read(1)[0]

    const hash = await DfinityTx._hash(raw.subarray(0, -65))
    json.publicKey = await DfinityTx.recoverPublicKey(hash, json.signature, json.recovery)

    return new DfinityTx(json)
  }

  /**
   * Gets the SHA-256 hash of the serialized tx
   * @param {number} length - the number of bytes of the hash to return. must be <= 32
   * @returns {Buffer} the hashed tx
   */
  hash (length = 32) {
    return DfinityTx._hash(this.serialize(), length)
  }

  static _hash (data, length) {
    const hash = crypto.createHash('sha256')
    hash.update(data)
    return hash.digest().slice(0, length)
  }

  static get defaults () {
    return {
      version: 0,
      to: new Uint8Array([]),
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
