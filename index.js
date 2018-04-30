const EventEmitter = require('events')
const Buffer = require('safe-buffer').Buffer
const assert = require('assert')
const crypto = require('crypto')
const secp256k1 = require('secp256k1')
const cbor = require('borc')

const CBOR_TAG = 40

/**
 * This implements basic functions relating to Dfinity Transactions
 * @param {Number} [version=0] - the tx version
 * @param {Buffer} [actorId=Buffer.from([])] - the actor's ID
 * @param {String} [funcName=""] - the name of an exported function of the actor
 * @param {Array}  [args=0] - the function arguments, an array of integers or floats
 * @param {Number} [ticks=0] - the number of ticks allocate for this message
 * @param {Number} [ticksPrice=0] - the price to pay for the ticks
 * @param {Number} [nonce=0]
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
   * Allow cbor encoder to directly encode DfinityTx object.
   */
  encodeCBOR (gen) {
    return gen.write(new cbor.Tagged(CBOR_TAG, [
      this.version,
      this.actorId,
      this.funcName,
      cbor.encode(this.args),
      this.ticks,
      this.ticksPrice,
      this.nonce,
    ]))
  }

  /**
   * signs a message and returns the serialized and signed DfinityTx message.
   * @param {Buffer} secretKey - a 32 bytes buffer to use as a secret key
   * @return {Buffer} Buffer containing serialized array of [ transaction, publicKey, signature ].
   */
  sign (secretKey) {
    const serialized = cbor.encode(this)
    const hash = DfinityTx._hash(serialized)
    const sig = secp256k1.sign(hash, secretKey)
    return cbor.encode([
      this,
      secp256k1.publicKeyCreate(secretKey),
      secp256k1.signatureExport(sig.signature)
    ])
  }

  /**
   * verify the signature of a serialized and signed DfinityTx message.
   * @return {Bool}
   */
  static verify(msg) {
    const decoder = DfinityTx.getDecoder()
    let [tx, publicKey, signature] = decoder.decodeFirst(msg)
    const hash = tx.hash()
    return secp256k1.verify(hash, secp256k1.signatureImport(signature), publicKey)
  }

  /**
   * deserializes the message and returns a new instance of `DfinityTx`
   * @param {Buffer} raw - the serialized raw message that is either signed or unsigned.
   * @return {DfinityTx} a new instance of `DfinityTx`
   */
  static decode(raw) {
    return DfinityTx.getDecoder().decodeFirst(raw)
  }

  /**
   * Get a CBOR decoder that can handle DfinityTx custom tag.
   * @return {Decoder} a new Decoder instance of `cbor.Decoder`.
   */
   static getDecoder() {
    return new cbor.Decoder({
      tags : {
        [CBOR_TAG]: (val) => {
          return new DfinityTx({
            version: val[0],
            actorId: val[1],
            funcName: val[2],
            args: cbor.decode(val[3]),
            ticks: val[4],
            ticksPrice: val[5],
            nonce: val[6]
          })
        }
      }
    })
  }

  /**
   * Gets the SHA-256 hash of the serialized tx
   * @param {number} length - the number of bytes of the hash to return. must be <= 32
   * @returns {Buffer} the hashed tx
   */
  hash (length = 32) {
    return DfinityTx._hash(cbor.encode(this), length)
  }

  static _hash (data, length) {
    const hash = crypto.createHash('sha256')
    hash.update(data)
    return hash.digest().slice(0, length)
  }

  static get defaults () {
    return {
      version: 0,
      actorId: Buffer.from([]),
      funcName: "",
      args: new Array([]),
      ticks: 0,
      ticksPrice: 0,
      nonce: 0
    }
  }
}
