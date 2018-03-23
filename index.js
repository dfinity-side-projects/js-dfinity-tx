const EventEmitter = require('events')
const Buffer = require('safe-buffer').Buffer
const assert = require('assert')
const crypto = require('crypto')
const secp256k1 = require('secp256k1')
const cbor = require('borc')
const NoFilter = require('nofilter')

/**
 * This implements basic functions relating to Dfinity Transactions
 * @param {Number} [version=0] - the tx version
 * @param {Buffer} [actorId=Buffer.from([])] - the actor's ID
 * @param {String} [funcName=""] - the name of an exported function of the actor
 * @param {Array}  [args=0] - the function arguments, an array of integers or floats
 * @param {Number} [ticks=0] - the number of ticks allocate for this message
 * @param {Number} [ticksPrice=0] - the price to pay for the ticks
 * @param {Number} [nonce=0]
 * @param {Buffer} [publicKey=Buffer.from([])]
 * @param {Buffer} [signature=Buffer.from([])]
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
      this.actorId,
      this.funcName,
      cbor.encode(this.args),
      this.ticks,
      this.ticksPrice,
      this.nonce,
    ])

    return (includeSig ? 
      cbor.encode([
        tag, 
        this.publicKey, 
        secp256k1.signatureExport(this.signature)
      ]) : cbor.encode(tag)
    )
  }

  /**
   * signs a message and returns the serialized and signed message. Note that
   * the public key and signature is added to the original transaction too.
   * @param {Buffer} secretKey - a 32 bytes buffer to use as a secret key
   * @return {Buffer} Buffer containing the serialised transaction.
   */
  sign (secretKey) {
    const serialized = this.serialize(false)
    const hash = DfinityTx._hash(serialized)
    const sig = secp256k1.sign(hash, secretKey)
    this.publicKey = secp256k1.publicKeyCreate(secretKey)
    this.signature = sig.signature
    return this.serialize()
  }

  /**
   * verify the signature of a `DfinityTx`.
   * @return {Bool}
   */
  verify() {
    const serialized = this.serialize(false)
    const hash = DfinityTx._hash(serialized)
    return secp256k1.verify(hash, this.signature, this.publicKey)
  } 

  /**
   * deserializes the message and returns a new instance of `DfinityTx`
   * @param {Buffer} raw - the serialized raw message that is either signed or unsigned.
   * @return {DfinityTx} a new instance of `DfinityTx`
   */
  static deserialize(raw) {
    const d = DfinityTx.getDecoder()
    const c = d.decodeFirst(raw)
    let tx
    if (c instanceof Array) {
      assert.equal(c.length, 3)
      tx = c[0]
      tx.publicKey = c[1]
      tx.signature = secp256k1.signatureImport(c[2])
    }
    else {
      tx = c
    }
    return tx
  }

  static getDecoder() {
    return new cbor.Decoder({ 
      tags : {
        44: (val) => {
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
      actorId: Buffer.from([]),
      funcName: "",
      args: new Array([]),
      ticks: 0,
      ticksPrice: 0,
      nonce: 0,
      publicKey: Buffer.from([]),
      signature: Buffer.from([]),
    }
  }
}
