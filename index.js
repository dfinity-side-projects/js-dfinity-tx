const Buffer = require('safe-buffer').Buffer
const assert = require('assert')
const Message = require('primea-message')
const Pipe = require('buffer-pipe')
const secp256k1 = require('secp256k1')
const leb128 = require('leb128').unsigned

/**
 * This implements basic functions relating to Dfinity Transactions
 * @param {Number} [version=0] - the tx version
 * @param {Buffer} [to=new Uint8Array(20)] - the address of the contract this tx is too
 * @param {Number} [caps=0] - the number of repsonse capablities this message has
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
  serialize (inculdeSig = this.signature.length !== 0) {
    const args = [
      Buffer.from([0x1]),
      leb128.encode(this.version),
      this.to,
      leb128.encode(this.caps),
      leb128.encode(this.ticks),
      leb128.encode(this.ticksPrice),
      leb128.encode(this.nonce),
      this._serializeSig(inculdeSig)
    ]
    return Buffer.concat(args)
  }

  _serializeSig (inculdeSig) {
    const args = [
      leb128.encode(this.data.length + 65),
      this.data,
      inculdeSig ? this.signature : Buffer.from([]),
      inculdeSig ? Buffer.from([this.recovery]) : Buffer.from([])
    ]
    return Buffer.concat(args)
  }

  /**
   * signs a message and returns the serialized and signed message
   * @param {Buffer} secretKey - a 32 bytes buffer to use as a secret key
   * @return {Promise} resolve with a Buffer containing the sinded message
   */
  async sign (secretKey) {
    const serialized = this.serialize(false)
    const hash = await DfinityTx.hash(serialized)
    const sig = secp256k1.sign(hash, secretKey)
    this.signature = sig.signature
    this.recovery = sig.recovery
    return Buffer.concat([serialized, sig.signature, Buffer.from([sig.recovery])])
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
   * @param {Buffer} raw - the serialized raw messsage
   * @return {Promise} resolve with a new instance of `DfinityTx`
   */
  static async deserialize (raw) {
    const p = new Pipe(raw)
    const type = p.read(1)
    assert.equal(type[0], 1, 'txs should start with type 1')

    const json = {
      version: leb128.read(p),
      to: p.read(20),
      caps: leb128.read(p),
      ticks: leb128.read(p),
      ticksPrice: leb128.read(p),
      nonce: leb128.read(p)
    }
    await DfinityTx.parseSig(json, raw, p)
    return new DfinityTx(json)
  }

  static async parseSig (json, raw, p) {
    const hash = await DfinityTx.hash(raw.subarray(0, -65))
    json.data = p.read(Number(leb128.read(p)) - 65)
    json.signature = p.read(64)
    json.recovery = p.buffer[0]
    json.publicKey = await DfinityTx.recoverPublicKey(hash, json.signature, json.recovery)
  }

  static get defaults () {
    return {
      version: 0,
      to: new Uint8Array(20),
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
