const crypto = require('crypto')
const secp256k1 = require('secp256k1')
const tape = require('tape')
const DfinityTx = require('../')

tape('tests', async t => {
  const tx = new DfinityTx({
    version: 1,
    actorId: Buffer.from('d82b84f4646d61696e80d82900', 'hex'),
    funcname: "main",
    args: new Array([1,1.2,3,4]),
    ticks: 1000,
    ticksPrice: 0,
    nonce: 0,
  })

  const unsignedTx = tx.serialize()
  const unsignedTxUint8 = new Uint8Array(tx.serialize())
  const tx1 = await DfinityTx.deserialize(unsignedTxUint8)
  t.equals(tx1.ticks, 1000, 'should validate unsigned message')
  t.deepEquals(tx1.serialize(), unsignedTx)

  const sk = crypto.randomBytes(32)
  const pk = secp256k1.publicKeyCreate(sk)

  const signedTx = await tx.sign(sk)

  const tx2 = await DfinityTx.deserialize(signedTx)
  t.equals(tx2.ticks, 1000, 'should validate signed message')
  t.deepEqual(tx2.publicKey, pk, 'should recover signed message')
  t.deepEquals(tx2.serialize(), signedTx)

  const sk2 = Buffer.from('ac15e6273a31c0c22cbad5241a875872108278a690423d912e6d33cc7544bd71', 'hex')
  const tx2hash = Buffer.from('68650e702f7c47e241a95ca5ef1fb1d1e4dc8d94b2f1729bde6144b5c98964f5', 'hex')
  await tx2.sign(sk2)
  t.deepEquals(tx2.hash(), tx2hash, 'should hash identically')

  tx2.signature[0] = Buffer.alloc(64).fill(0xff)

  const fail = await DfinityTx.recoverPublicKey(tx2.serialize(), tx2.recovery)
  t.notDeepEqual(fail, pk, 'shouldn\'t recover invalid sig')

  tx2.recovery = 2
  const fail2 = await DfinityTx.recoverPublicKey(tx2.serialize(), tx2.recovery)
  t.equals(fail2, false, 'should fail with invalid recovery')

  t.end()
})
