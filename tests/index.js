const crypto = require('crypto')
const secp256k1 = require('secp256k1')
const tape = require('tape')
const DfinityTx = require('../')

tape('tests', async t => {
  const tx = new DfinityTx({
    version: 1,
    to: 10,
    caps: 4,
    ticks: 1000,
    ticksPrice: 0,
    nonce: 0,
    data: new Uint8Array([])
  })

  const unsignedTx = tx.serialize()
  const tx1 = await DfinityTx.deserialize(unsignedTx)
  t.equals(tx1.ticks, 1000, 'should validate unsigned message')
  t.deepEquals(tx1.serialize(), unsignedTx)

  const sk = crypto.randomBytes(32)
  const pk = secp256k1.publicKeyCreate(sk)

  const signedTx = await tx.sign(sk)

  const tx2 = await DfinityTx.deserialize(signedTx)
  t.equals(tx2.ticks, 1000, 'should validate signed message')
  t.deepEqual(tx2.publicKey, pk, 'should recover signed message')
  t.deepEquals(tx2.serialize(), signedTx)

  tx2.signature[0] = Buffer.alloc(64).fill(0xff)

  const fail = await DfinityTx.recoverPublicKey(tx2.serialize(), tx2.recovery)
  t.notDeepEqual(fail, pk, 'shouldn\'t recover invalid sig')

  tx2.recovery = 2
  const fail2 = await DfinityTx.recoverPublicKey(tx2.serialize(), tx2.recovery)
  t.equals(fail2, false, 'should fail with invalid recovery')

  t.end()
})
