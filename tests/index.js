const crypto = require('crypto')
const secp256k1 = require('secp256k1')
const tape = require('tape')
const DfinityTx = require('../')

tape('tests', async t => {
  const tx = new DfinityTx({
    version: 0,
    to: new Uint8Array(20),
    caps: 4,
    ticks: 1000,
    ticksPrice: 0,
    nonce: 0,
    height: 0,
    data: new Uint8Array([])
  })

  const sk = crypto.randomBytes(32)
  const pk = secp256k1.publicKeyCreate(sk)

  const signedTx = await tx.sign(sk)
  // const result = await DfinityTx.recoverPublicKey(signedTx)

  const tx2 = await DfinityTx.deserialize(signedTx)
  t.deepEqual(tx2.publicKey, pk, 'should validate message')
  t.equals(tx2.ticks, '1000')
  t.deepEquals(tx2.serialize(), signedTx)

  tx2.signature[0] = Buffer.alloc(64).fill(0xff)

  const fail = await DfinityTx.recoverPublicKey(tx2.serialize())
  t.notDeepEqual(fail, pk, 'shouldnt recover invalid sig')

  tx2.recovery = 2
  const fail2 = await DfinityTx.recoverPublicKey(tx2.serialize())
  t.equals(fail2, false, 'invalid recovery')

  t.end()
})
