[![NPM Package](https://img.shields.io/npm/v/dfinity-tx.svg?style=flat-square)](https://www.npmjs.org/package/dfinity-tx)
[![Build Status](https://img.shields.io/travis/dfinity/js-dfinity-tx.svg?branch=master&style=flat-square)](https://travis-ci.org/dfinity/js-dfinity-tx)
[![Coverage Status](https://img.shields.io/coveralls/dfinity/js-dfinity-tx.svg?style=flat-square)](https://coveralls.io/r/dfinity/js-dfinity-tx)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

# Synopsis

This library provides basic functions for creating and validating txs

## Installation
`npm install dfinity-tx`

## Usage

```javascript
const DfinityTx = require('dfinity-tx')
const crypto = require('crypto')

// create a new tx
const tx = new DfinityTx({
  version: 0,
  to: new Uint8Array(20),
  caps: 4,
  ticks: 1000,
  ticksPrice: 0,
  nonce: 0,
  data: new Uint8Array([])
})

// get properties from
tx.ticks // 1000

// set properties
tx.nonce = 1

const secretKey = crypto.randomBytes(32)

// sign the tx, this returns a signed serialized tx
const signedTx = await tx.sign(secretKey)

// parse a tx
const tx2 = DfinityTx.deserialize(signedTx)

// get the public key used to sign the message
tx2.publicKey
```

## API
[./docs/](./docs/index.md)

## Specification
[./docs/](./docs/spec.md)

## License

[**(C) 2018 DFINITY STIFTUNG**](http://dfinity.network)

All code and designs are open sourced under GPL V3.

![image](https://user-images.githubusercontent.com/6457089/32753794-10f4cbc2-c883-11e7-8dcf-ff8088b38f9f.png)
