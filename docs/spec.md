#  Dfinity-tx (sepc256k1 version)

# Data Structure Definitions

Encoding is done with [CBOR](https://en.wikipedia.org/wiki/CBOR).

## Data Types

### `uintN`
An unsigned integer of _N_ bits.

### `varuintN`
A variable-length integer, limited to _N_ bits (i.e., the values [0, 2^_N_-1]).

### `bytesN`
A simple byte array of N length.

### `signature`
A secp256k1 signature. Each signature is 64 bytes and is over the 32 byte sha2-256 hash for the message without the signature and recovery fields.

## Tx
An ingress message or transaction is a message broadcast by clients with the intent of being included in the blockchain.

| Field | Type | Description |
|-------|------|-------------|
| type  | `uint1` | a uint that is also 1. This identifies that the packets is a tx|
| version | `uint8` | The version of the tx format|
| to | `varuint64` | The function reference that this message is addressed to |
| caps | `varuint32` | The number of response ports that this tx has |
| ticks | `varuint64` | The number of ticks that this message is aloted to run |
| tick_price | `varuint32` | The price in that this message is paying per tick denoted in Dfinities |
| nonce | `varuint64` ||
| data | `bytes*` ||
| signature | `signature` ||
| recovery | `uint1` | the recovery bit, used to recover the public key of the signer|
