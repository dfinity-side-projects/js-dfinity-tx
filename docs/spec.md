#  Dfinity-tx (sepc256k1 version)

# Data Structure Definitions

## Data Types

### `uintN`
An unsigned integer of _N_ bits,
represented in _N_/8 bytes in [little endian](https://en.wikipedia.org/wiki/Endianness#Little-endian) order.

### `varuintN`
A [LEB128](https://en.wikipedia.org/wiki/LEB128) variable-length integer, limited to _N_ bits (i.e., the values [0, 2^_N_-1]),
represented by _at most_ ceil(_N_/7) bytes that may contain padding `0x80` bytes.

### `bytesN`
A simple byte array of N length.

### `signature`
A secp2556k1 signature. Each Signature is 64 Bytes. and is over th  32 byte sha2-256 hash for the message without the signature and recovery fields

## Tx
An ingress messages or transaction is a message broadcast by clients with the intend of being inculded in the blockchain.

| Field | Type | Description |
|-------|------|-------------|
| type  | `unint1` | a unint that is also 1. This identies that the packets is a tx|
| version | `uint8` | The version of the tx format|
| to | `bytes20` | The ID of the contract that this message is addressed to |
| caps | `varuint32` | The number of response ports that this tx has |
| ticks | `varuint64` | The number of ticks that this message is aloted to run |
| tick_price | `varuint32` | The price in that this message is paying per tick denoted in Dfinities |
| nonce | `varuint64` ||
| timestamp | `varuint128` || 
| payload_len | `varuint32` | The length in bytes of the payload |
| payload | `bytes*` ||
| signature | `signature` ||
| recovery | `unint1` | the recovery bit, used to recover the public key of the signer|
