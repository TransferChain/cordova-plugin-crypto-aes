# Usage and API

All examples run inside an async function after Cordova `deviceready`. They call
the public JavaScript module registered by plugin.xml. Consumer functions such
as consumeKey are placeholders supplied by the caller.

## One-shot interface

`CryptoKit.AES.encrypt(options)` returns Promise<{ mode, iv, data, tag? }>.
`decrypt(options)` returns Promise<Uint8Array>. options contains mode (GCM or
CTR), key, data, optional encryption iv, optional aad and GCM tag for decrypt.
Binary fields accept Uint8Array or ArrayBuffer. Use 32-byte keys for AES-256.
GCM uses a 12-byte nonce and 16-byte tag; CTR uses a 16-byte IV. CTR alone does
not authenticate ciphertext. Never reuse an IV with the same key.

```js
const encrypted = await CryptoKit.AES.encrypt({ mode: 'GCM', key, data })
let plain
try {
  plain = await CryptoKit.AES.decrypt({
    mode: 'GCM', key, iv: encrypted.iv, data: encrypted.data,
    tag: encrypted.tag
  })
  await consumePlaintext(plain)
} finally {
  plain?.fill(0)
}
```

key, data and consumePlaintext belong to the application. Clean owned input keys
after all operations using them have settled.

## Streaming CTR with HMAC

`open(callback)` owns a native transaction. Its callback receives create,
update, finalize and abort; these are not direct global plugin methods.

```js
const file = await CryptoKit.AES.open(async (transaction) => {
  const id = await transaction.create({ operation: 'encrypt', key, keyHmac })
  await transaction.update(id, chunk)
  return transaction.finalize(id)
})
```

operation may be encrypt or decrypt. update accepts chunks up to 1048576 bytes.
finalize returns a Cordova File reference; the File plugin is required. Await
open before consuming file: native commit transfers ownership only on success.
On failure the transaction rolls back its outputs. Decrypt authenticates HMAC
before exposing the output. abort(id) explicitly removes an active session. The
caller is responsible for deleting successfully committed output files.

## Errors and lifecycle

Handle rejected promises or failure callbacks explicitly. Do not substitute
plaintext, predictable keys or weaker algorithms after failure. Keep caller
buffers valid until async work completes, and wipe only buffers you own.

[Developer guide](../DEVELOPMENT.md) · [Security policy](../SECURITY.md) ·
[README](../README.md)
