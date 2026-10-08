const exec = require('cordova/exec'),
  { SendThrow } = require('./utils/throw')

function invalid(message) {
  return { name: 'ArgumentError', code: 'INVALID_ARGUMENT', message }
}

function optionsObject(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw invalid('Expected an options object.')
  }
}

// Use ArrayBuffer for Cordova binary transport. For a subarray, send only
// its visible range so unrelated bytes in the backing buffer are not exposed.
function buffer(value, name, min, max, optional = false) {
  if (typeof value === 'undefined' && optional) return null

  // WHY Uint8Array / ArrayBuffer
  // Uint8Array provides byte indexing and an exact visible range. ArrayBuffer is
  // its storage and the binary type understood by Cordova. Strings would require
  // an encoding for arbitrary bytes; numeric arrays would need element conversion.
  // Only ordinary ArrayBuffer-backed data is accepted, excluding shared memory.
  //
  // The full-buffer path forwards storage without a snapshot. Callers must avoid
  // mutating input while the asynchronous operation is pending. A partial view is
  // copied to avoid exposing surrounding bytes. This helper does not wipe caller
  // inputs, and Object.freeze on an API does not make input buffers immutable.
  const bytes =
    value instanceof Uint8Array
      ? value
      : value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : null

  if (
    !bytes ||
    !(bytes.buffer instanceof ArrayBuffer) ||
    bytes.byteLength < min ||
    bytes.byteLength > max
  ) {
    throw invalid(
      `${name} must be a Uint8Array or ArrayBuffer within the byte limits.`
    )
  }

  // A view spanning the full buffer can be forwarded without copying. A partial
  // view needs a slice because Cordova receives the ArrayBuffer, not the view's
  // byteOffset/byteLength metadata.
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes.buffer
  }

  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  )
}

// One-shot GCM/CTR calls are separate from streaming. Binary fields are
// top-level arguments; their order must match Java/Swift perform entry points.
function call(action, options) {
  optionsObject(options)

  const args = [
    { mode: options.mode },
    buffer(options.key, 'key', 16, 32),
    buffer(options.data, 'data', 0, 1048576),
    buffer(options.iv, 'iv', 12, 16, action === 'encrypt'),
    buffer(options.aad, 'aad', 0, 1048576, true),
    buffer(options.tag, 'tag', 16, 16, true)
  ]

  return new Promise((resolve, reject) => {
    const success =
      action === 'decrypt'
        ? (data) => resolve(new Uint8Array(data))
        : // Native encryption uses a multipart callback. Its field order is part of
          // our bridge contract; decrypt instead returns a single binary payload.
          (mode, iv, data, tag) => {
            const result = {
              mode,
              iv: new Uint8Array(iv),
              data: new Uint8Array(data)
            }

            if (tag !== null) result.tag = new Uint8Array(tag)

            resolve(result)
          }

    exec(success, reject, 'AES', action, args)
  })
}

function invoke(action, args) {
  return new Promise((resolve, reject) => {
    exec(resolve, reject, 'AES', action, args)
  })
}

// Native finalize returns a URL. The Cordova File plugin resolves it to a
// File reference without loading the entire output into JavaScript memory.
function fileReference(url) {
  return new Promise((resolve, reject) => {
    if (typeof globalThis.window?.resolveLocalFileSystemURL !== 'function') {
      reject({
        code: 'NATIVE_UNAVAILABLE',
        message: 'Cordova File plugin is unavailable.'
      })
      return
    }

    window.resolveLocalFileSystemURL(
      url,
      (entry) => {
        entry.file(
          (file) => {
            if (!file)
              reject({ code: 'NOT_FOUND', message: 'Key does not exists!' })
            else resolve(file)
          },
          () =>
            reject({
              code: 'OPERATION_FAILED',
              message: 'Unable to read the AES output file.'
            })
        )
      },
      () =>
        reject({
          code: 'NOT_FOUND',
          message: 'AES output file does not exist.'
        })
    )
  })
}

// Drain pending operations after the transaction callback finishes. An operation
// failure prevents commit even if the caller catches it. Finalize prepares the
// file; ownership is transferred only when the native transaction commits.
async function open(operation) {
  if (typeof operation !== 'function')
    throw invalid('Expected a transaction callback.')

  const transactionID = await invoke('open', []),
    sessions = new Set(),
    enqueue = (operation) => {
      if (closed) return Promise.reject(invalid('AES transaction is closed.'))

      const task = pending.then(() => {
        if (failed) return Promise.reject(failure)

        return operation()
      })

      // Keep a settled queue tail so cleanup can await every submitted operation.
      // Return the original task to its caller, while remembering the first failure
      // here so a caught rejection cannot turn the transaction into a success.
      pending = task.catch((error) => {
        if (!failed) {
          failed = true
          failure = error
        }
      })
      return task
    },
    requireSession = (sessionID) => {
      if (!sessions.has(sessionID))
        throw { code: 'NOT_FOUND', message: 'Key does not exists!' }
    },
    transaction = Object.freeze({
      create: (options) =>
        enqueue(async () => {
          optionsObject(options)
          const sessionID = await invoke('create', [
            { transactionID, operation: options.operation ?? 'encrypt' },
            buffer(options.key, 'key', 16, 32),
            buffer(options.keyHmac, 'keyHmac', 1, 1048576)
          ])

          sessions.add(sessionID)
          return sessionID
        }),
      update: (sessionID, data) =>
        enqueue(async () => {
          requireSession(sessionID)
          await invoke('update', [sessionID, buffer(data, 'data', 0, 1048576)])
        }),
      finalize: (sessionID) =>
        enqueue(async () => {
          requireSession(sessionID)
          // Resolve the native output to a File before committing. If File resolution
          // fails, the transaction still owns the completed output and can roll it back.
          const url = await invoke('finalize', [sessionID]),
            file = await fileReference(url)

          sessions.delete(sessionID)
          return file
        }),
      abort: (sessionID) =>
        enqueue(async () => {
          requireSession(sessionID)
          await invoke('abort', [sessionID])
          sessions.delete(sessionID)
        })
    })

  // TRANSACTION STATE
  // pending is the queue tail, not the public operation result. Each new task chains
  // onto it so update order matches call order even when calls are submitted rapidly.
  // failed/failure are sticky: the first operation error poisons the transaction.
  // closed prevents escaped handles from accepting work after the callback finishes.
  //
  // The callback may return before an unawaited task settles. Draining pending below
  // keeps native resources alive until those tasks finish. Native commit happens only
  // after the drain and the session completeness check. A catch in application code
  // can inspect an error, but cannot clear this transaction's failure state.
  let pending = Promise.resolve(),
    failure,
    failed = false,
    closed = false

  try {
    const result = await operation(transaction)

    closed = true
    await pending
    if (failed) SendThrow(failure)

    if (sessions.size)
      SendThrow(invalid('Finalize or abort every session before committing.'))

    closed = true
    // All sessions must already be finalized or aborted. Commit removes native
    // rollback ownership; the caller is now responsible for the returned files.
    await invoke('commit', [transactionID])
    return result
  } catch (error) {
    failed = true
    failure = error
    closed = true
    await pending
    closed = true
    // A native action may already have rolled back the transaction. NOT_FOUND
    // therefore means cleanup already ran; other rollback errors still propagate.
    await invoke('rollback', [transactionID]).catch((rollbackError) => {
      if (rollbackError?.code !== 'NOT_FOUND')
        return Promise.reject(rollbackError)
    })
    return Promise.reject(error)
  }
}

// TWO API SHAPES, TWO OUTPUT CONTRACTS
//
// 1. encrypt/decrypt(options) handles bounded, one-shot GCM or CTR payloads.
//    Encryption resolves { mode, iv, data, tag? }; decryption resolves Uint8Array.
//    Persist the IV with ciphertext. GCM additionally requires the original tag
//    and identical AAD to decrypt. Standard CTR has no authentication tag.
// 2. open(callback) owns a streaming CTR-with-HMAC transaction. The callback gets
//    create/update/finalize/abort methods; GCM/CTR are not session operations.
//
// Example flow, with caller-provided independent AES/HMAC keys and binary chunks:
//   const file = await CryptoKit.AES.open(async tx => {
//     const id = await tx.create({ operation: 'encrypt', key, keyHmac })
//     await tx.update(id, firstChunk)
//     await tx.update(id, secondChunk)
//     return tx.finalize(id)
//   })
//
// Each update accepts up to 1 MiB. Use operation: 'decrypt' and feed the complete
// encoded stream to recover a File; chunk boundaries need not match encryption.
// finalize ends one session, while successful open commits its transaction.
// After open resolves, the caller owns the output file and its eventual removal.
// Await open before consuming a returned file; failure may remove finalized files.
module.exports = Object.freeze({
  open,
  async encrypt(options) {
    return call('encrypt', options)
  },
  async decrypt(options) {
    return call('decrypt', options)
  }
})
