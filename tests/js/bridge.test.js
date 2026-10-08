import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { it as test } from 'mocha'
import vm from 'node:vm'
import { createRequire } from 'node:module'

const { SendThrow } = createRequire(import.meta.url)('../../www/utils/throw.js')

function bridge(_slug, name, exec) {
  const filename = new URL(`../../www/${name}.js`, import.meta.url),
    module = { exports: {} }

  vm.runInNewContext(readFileSync(filename, 'utf8'), {
    module,
    ArrayBuffer,
    Uint8Array,
    require(id) {
      if (id === './utils/throw') return { SendThrow }

      assert.equal(id, 'cordova/exec')
      return exec
    }
  })
  return module.exports
}

const invalid = { name: 'ArgumentError', code: 'INVALID_ARGUMENT' }

test('AES passes top-level binary arguments and preserves subarray boundaries', async () => {
  const backing = new Uint8Array([99, 10, 20, 30, 88]),
    data = backing.subarray(1, 4),
    key = new Uint8Array(32),
    iv = new Uint8Array(12),
    tag = new Uint8Array(16),
    aes = bridge('aes', 'AES', (success, _reject, service, action, args) => {
      assert.equal(service, 'AES')
      assert.equal(action, 'encrypt')
      assert.equal(args.length, 6)
      assert.equal(args[0].mode, 'GCM')
      assert.deepEqual(Object.keys(args[0]), ['mode'])
      assert.equal(args[1], key.buffer)
      assert.ok(args[2] instanceof ArrayBuffer)
      assert.deepEqual(new Uint8Array(args[2]), new Uint8Array([10, 20, 30]))
      assert.equal(args[3], null)
      assert.equal(args[4], null)
      assert.equal(args[5], null)
      success('GCM', iv.buffer, args[2], tag.buffer)
    }),
    result = await aes.encrypt({ mode: 'GCM', key, data })

  assert.equal(result.mode, 'GCM')
  assert.deepEqual(result.iv, iv)
  assert.deepEqual(result.data, data)
  assert.deepEqual(result.tag, tag)
  assert.deepEqual(backing, new Uint8Array([99, 10, 20, 30, 88]))
})

test('AES CTR result omits tag and decrypt returns binary, including empty data', async () => {
  const aes = bridge(
      'aes',
      'AES',
      (success, _reject, _service, action, args) => {
        if (action === 'encrypt')
          success('CTR', new ArrayBuffer(16), args[2], null)
        else success(args[2])
      }
    ),
    key = new Uint8Array(16),
    encrypted = await aes.encrypt({
      mode: 'CTR',
      key,
      data: new ArrayBuffer(0)
    }),
    decrypted = await aes.decrypt({ ...encrypted, key })

  assert.equal('tag' in encrypted, false)
  assert.ok(decrypted instanceof Uint8Array)
  assert.equal(decrypted.length, 0)
})

test('AES rejects unsupported binary types and missing IV on decryption', async () => {
  const aes = bridge('aes', 'AES', () => assert.fail('Unexpected native call')),
    key = new Uint8Array(16)

  for (const data of [
    'abc',
    [1, 2],
    new Uint16Array(4),
    new DataView(new ArrayBuffer(8))
  ]) {
    await assert.rejects(aes.encrypt({ mode: 'GCM', key, data }), invalid)
  }

  await assert.rejects(
    aes.decrypt({ mode: 'GCM', key, data: new Uint8Array(0) }),
    invalid
  )
  await assert.rejects(aes.encrypt(null), invalid)
})

test('native errors preserve stable code/message without fallback or retry', async () => {
  const failure = {
      name: 'OperationError',
      code: 'AUTHENTICATION_FAILED',
      message: 'AES-GCM authentication failed.'
    },
    aes = bridge('aes', 'AES', (_success, reject) => reject(failure))

  await assert.rejects(
    aes.decrypt({
      mode: 'GCM',
      key: new Uint8Array(16),
      data: new Uint8Array(0),
      iv: new Uint8Array(12),
      tag: new Uint8Array(16)
    }),
    (error) => error === failure
  )
})
