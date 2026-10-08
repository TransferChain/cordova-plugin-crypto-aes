import Foundation
import CoreFoundation
import Security
import CryptoKit
import CommonCrypto
#if canImport(Cordova)
import Cordova
#endif

@objc(AES)
final class AES: CDVPlugin {
    // Stream steps and session maps share one serial queue. One-shot GCM/CTR
    // operations use a separate Cordova background execution path.
    // QUEUE CONFINEMENT PROTOCOL
    // A serial DispatchQueue orders blocks, not OS thread identities. Session maps
    // and stream state are owned by this queue, so no NSLock is needed while every
    // access obeys that rule. An async continuation on another queue must dispatch
    // back before accessing this state. Calling sync on this queue from inside its
    // own block would deadlock.
    //
    // One-shot GCM/CTR uses Cordova background dispatch and call-local state. The
    // application worker bounds submitted operations separately. Neither queue is
    // a memory manager or a guarantee of the same thread throughout a transaction.
    private let streamQueue = DispatchQueue(label: "com.transferchain.aes.streams")

    // RESOURCE REGISTRY: KEEP THESE THREE COLLECTIONS CONSISTENT
    // sessions maps a session ID to its active cipher/file state. owners links that
    // session to its transaction. transactions tracks completed output files that
    // still need rollback protection. Finalization removes a session and its owner
    // entry, but keeps the finished file in transactions until commit.
    //
    // State progression: open -> create -> update* -> finalize/abort -> commit.
    // One transaction can contain multiple sessions. A failure rolls back the owning
    // transaction, including files produced by earlier sessions in that transaction.
    // These maps are accessed through the serialized stream execution path. Do not
    // introduce direct access from a callback on another thread.
    private var sessions: [String: StreamSession] = [:]
    private var owners: [String: String] = [:]
    private var transactions: [String: [URL]] = [:]

    @objc(open:) func open(_ command: CDVInvokedUrlCommand) { stream("open", command) }

    @objc(create:) func create(_ command: CDVInvokedUrlCommand) { stream("create", command) }

    @objc(update:) func update(_ command: CDVInvokedUrlCommand) { stream("update", command) }

    @objc(finalize:) func finalize(_ command: CDVInvokedUrlCommand) { stream("finalize", command) }

    @objc(abort:) func abort(_ command: CDVInvokedUrlCommand) { stream("abort", command) }

    @objc(commit:) func commit(_ command: CDVInvokedUrlCommand) { stream("commit", command) }

    @objc(rollback:) func rollbackCommand(_ command: CDVInvokedUrlCommand) { stream("rollback", command) }

    override func onReset() {
        streamQueue.async {
            for id in Array(self.transactions.keys) { self.rollback(id) }
        }
    }

    deinit {
        for session in sessions.values { session.close() }

        for files in transactions.values {
            for url in files { try? FileManager.default.removeItem(at: url) }
        }
    }

    // Completed files still belong to the transaction until commit. On callback
    // or native failure, close its sessions and remove its output files.
    private func rollback(_ id: String) {
        for sessionID in Array(owners.keys) where owners[sessionID] == id {
            sessions.removeValue(forKey: sessionID)?.close()
            owners.removeValue(forKey: sessionID)
        }

        for url in transactions.removeValue(forKey: id) ?? [] {
            try? FileManager.default.removeItem(at: url)
        }
    }

    private func stream(_ action: String, _ command: CDVInvokedUrlCommand) {
        streamQueue.async {
            var transactionID: String?

            do {
                let args = command.arguments ?? []
                var response: String

                if action == "open" {
                    guard args.isEmpty else { throw Self.invalid("open does not accept native arguments.") }

                    guard self.transactions.count < 16 else {
                        throw Failure(code: "RESOURCE_LIMIT", message: "Too many active AES transactions.")
                    }

                    response = UUID().uuidString
                    self.transactions[response] = []
                } else if action == "commit" || action == "rollback" {
                    guard args.count == 1, let id = args[0] as? String else {
                        throw Self.invalid("Expected a transaction ID.")
                    }

                    transactionID = id
                    guard self.transactions[id] != nil else {
                        throw Failure(code: "NOT_FOUND", message: "Key does not exists!")
                    }

                    if action == "commit" {
                        guard !self.owners.values.contains(id) else {
                            throw Self.invalid("Finalize or abort every session before committing.")
                        }

                        self.transactions.removeValue(forKey: id)
                    } else { self.rollback(id) }

                    response = action
                } else if action == "create" {
                    guard args.count == 3, let options = args[0] as? [String: Any] else {
                        throw Self.invalid("Expected stream options and two keys.")
                    }

                    let id = try Self.string(options, "transactionID")

                    transactionID = id
                    guard self.transactions[id] != nil else {
                        throw Failure(code: "NOT_FOUND", message: "Key does not exists!")
                    }

                    let operation = try Self.string(options, "operation")

                    guard operation == "encrypt" || operation == "decrypt" else {
                        throw Self.invalid("operation must be encrypt or decrypt.")
                    }

                    guard self.sessions.count < 16 else {
                        throw Failure(code: "RESOURCE_LIMIT", message: "Too many active AES sessions.")
                    }

                    var key = try Self.bytes(args, 1, "key", 16, 32)

                    defer { key.resetBytes(in: 0..<key.count) }

                    guard [16, 24, 32].contains(key.count) else { throw Self.invalid("key must contain 16, 24 or 32 bytes.") }

                    var keyHmac = try Self.bytes(args, 2, "keyHmac", 1, 1048576)

                    defer { keyHmac.resetBytes(in: 0..<keyHmac.count) }

                    let session = try StreamSession(key, keyHmac, operation == "encrypt")

                    response = UUID().uuidString
                    self.sessions[response] = session
                    self.owners[response] = id
                } else {
                    guard args.count == (action == "update" ? 2 : 1), let id = args[0] as? String else {
                        throw Self.invalid("Expected a session ID and action arguments.")
                    }

                    guard let session = self.sessions[id], let owner = self.owners[id] else {
                        throw Failure(code: "NOT_FOUND", message: "Key does not exists!")
                    }

                    transactionID = owner
                    if action == "update" {
                        var data = try Self.bytes(args, 1, "data", 0, 1048576)

                        defer { data.resetBytes(in: 0..<data.count) }

                        try session.update(data)
                        response = "updated"
                    } else {
                        if action == "finalize" {
                            let url = try session.finish()

                            self.transactions[owner]?.append(url)
                            response = url.absoluteString
                        } else { response = "aborted" }

                        session.close()
                        self.sessions.removeValue(forKey: id)
                        self.owners.removeValue(forKey: id)
                    }
                }

                self.commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_OK, messageAs: response), callbackId: command.callbackId)
            } catch let error as Failure {
                if let id = transactionID { self.rollback(id) }

                self.fail(command, error.code, error.message)
            } catch {
                if let id = transactionID { self.rollback(id) }

                self.fail(command, "OPERATION_FAILED", "Native AES stream operation failed.")
            }
        }
    }

    // Match Android/Go: 01 | IV(16) | ciphertext | SHA512-HMAC(64).
    // Decryption spools ciphertext, then decrypts in a second pass after validation.
    private final class StreamSession {
        let encrypt: Bool
        var key: Data
        var iv = Data(count: 16)
        var mac: HMAC<SHA512>?

        // NATIVE HANDLE OWNERSHIP
        // Optional distinguishes absent/released state from a live CommonCrypto cipher.
        // The same handle must survive updates so the CTR counter advances continuously.
        // StreamSession is a reference type with one resource owner; copying resource
        // ownership into unrelated tasks would risk concurrent use or double release.
        // Incremental HMAC is also session state. Mutable Data holds bytes we can reset;
        // releasing a provider handle does not prove all provider copies were overwritten.
        var cryptor: CCCryptorRef?
        var spool: URL
        var output: URL?
        var writer: FileHandle?
        var header = Data()
        var tail = Data()
        var total = 0
        var completed = false

        init(_ key: Data, _ keyHmac: Data, _ encrypt: Bool) throws {
            self.key = key
            self.encrypt = encrypt
            self.mac = HMAC<SHA512>(key: SymmetricKey(data: keyHmac))
            let directory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("transferchain-aes", isDirectory: true)

            spool = directory.appendingPathComponent(UUID().uuidString + ".part")
            do {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                writer = try makeFile(spool)
                if encrypt {
                    let status = iv.withUnsafeMutableBytes { buffer in
                        SecRandomCopyBytes(kSecRandomDefault, 16, buffer.baseAddress!)
                    }

                    guard status == errSecSuccess else { throw AES.invalid("Unable to generate an IV.") }

                    try startCipher()
                    try writer!.write(contentsOf: Data([1]) + iv)
                    mac!.update(data: iv)
                }
            } catch { close(); throw error }
        }

        // OUTPUT FILE POLICY
        // Files are created in the application's cache directory with owner-only POSIX
        // permissions and complete iOS file protection. Cache files are working outputs,
        // not durable application records; callers must explicitly retain/move committed
        // results when they need persistence.
        //
        // Device locking can make protected files unavailable during an operation. Let
        // that I/O failure enter transaction rollback rather than weakening protection
        // or retrying the write into a less protected directory.
        private func makeFile(_ url: URL) throws -> FileHandle {
            guard FileManager.default.createFile(atPath: url.path, contents: nil,
                attributes: [.posixPermissions: 0o600, .protectionKey: FileProtectionType.complete]) else {
                throw Failure(code: "OPERATION_FAILED", message: "Unable to create AES output file.")
            }

            return try FileHandle(forWritingTo: url)
        }

        private func startCipher() throws {
            let status = key.withUnsafeBytes { k in
                iv.withUnsafeBytes { v in
                    CCCryptorCreateWithMode(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
                        CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding),
                        v.baseAddress, k.baseAddress, key.count, nil, 0, 0,
                        CCModeOptions(kCCModeOptionCTR_BE), &cryptor)
                }
            }

            guard status == kCCSuccess else {
                throw Failure(code: "OPERATION_FAILED", message: "Unable to create AES stream cipher.")
            }
        }

        private func transform(_ data: Data, _ final: Bool = false) throws -> Data {
            var result = Data(count: data.count + 16)
            var moved = 0
            let capacity = result.count
            let status = result.withUnsafeMutableBytes { out in
                if final { return CCCryptorFinal(cryptor!, out.baseAddress, capacity, &moved) }

                return data.withUnsafeBytes { input in
                    CCCryptorUpdate(cryptor!, input.baseAddress, data.count, out.baseAddress, capacity, &moved)
                }
            }

            guard status == kCCSuccess else {
                result.resetBytes(in: 0..<result.count)
                throw Failure(code: "OPERATION_FAILED", message: "AES stream cipher failed.")
            }

            result.count = moved
            return result
        }

        // INCREMENTAL INPUT PARSING
        // Encryption feeds the existing cipher, then adds emitted ciphertext to HMAC and
        // spool. Recreating the cipher for each chunk would restart the counter and break
        // the stream. An empty update must not reset any state.
        //
        // Decryption has three logical regions: a 17-byte version/IV header, ciphertext,
        // and a 64-byte trailing HMAC. These regions can cross any update boundary. Until
        // finalize, the most recent 64 bytes are candidates for the tag and remain in tail.
        // For example, 80 pending bytes yield 16 ciphertext bytes and a 64-byte tail.
        // The spool contains ciphertext only; authentication is completed in finish.
        func update(_ data: Data) throws {
            let previous = total

            total += data.count
            guard total <= 1073741824 + (encrypt ? 0 : 81) else {
                throw Failure(code: "RESOURCE_LIMIT", message: "AES stream exceeds 1 GiB.")
            }

            if encrypt {
                try AES.checkCounter(iv, total)
                if data.isEmpty { return }

                var encrypted = try transform(data)

                defer { encrypted.resetBytes(in: 0..<encrypted.count) }

                mac!.update(data: encrypted)
                try writer!.write(contentsOf: encrypted)
                return
            }

            let offset = min(17 - header.count, data.count)

            header.append(data.prefix(offset))
            if header.count < 17 { return }

            guard header[0] == 1 else { throw AES.invalid("Unsupported ctr-with-hmac envelope version.") }

            if previous < 17 {
                iv = header.subdata(in: 1..<17)
                mac!.update(data: iv)
            }

            var pending = tail

            pending.append(data.dropFirst(offset))
            defer { pending.resetBytes(in: 0..<pending.count) }

            // Retain a sliding 64-byte tail for the final HMAC. A transport chunk may end
            // anywhere, including in the middle of the tag; chunk size is not a delimiter.
            let count = max(0, pending.count - 64)

            if count > 0 {
                mac!.update(data: pending.prefix(count))
                try writer!.write(contentsOf: pending.prefix(count))
            }

            tail.resetBytes(in: 0..<tail.count)
            tail = Data(pending.suffix(pending.count - count))
        }

        // FINALIZATION IS NOT TRANSACTION COMMIT
        // On encryption, flush the cipher, authenticate its final bytes, append the HMAC,
        // and close the writer before promoting the temporary path to a result path.
        // On decryption, validate envelope size and the complete HMAC first. Only then
        // read the ciphertext spool again and write authenticated plaintext to output.
        //
        // An empty plaintext is valid: its encoded stream still has 1 + 16 + 64 bytes.
        // Missing header/tag bytes are malformed input, not an empty file. If any step
        // throws, transaction rollback closes the session and attempts to remove outputs.
        // The caller receives a path here; the transaction retains rollback ownership.
        func finish() throws -> URL {
            if encrypt {
                var end = try transform(Data(), true)

                defer { end.resetBytes(in: 0..<end.count) }

                mac!.update(data: end)
                try writer!.write(contentsOf: end)
                try writer!.write(contentsOf: Data(mac!.finalize()))
                try writer!.close();
                writer = nil
                let url = spool.deletingLastPathComponent().appendingPathComponent(UUID().uuidString + ".bin")

                output = url
                try FileManager.default.moveItem(at: spool, to: url)
            } else {
                guard header.count == 17, tail.count == 64 else {
                    throw AES.invalid("Incomplete ctr-with-hmac envelope.")
                }

                // CryptoKit compares MAC values in constant time, including this incremental MAC.
                // The left operand remains CryptoKit's authentication-code type, invoking MAC
                // comparison behavior. Converting both operands into ordinary arrays and using
                // an early-exit loop would change the timing properties. The whole ciphertext
                // spool is authenticated before plaintext creation; independent chunk tags would
                // be a different protocol and cannot replace this final stream tag.
                guard mac!.finalize() == tail else {
                    throw Failure(code: "AUTHENTICATION_FAILED", message: "AES-CTR HMAC authentication failed.")
                }

                try writer!.close();
                writer = nil
                try AES.checkCounter(iv, total - 81)
                // Only start decrypting after authenticating the entire ciphertext spool.
                // This prevents unverified plaintext from becoming a returned file.
                try startCipher()
                let url = spool.deletingLastPathComponent().appendingPathComponent(UUID().uuidString + ".bin")

                output = url
                let decoded = try makeFile(url)

                defer { try? decoded.close() }

                let input = try FileHandle(forReadingFrom: spool)

                defer { try? input.close() }

                while true {
                    // Each iteration owns a bounded input/output pair. The defer statements run
                    // at the end of this iteration, including the EOF break and thrown errors.
                    var chunk = try input.read(upToCount: 16384) ?? Data()

                    defer { chunk.resetBytes(in: 0..<chunk.count) }

                    if chunk.isEmpty { break }

                    var plain = try transform(chunk)

                    defer { plain.resetBytes(in: 0..<plain.count) }

                    try decoded.write(contentsOf: plain)
                }

                var end = try transform(Data(), true)

                defer { end.resetBytes(in: 0..<end.count) }

                try decoded.write(contentsOf: end)
                try decoded.close()
            }

            completed = true
            return output!
        }

        // SESSION CLEANUP AND OUTPUT OWNERSHIP
        // Close the writer and remove the temporary spool on both success and failure.
        // An incomplete output belongs to this session and must also be removed. A
        // completed output is retained here because transaction rollback/commit now
        // controls it; deleting it unconditionally would break successful finalize.
        //
        // Clear owned key/header/tail buffers and release provider state. Releasing a
        // Cipher/MAC reference is not proof that every provider-internal copy was wiped.
        // File removal in this cleanup path is best-effort; it is not a crash-recovery
        // journal or a guarantee that an OS deletion failure has been repaired.
        func close() {
            try? writer?.close();
            writer = nil
            try? FileManager.default.removeItem(at: spool)
            if !completed, let url = output { try? FileManager.default.removeItem(at: url) }

            if let context = cryptor { CCCryptorRelease(context); cryptor = nil }

            key.resetBytes(in: 0..<key.count)
            iv.resetBytes(in: 0..<iv.count)
            header.resetBytes(in: 0..<header.count)
            tail.resetBytes(in: 0..<tail.count)
            mac = nil
        }
    }

    @objc(encrypt:)
    func encrypt(_ command: CDVInvokedUrlCommand) {
        run("encrypt", command)
    }

    @objc(decrypt:)
    func decrypt(_ command: CDVInvokedUrlCommand) {
        run("decrypt", command)
    }

    private func run(_ action: String, _ command: CDVInvokedUrlCommand) {
        commandDelegate.run(inBackground: {
            do {
                guard command.arguments.count == 6,
                      let options = command.arguments[0] as? [String: Any] else {
                    throw Self.invalid("Expected one options object.")
                }

                let result = try Self.perform(action, options, command.arguments)

                self.commandDelegate.send(result, callbackId: command.callbackId)
            } catch let error as Failure {
                self.fail(command, error.code, error.message)
            } catch {
                self.fail(command, "OPERATION_FAILED", "Native AES operation failed.")
            }
        })
    }

    private static func perform(_ action: String, _ options: [String: Any],
                                _ args: [Any]) throws -> CDVPluginResult {
        let mode = try string(options, "mode")

        guard mode == "GCM" || mode == "CTR" else {
            throw invalid("mode must be GCM or CTR.")
        }

        let encrypt = action == "encrypt"
        if mode == "CTR" && (!(args[4] is NSNull) || !(args[5] is NSNull)) {
            throw invalid("CTR does not support aad or tag.")
        }

        if encrypt && !(args[5] is NSNull) {
            throw invalid("encrypt does not accept tag.")
        }

        var key = try bytes(args, 1, "key", 16, 32)

        defer { key.resetBytes(in: 0..<key.count) }

        guard [16, 24, 32].contains(key.count) else {
            throw invalid("key must contain 16, 24 or 32 bytes.")
        }

        var data = try bytes(args, 2, "data", 0, 1048576)

        defer { data.resetBytes(in: 0..<data.count) }

        let ivLength = mode == "GCM" ? 12 : 16
        var iv: Data

        if encrypt && args[3] is NSNull {
            iv = Data(count: ivLength)
            let status = iv.withUnsafeMutableBytes { buffer in
                SecRandomCopyBytes(kSecRandomDefault, ivLength, buffer.baseAddress!)
            }

            guard status == errSecSuccess else {
                throw Failure(code: "OPERATION_FAILED", message: "Native IV generation failed.")
            }
        } else {
            iv = try bytes(args, 3, "iv", ivLength, ivLength)
        }

        // NONCE AND AAD RESPONSIBILITIES
        // CryptoKit Nonce holds the IV; SealedBox groups ciphertext and tag; open verifies
        // authenticity. AAD is authenticated but not encrypted or stored in ciphertext,
        // so the caller must reproduce it exactly during decryption.
        // The API accepts explicit IVs. Length validation cannot prove nonce uniqueness
        // across calls; callers supplying IVs must enforce that rule. Omitted encryption
        // IVs come from the OS random source. Never reuse key/nonce for different plaintext.
        if mode == "GCM" {
            var aad = Data()

            if !(args[4] is NSNull) { aad = try bytes(args, 4, "aad", 0, 1048576) }

            defer { aad.resetBytes(in: 0..<aad.count) }

            let aesKey = SymmetricKey(data: key)

            if encrypt {
                let sealed = try CryptoKit.AES.GCM.seal(data, using: aesKey,
                                             nonce: CryptoKit.AES.GCM.Nonce(data: iv), authenticating: aad)

                return CDVPluginResult(status: CDVCommandStatus_OK,
                    messageAsMultipart: [mode, iv, sealed.ciphertext, sealed.tag])
            }

            let tag = try bytes(args, 5, "tag", 16, 16)

            // Reconstruct CryptoKit's authenticated container from the bridge fields.
            // Constructing it does not verify authenticity; CryptoKit.AES.GCM.open below does.
            let sealed = try CryptoKit.AES.GCM.SealedBox(nonce: CryptoKit.AES.GCM.Nonce(data: iv),
                                               ciphertext: data, tag: tag)

            do {
                var output = try CryptoKit.AES.GCM.open(sealed, using: aesKey, authenticating: aad)

                defer { output.resetBytes(in: 0..<output.count) }

                return CDVPluginResult(status: CDVCommandStatus_OK, messageAsArrayBuffer: output)
            } catch {
                throw Failure(code: "AUTHENTICATION_FAILED", message: "AES-GCM authentication failed.")
            }
        }

        try checkCounter(iv, data.count)
        var output = try ctr(data, key, iv, encrypt)

        defer { output.resetBytes(in: 0..<output.count) }

        if !encrypt { return CDVPluginResult(status: CDVCommandStatus_OK, messageAsArrayBuffer: output) }

        return CDVPluginResult(status: CDVCommandStatus_OK,
                               messageAsMultipart: [mode, iv, output, NSNull()])
    }

    private static func checkCounter(_ iv: Data, _ length: Int) throws {
        var carry = max(0, (length + 15) / 16 - 1)

        for byte in iv.reversed() { carry = (Int(byte) + carry) >> 8 }

        if carry != 0 { throw invalid("CTR counter would wrap for this data length.") }
    }

    // CryptoKit handles GCM; CommonCrypto handles CTR. CTR alone provides no
    // authentication. Callers requiring HMAC must use the stream interface.
    private static func ctr(_ data: Data, _ key: Data, _ iv: Data,
                            _ encrypt: Bool) throws -> Data {
        var cryptor: CCCryptorRef?
        let created = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCryptorCreateWithMode(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
                    CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding),
                    ivBytes.baseAddress, keyBytes.baseAddress, key.count,
                    nil, 0, 0, CCModeOptions(kCCModeOptionCTR_BE), &cryptor)
            }
        }

        guard created == kCCSuccess, let context = cryptor else {
            throw Failure(code: "OPERATION_FAILED", message: "Unable to create AES-CTR context.")
        }

        // Release the CommonCrypto context on every exit, including empty data and
        // errors. Borrowed key/IV pointers from the creation closures must not escape.
        defer { CCCryptorRelease(context) }

        if data.isEmpty { return Data() }

        var output = Data(count: data.count + kCCBlockSizeAES128)
        var moved = 0
        var finalMoved = 0
        let capacity = output.count
        let status = data.withUnsafeBytes { inputBytes in
            output.withUnsafeMutableBytes { outputBytes -> CCCryptorStatus in
                let updated = CCCryptorUpdate(context, inputBytes.baseAddress, data.count,
                                              outputBytes.baseAddress, capacity, &moved)
                if updated != kCCSuccess { return updated }

                return CCCryptorFinal(context, outputBytes.baseAddress!.advanced(by: moved),
                                      capacity - moved, &finalMoved)
            }
        }

        // CTR has no padding, so output length must equal input length. Check both
        // the provider status and byte count before exposing the resulting Data.
        guard status == kCCSuccess, moved + finalMoved == data.count else {
            output.resetBytes(in: 0..<output.count)
            throw Failure(code: "OPERATION_FAILED", message: "Native AES-CTR operation failed.")
        }

        output.count = moved + finalMoved
        return output
    }

    private static func integer(_ options: [String: Any], _ name: String,
                                _ min: Int, _ max: Int) throws -> Int {
        guard let value = options[name] as? NSNumber,
              CFGetTypeID(value) != CFBooleanGetTypeID() else {
            throw invalid("\(name) must be an integer.")
        }

        let number = value.doubleValue

        guard number.isFinite, number.rounded(.towardZero) == number,
              number >= Double(min), number <= Double(max) else {
            throw invalid("\(name) is outside the supported integer range.")
        }

        return Int(number)
    }

    private static func string(_ options: [String: Any], _ name: String) throws -> String {
        guard let value = options[name] as? String else {
            throw invalid("\(name) must be a string.")
        }

        return value
    }

    private static func bytes(_ args: [Any], _ index: Int, _ name: String,
                              _ min: Int, _ max: Int) throws -> Data {
        guard let value = args[index] as? Data,
              value.count >= min, value.count <= max else {
            throw invalid("\(name) must be an ArrayBuffer within the byte limits.")
        }

        return value
    }

    private static func invalid(_ message: String) -> Failure {
        return Failure(code: "INVALID_ARGUMENT", message: message)
    }

    private struct Failure: Error {
        let code: String
        let message: String
    }

    private func fail(_ command: CDVInvokedUrlCommand, _ code: String, _ message: String) {
        let error = ["code": code, "message": message,
                     "name": code == "INVALID_ARGUMENT" ? "ArgumentError" : "OperationError"]

        commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_ERROR,
                                            messageAs: error), callbackId: command.callbackId)
    }
}
