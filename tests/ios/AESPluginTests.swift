import XCTest
import Cordova
import CryptoTestSupport
@testable import NativeCryptoPlugins

final class AESPluginTests: XCTestCase {
    private func invoke(_ plugin: CDVPlugin, _ action: String, _ args: [Any],
                        file: StaticString = #filePath, line: UInt = #line) throws -> CDVPluginResult {
        let done = expectation(description: action)
        done.assertForOverFulfill = true
        let delegate = CryptoTestDelegate()
        var captured: CDVPluginResult?
        delegate.onResult = { result in
            captured = result
            done.fulfill()
        }
        plugin.commandDelegate = delegate
        let command = CDVInvokedUrlCommand(arguments: args, callbackId: "test",
                                          className: "test", methodName: action)
        _ = plugin.perform(NSSelectorFromString(action + ":"), with: command)
        wait(for: [done], timeout: 60)
        return try XCTUnwrap(captured, file: file, line: line)
    }

    private func ok(_ plugin: CDVPlugin, _ action: String, _ args: [Any],
                    file: StaticString = #filePath, line: UInt = #line) throws -> CDVPluginResult {
        let result = try invoke(plugin, action, args)
        XCTAssertEqual(result.status.intValue, Int(CDVCommandStatus_OK.rawValue), file: file, line: line)
        return result
    }

    private func rejects(_ plugin: CDVPlugin, _ action: String, _ args: [Any], _ code: String,
                         file: StaticString = #filePath, line: UInt = #line) throws {
        let result = try invoke(plugin, action, args)
        XCTAssertEqual(result.status.intValue, Int(CDVCommandStatus_ERROR.rawValue), file: file, line: line)
        let error = try XCTUnwrap(result.message as? [String: Any])
        XCTAssertEqual(error["code"] as? String, code, file: file, line: line)
        XCTAssertFalse((error["message"] as? String ?? "").isEmpty, file: file, line: line)
    }

    private func binary(_ message: Any?) throws -> Data {
        let value = try XCTUnwrap(message as? [String: Any])
        XCTAssertEqual(value["CDVType"] as? String, "ArrayBuffer")
        let encoded = try XCTUnwrap(value["data"] as? String)
        return try XCTUnwrap(Data(base64Encoded: encoded))
    }

    private func parts(_ result: CDVPluginResult) throws -> [Any] {
        let message = try XCTUnwrap(result.message as? [String: Any])
        XCTAssertEqual(message["CDVType"] as? String, "MultiPart")
        return try XCTUnwrap(message["messages"] as? [Any])
    }

    private func hex(_ bytes: Data) -> String {
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func unhex(_ text: String) -> Data {
        let characters = Array(text)
        return Data(stride(from: 0, to: characters.count, by: 2).map {
            UInt8(String(characters[$0...($0 + 1)]), radix: 16)!
        })
    }

    private func aes(_ mode: String, _ key: Data, _ data: Data,
                     _ iv: Data? = nil, _ aad: Data? = nil, _ tag: Data? = nil) -> [Any] {
        return [["mode": mode], key, data,
                iv.map { $0 as Any } ?? NSNull(),
                aad.map { $0 as Any } ?? NSNull(),
                tag.map { $0 as Any } ?? NSNull()]
    }

    func testGCMNistVectorAndTamper() throws {
        let key = Data(repeating: 0, count: 16)
        let iv = Data(repeating: 0, count: 12)
        let result = try parts(ok(AES(), "encrypt", aes("GCM", key, Data(repeating: 0, count: 16), iv)))
        let ciphertext = try binary(result[2])
        var tag = try binary(result[3])
        XCTAssertEqual(hex(ciphertext), "0388dace60b6a392f328c2b971b2fe78")
        XCTAssertEqual(hex(tag), "ab6e47d42cec13bdf53a67b21257bddf")
        let plaintext = try binary(ok(AES(), "decrypt", aes("GCM", key, ciphertext, iv, nil, tag)).message)
        XCTAssertEqual(plaintext, Data(repeating: 0, count: 16))
        tag[0] ^= 1
        try rejects(AES(), "decrypt", aes("GCM", key, ciphertext, iv, nil, tag), "AUTHENTICATION_FAILED")
    }

    func testCTRNistVectorAndUnsupportedAAD() throws {
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c")
        let iv = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        let message = unhex("6bc1bee22e409f96e93d7e117393172a")
        let result = try parts(ok(AES(), "encrypt", aes("CTR", key, message, iv)))
        let ciphertext = try binary(result[2])
        XCTAssertEqual(hex(ciphertext), "874d6191b620e3261bef6864990db6ce")
        XCTAssertTrue(result[3] is NSNull)
        XCTAssertEqual(try binary(ok(AES(), "decrypt", aes("CTR", key, ciphertext, iv)).message), message)
        try rejects(AES(), "encrypt", aes("CTR", key, message, iv, Data()), "INVALID_ARGUMENT")
    }

    func testAESKeySizesFreshIVAndEmptyData() throws {
        for mode in ["GCM", "CTR"] {
            for size in [16, 24, 32] {
                let key = Data(repeating: 0, count: size)
                let first = try parts(ok(AES(), "encrypt", aes(mode, key, Data())))
                let second = try parts(ok(AES(), "encrypt", aes(mode, key, Data())))
                let iv = try binary(first[1])
                XCTAssertNotEqual(iv, try binary(second[1]))
                let tag: Data? = try (mode == "GCM" ? binary(first[3]) : nil)
                let plain = try binary(ok(AES(), "decrypt", aes(mode, key, try binary(first[2]), iv, nil, tag)).message)
                XCTAssertEqual(plain.count, 0)
            }
        }
    }

    private func begin(_ plugin: AES) throws -> String {
        return try XCTUnwrap(ok(plugin, "open", []).message as? String)
    }

    private func create(_ plugin: AES, _ transaction: String, _ operation: String,
                        _ key: Data, _ keyHmac: Data) throws -> String {
        return try XCTUnwrap(ok(plugin, "create", [["transactionID": transaction, "operation": operation], key, keyHmac]).message as? String)
    }

    private func finish(_ plugin: AES, _ id: String) throws -> URL {
        let path = try XCTUnwrap(ok(plugin, "finalize", [id]).message as? String)
        return try XCTUnwrap(URL(string: path))
    }

    func testAuthenticatedStreamRoundtripRollbackAndAbort() throws {
        let plugin = AES()
        for keySize in [16, 24, 32] {
            let transaction = try begin(plugin)
            let key = Data(repeating: 0x10, count: keySize)
            let keyHmac = Data(repeating: 0x42, count: 64)
            let plain = Data(repeating: 0xA5, count: 16385)
            let id = try create(plugin, transaction, "encrypt", key, keyHmac)
            for offset in stride(from: 0, to: plain.count, by: 19) {
                _ = try ok(plugin, "update", [id, plain.subdata(in: offset..<min(offset + 19, plain.count))])
            }
            let sealed = try finish(plugin, id)
            let envelope = try Data(contentsOf: sealed)
            XCTAssertEqual(envelope.count, plain.count + 81)
            let decrypt = try create(plugin, transaction, "decrypt", key, keyHmac)
            for offset in stride(from: 0, to: envelope.count, by: 31) {
                _ = try ok(plugin, "update", [decrypt, envelope.subdata(in: offset..<min(offset + 31, envelope.count))])
            }
            let decoded = try finish(plugin, decrypt)
            XCTAssertEqual(try Data(contentsOf: decoded), plain)
            _ = try ok(plugin, "rollback", [transaction])
            XCTAssertFalse(FileManager.default.fileExists(atPath: sealed.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: decoded.path))
            let next = try begin(plugin)
            let aborted = try create(plugin, next, "encrypt", key, keyHmac)
            _ = try ok(plugin, "abort", [aborted])
            _ = try ok(plugin, "commit", [next])
            try rejects(plugin, "finalize", [aborted], "NOT_FOUND")
        }
    }

    func testAuthenticatedStreamGoVectorAndTampering() throws {
        let plugin = AES()
        let key = Data(repeating: 0x10, count: 16)
        let keyHmac = Data(repeating: 0x42, count: 129)
        let envelope = unhex("0113131313131313131313131313131313d97374e0b251a98a84492b285372ed34684c1b99505f021fe2cb5b0149ba531d500bd458481fab066863598ad3ab65f6d006b150ad18cdd33c73f9cafd0ed3ccdd4e5c25db9ebb2f5759dfbebbd9d1e373")
        let transaction = try begin(plugin)
        let id = try create(plugin, transaction, "decrypt", key, keyHmac)
        _ = try ok(plugin, "update", [id, envelope])
        let file = try finish(plugin, id)
        XCTAssertEqual(try Data(contentsOf: file), Data(repeating: 0x57, count: 17))
        _ = try ok(plugin, "rollback", [transaction])
        for position in [1, 16, 17, 33, 34, 97] {
            let next = try begin(plugin)
            let decrypt = try create(plugin, next, "decrypt", key, keyHmac)
            var changed = envelope
            changed[position] ^= 1
            _ = try ok(plugin, "update", [decrypt, changed])
            try rejects(plugin, "finalize", [decrypt], "AUTHENTICATION_FAILED")
            try rejects(plugin, "commit", [next], "NOT_FOUND")
        }
    }

}
