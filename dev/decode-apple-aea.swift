#!/usr/bin/env swift
// Host acquisition only: CryptoKit HPKE (RFC 9180), then Apple's AEA decoder.
// Reference: blacktop/ipsw 65ceb7620436150e232970ebd0875cfe8062b63c pkg/aea.
// No networking, Keychain, mount, Apple-signature or filesystem-seal verification.
import CryptoKit
import Darwin
import Foundation

struct Failure: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}
func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure(message) }
}
func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
func exists(_ path: String) -> Bool { var info = stat(); return lstat(path, &info) == 0 }
func fileSize(_ url: URL) throws -> UInt64 {
    let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
    try require(attrs[.type] as? FileAttributeType == .typeRegular, "Expected a regular file")
    return (attrs[.size] as! NSNumber).uint64Value
}
func hashFile(_ url: URL, limit: UInt64 = UInt64.max) throws -> (bytes: UInt64, sha256: String) {
    let file = try FileHandle(forReadingFrom: url)
    defer { try? file.close() }
    var hash = SHA256(), total: UInt64 = 0
    while let data = try file.read(upToCount: 4 * 1024 * 1024), !data.isEmpty {
        try require(UInt64(data.count) <= limit - total, "File exceeds byte limit")
        total += UInt64(data.count); hash.update(data: data)
    }
    return (total, hash.finalize().map { String(format: "%02x", $0) }.joined())
}
func privateWrite(_ data: Data, to url: URL) throws {
    let fd = open(url.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, S_IRUSR | S_IWUSR)
    try require(fd >= 0, "Cannot exclusively create private temporary file")
    let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    try file.write(contentsOf: data); try file.synchronize(); try file.close()
}
func jsonData(_ object: Any) throws -> Data {
    var data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    data.append(10); return data
}
func readSmall(_ url: URL, max: Int) throws -> Data {
    try require(try fileSize(url) <= UInt64(max), "Small input exceeds byte limit")
    let file = try FileHandle(forReadingFrom: url); defer { try? file.close() }
    let data = try file.read(upToCount: max + 1) ?? Data()
    try require(data.count <= max, "Small input exceeds byte limit")
    return data
}
func u32(_ data: Data, _ offset: Int) -> UInt32 {
    (0..<4).reduce(UInt32(0)) { $0 | UInt32(data[offset + $1]) << ($1 * 8) }
}
struct Metadata {
    let auth: Data
    let fields: [String: Data]
    let encapsulated: Data
    let wrapped: Data
}
func metadata(_ input: URL) throws -> Metadata {
    let file = try FileHandle(forReadingFrom: input); defer { try? file.close() }
    let header = try file.read(upToCount: 12) ?? Data()
    try require(header.count == 12 && header.prefix(4) == Data("AEA1".utf8), "Expected AEA1 header")
    try require(u32(header, 4) == 1, "Only AEA profile 1 with zero scrypt-strength is supported")
    let size = Int(u32(header, 8))
    try require(size > 0 && size <= 65536, "AEA auth data exceeds 64 KiB profile limit")
    let auth = try file.read(upToCount: size) ?? Data()
    try require(auth.count == size, "Truncated AEA auth data")
    var fields: [String: Data] = [:], cursor = 0
    while cursor < auth.count {
        try require(auth.count - cursor >= 4, "Truncated metadata length")
        let length = Int(u32(auth, cursor))
        try require(length >= 6 && length <= auth.count - cursor, "Invalid metadata field extent")
        let field = Data(auth[(cursor + 4)..<(cursor + length)])
        guard let zero = field.firstIndex(of: 0), zero > 0, zero <= 255,
              let name = String(data: field.prefix(zero), encoding: .utf8) else {
            throw Failure("Invalid metadata field name")
        }
        try require(name.unicodeScalars.allSatisfy { $0.value >= 32 && $0.value < 127 }, "Non-ASCII metadata name")
        try require(fields[name] == nil && fields.count < 64, "Duplicate or excessive metadata fields")
        fields[name] = Data(field[(zero + 1)...]); cursor += length
    }
    guard let response = fields["com.apple.wkms.fcs-response"], response.count <= 4096,
          let json = try JSONSerialization.jsonObject(with: response) as? [String: String],
          Set(json.keys) == Set(["enc-request", "wrapped-key"]),
          let encapsulated = Data(base64Encoded: json["enc-request"]!),
          let wrapped = Data(base64Encoded: json["wrapped-key"]!) else {
        throw Failure("Expected bounded FCS response with two base64 fields")
    }
    try require(encapsulated.count == 65 && encapsulated.first == 4 && wrapped.count == 48,
                "Expected P256 encapsulation and wrapped 32-byte AES key")
    return Metadata(auth: auth, fields: fields, encapsulated: encapsulated, wrapped: wrapped)
}

@available(macOS 14.0, *)
func unwrap(_ md: Metadata, pem: Data) throws -> Data {
    guard let text = String(data: pem, encoding: .utf8) else { throw Failure("Expected PEM text") }
    // Base mode supplies no sender authentication. AEA profile1 has no signature.
    let key = try P256.KeyAgreement.PrivateKey(pemRepresentation: text)
    var receiver = try HPKE.Recipient(privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256,
                                    info: Data(), encapsulatedKey: md.encapsulated)
    let raw = try receiver.open(md.wrapped, authenticating: Data())
    try require(raw.count == 32, "Unexpected unwrapped symmetric-key length")
    return raw
}

struct Options {
    let input: URL, pem: URL, output: URL
    var maxOutput: UInt64 = 64 * 1024 * 1024 * 1024
    var timeout: TimeInterval = 3600
}
// The file-size rlimit is inherited by the child, then restored in this host
// tool. Polling additionally enforces timeout; no secret enters argv or stdout.
func aea(_ arguments: [String], stage: URL, maxBytes: UInt64, timeout: TimeInterval) throws {
    let diagnostics = stage.appendingPathComponent(UUID().uuidString + ".diagnostics")
    try privateWrite(Data(), to: diagnostics)
    let errorFile = try FileHandle(forWritingTo: diagnostics); defer { try? errorFile.close() }
    let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/aea")
    process.arguments = arguments; process.standardOutput = FileHandle.nullDevice
    process.standardInput = FileHandle.nullDevice; process.standardError = errorFile
    var previous = rlimit()
    try require(getrlimit(RLIMIT_FSIZE, &previous) == 0, "Cannot read output-size resource limit")
    var bounds = previous; bounds.rlim_cur = min(rlim_t(maxBytes), previous.rlim_max)
    try require(setrlimit(RLIMIT_FSIZE, &bounds) == 0, "Cannot set child output-size resource limit")
    do { try process.run() } catch {
        _ = setrlimit(RLIMIT_FSIZE, &previous); throw Failure("Cannot launch /usr/bin/aea")
    }
    let restored = setrlimit(RLIMIT_FSIZE, &previous)
    if restored != 0 { process.terminate(); process.waitUntilExit(); throw Failure("Cannot restore host resource limit") }
    let deadline = Date().addingTimeInterval(timeout)
    while process.isRunning {
        if Date() >= deadline {
            process.terminate(); Thread.sleep(forTimeInterval: 0.1)
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit(); throw Failure("AEA operation exceeded timeout")
        }
        Thread.sleep(forTimeInterval: 0.05)
    }
    process.waitUntilExit()
    try require(process.terminationReason == .exit && process.terminationStatus == 0,
                "Apple aea failed; diagnostic body suppressed to prevent key disclosure")
}

@available(macOS 14.0, *)
func decode(_ options: Options) throws -> [String: Any] {
    let fm = FileManager.default, receipt = URL(fileURLWithPath: options.output.path + ".json")
    try require(options.maxOutput > 0 && options.maxOutput <= 256 * 1024 * 1024 * 1024,
                "Output bound must be 1..256 GiB")
    try require(options.timeout > 0 && options.timeout <= 86400, "Timeout must be 1..86400 seconds")
    try require(!exists(options.output.path) && !exists(receipt.path), "Output or receipt already exists")
    try require(try fileSize(options.input) > 0, "Empty AEA input")
    let inputHash = try hashFile(options.input, limit: 16 * 1024 * 1024 * 1024)
    let md = try metadata(options.input)
    let pem = try readSmall(options.pem, max: 65536), keyHash = digest(pem)
    var symmetric = try unwrap(md, pem: pem)
    defer { symmetric.resetBytes(in: 0..<symmetric.count) }
    let parent = options.output.deletingLastPathComponent()
    try fm.createDirectory(at: parent, withIntermediateDirectories: true)
    let lock = URL(fileURLWithPath: options.output.path + ".aea-lock")
    try require(mkdir(lock.path, S_IRWXU) == 0, "Output is reserved by another decoder")
    defer { _ = rmdir(lock.path) }
    let stage = parent.appendingPathComponent(".stela-aea-" + UUID().uuidString)
    try require(mkdir(stage.path, S_IRWXU) == 0, "Cannot create private staging directory")
    defer { try? fm.removeItem(at: stage) }
    let temporaryKey = stage.appendingPathComponent("key"), temporaryOutput = stage.appendingPathComponent("decoded")
    try privateWrite(symmetric, to: temporaryKey)
    try privateWrite(Data(), to: temporaryOutput)
    try aea(["decrypt", "-key", temporaryKey.path, "-i", options.input.path, "-o", temporaryOutput.path],
            stage: stage, maxBytes: options.maxOutput, timeout: options.timeout)
    try fm.removeItem(at: temporaryKey)
    let outputHash = try hashFile(temporaryOutput, limit: options.maxOutput)
    try require(outputHash.bytes > 0, "AEA produced empty output")
    let inputAfter = try hashFile(options.input, limit: 16 * 1024 * 1024 * 1024)
    let keyAfter = try hashFile(options.pem, limit: 65536).sha256
    try require(inputAfter == inputHash && keyAfter == keyHash,
                "Input or explicit PEM changed during decode")
    let source = URL(fileURLWithPath: #filePath).standardizedFileURL
    let executable = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    let report: [String: Any] = [
        "schema_version": 1, "tool_version": 1, "kind": "apple_aea_profile1_decode", "status": "passed",
        "input": options.input.path, "input_bytes": inputHash.bytes, "input_sha256": inputHash.sha256,
        "output": options.output.path, "output_bytes": outputHash.bytes, "output_sha256": outputHash.sha256,
        "key_file_sha256": keyHash, "auth_data_sha256": digest(md.auth),
        "metadata": md.fields.keys.sorted().map { ["name": $0, "bytes": md.fields[$0]!.count,
                                                    "sha256": digest(md.fields[$0]!)] as [String: Any] },
        "crypto": "CryptoKit HPKE base P256/HKDF-SHA256/AES-GCM-256; empty info/AAD",
        "decoder": "/usr/bin/aea", "decoder_sha256": try hashFile(URL(fileURLWithPath: "/usr/bin/aea")).sha256,
        "tool_source_sha256": try hashFile(source).sha256, "tool_executable_sha256": try hashFile(executable).sha256,
        "host": ProcessInfo.processInfo.operatingSystemVersionString,
        "max_input_bytes": UInt64(16 * 1024 * 1024 * 1024), "max_output_bytes": options.maxOutput,
        "timeout_seconds": options.timeout, "aea_exit_status": 0,
        "publication": "Exclusive reservation; complete files linked without replacement; receipt last; rollback on receipt failure. Two paths are not a single atomic transaction.",
        "limits": "Profile1 integrity/decryption only; no Apple signature, APFS seal, mount, binary execution or boot validation. Explicit PEM provenance is supplied by the caller; no network lookup. Temporary files are cleaned on normal success/error; abrupt process termination may leave private staging files.",
    ]
    let stagedReceipt = stage.appendingPathComponent("receipt.json")
    try privateWrite(try jsonData(report), to: stagedReceipt)
    try require(link(temporaryOutput.path, options.output.path) == 0, "Output publication collision/failure")
    if link(stagedReceipt.path, receipt.path) != 0 {
        // The caller owns this reserved destination; remove only our hard link.
        var published = stat(), staged = stat()
        if lstat(options.output.path, &published) == 0 && lstat(temporaryOutput.path, &staged) == 0
            && published.st_ino == staged.st_ino && published.st_dev == staged.st_dev { _ = unlink(options.output.path) }
        throw Failure("Receipt publication collision/failure; output rolled back")
    }
    return ["status": "passed", "output": options.output.path, "receipt": receipt.path,
            "output_bytes": outputHash.bytes, "output_sha256": outputHash.sha256]
}

@available(macOS 14.0, *)
func selfTest() throws {
    let fm = FileManager.default
    let stage = fm.temporaryDirectory.appendingPathComponent("stela-aea-test-" + UUID().uuidString)
    try require(mkdir(stage.path, S_IRWXU) == 0, "Cannot create private test directory")
    defer { try? fm.removeItem(at: stage) }
    let privateKey = P256.KeyAgreement.PrivateKey()
    let pem = stage.appendingPathComponent("recipient.pem")
    try privateWrite(Data(privateKey.pemRepresentation.utf8), to: pem)
    let symmetric = SymmetricKey(size: .bits256)
    let raw = symmetric.withUnsafeBytes { Data($0) }
    let key = stage.appendingPathComponent("key"); try privateWrite(raw, to: key)
    var sender = try HPKE.Sender(recipientKey: privateKey.publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: Data())
    let response = try jsonData(["enc-request": sender.encapsulatedKey.base64EncodedString(),
                                 "wrapped-key": try sender.seal(raw, authenticating: Data()).base64EncodedString()])
    let auth = stage.appendingPathComponent("auth"); try privateWrite(response, to: auth)
    let plaintext = Data((0..<4096).map { UInt8(truncatingIfNeeded: $0 * 73 + 19) })
    let input = stage.appendingPathComponent("plain"), archive = stage.appendingPathComponent("own.aea")
    try privateWrite(plaintext, to: input)
    try aea(["encrypt", "-profile", "1", "-key", key.path, "-i", input.path, "-o", archive.path,
             "-auth-data-key", "com.apple.wkms.fcs-response", "-auth-data", auth.path],
            stage: stage, maxBytes: 1024 * 1024, timeout: 10)
    let output = stage.appendingPathComponent("roundtrip")
    _ = try decode(Options(input: archive, pem: pem, output: output))
    try require(try Data(contentsOf: output) == plaintext, "Synthetic roundtrip mismatch")
    func declined(_ options: Options) throws {
        do { _ = try decode(options) } catch {
            try require(!exists(options.output.path), "Failed decode published output"); return
        }
        throw Failure("Expected synthetic rejection")
    }
    let before = try Data(contentsOf: output)
    var existingRejected = false
    do { _ = try decode(Options(input: archive, pem: pem, output: output)) }
    catch { existingRejected = true }
    try require(existingRejected && (try Data(contentsOf: output)) == before, "Existing output accepted/overwritten")
    let tampered = stage.appendingPathComponent("tampered.aea")
    var damaged = try Data(contentsOf: archive); damaged[damaged.count - 1] ^= 1
    try privateWrite(damaged, to: tampered)
    try declined(Options(input: tampered, pem: pem, output: stage.appendingPathComponent("tampered-output")))
    let wrongPem = stage.appendingPathComponent("wrong.pem")
    try privateWrite(Data(P256.KeyAgreement.PrivateKey().pemRepresentation.utf8), to: wrongPem)
    try declined(Options(input: archive, pem: wrongPem, output: stage.appendingPathComponent("wrong-key-output")))
    var bounded = Options(input: archive, pem: pem, output: stage.appendingPathComponent("bounded-output"))
    bounded.maxOutput = 128; try declined(bounded)
    for (name, offset, replacement) in [("profile", 4, UInt8(2)), ("metadata_length", 8, UInt8(255))] {
        let bad = stage.appendingPathComponent(name + ".aea")
        var data = try Data(contentsOf: archive); data[offset] = replacement
        if name == "metadata_length" { for index in 8..<12 { data[index] = 255 } }
        try privateWrite(data, to: bad)
        try declined(Options(input: bad, pem: pem, output: stage.appendingPathComponent(name + "-output")))
    }
    let leftovers = try fm.contentsOfDirectory(atPath: stage.path)
    try require(!leftovers.contains { $0.hasPrefix(".stela-aea-") || $0.hasSuffix(".aea-lock") }, "Private staging cleanup failed")
    print("{\"self_test\":\"passed\",\"checks\":[\"roundtrip\",\"existing_output\",\"tamper\",\"wrong_recipient\",\"output_limit\",\"reserved_profile\",\"metadata_extent\",\"cleanup\"]}")
}

func main() throws {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--help"] || arguments.isEmpty {
        print("Usage: decode-apple-aea INPUT.aea EXPLICIT-APPLE-KEY.pem NEW-OUTPUT.dmg [--max-output-bytes N] [--timeout-seconds N]\n       decode-apple-aea --self-test\nRequires macOS14+, CryptoKit and /usr/bin/aea. No keys are printed or passed in argv. Existing output/receipt are preserved.")
        return
    }
    guard #available(macOS 14.0, *) else { throw Failure("CryptoKit HPKE requires macOS14 or later") }
    if arguments == ["--self-test"] { try selfTest(); return }
    try require(arguments.count >= 3 && (arguments.count - 3).isMultiple(of: 2), "Expected three paths followed by option/value pairs")
    var options = Options(input: URL(fileURLWithPath: arguments[0]).standardizedFileURL,
                          pem: URL(fileURLWithPath: arguments[1]).standardizedFileURL,
                          output: URL(fileURLWithPath: arguments[2]).standardizedFileURL)
    for index in stride(from: 3, to: arguments.count, by: 2) {
        guard let value = UInt64(arguments[index + 1]), value > 0 else { throw Failure("Expected positive numeric bound") }
        switch arguments[index] {
        case "--max-output-bytes": options.maxOutput = value
        case "--timeout-seconds": options.timeout = TimeInterval(value)
        default: throw Failure("Unknown decoder option")
        }
    }
    print(String(data: try jsonData(decode(options)), encoding: .utf8)!)
}
do { try main() } catch {
    // Crypto errors are deliberately not interpolated: never log key data.
    let message = (error as? Failure)?.description ?? "AEA acquisition failed; underlying diagnostic suppressed"
    FileHandle.standardError.write(Data(("error: " + message + "\n").utf8)); exit(1)
}
