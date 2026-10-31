// A bounded, read-only projection of setup record schema 9. Never follow recorded disk paths.
import Foundation

public struct SetupSummary: Codable, Equatable, Sendable {
  public let schema: Int
  public let installBuild: String
  public let model: String
  public let complete: Bool
  public let bootVersion: String?
  public let retainedVersionCount: Int
  public let installCount: Int
  public let bundleSchema: Int
  public let bundleRevision: Int
  public let updatePending: Bool
  public let inspectedAt: Date

  // This intentionally excludes ECIDs, disk paths/serials, keys, Wi-Fi and option lines.
  private struct Record: Decodable {
    struct Install: Decodable {}
    struct Change: Decodable { let kind: String }
    let schemaVersion: Int
    let kind: String
    let build: String
    let model: String
    let complete: Bool
    let stelaVersion: String?
    let stelaVersions: [String]?
    let installs: [Install]?
    let bundleSchema: Int
    let bundleRevision: Int
    let pending: Change?
  }

  public enum InspectionError: LocalizedError {
    case tooLarge, wrongKind
    case unsupportedSchema(Int)
    case invalidRecord

    public var errorDescription: String? {
      switch self {
      case .tooLarge: return "The setup record exceeds the 1 MiB inspection limit."
      case .wrongKind:
        return
          "This file is not a Stela setup record. Select EFI/stela/setup.json from your setup volume."
      case .unsupportedSchema(let schema):
        return
          "Setup record schema \(schema) is not supported by this app. This build reads schema 9."
      case .invalidRecord:
        return "The setup record contains invalid version or configuration fields."
      }
    }
  }

  public static let maximumBytes = 1_048_576

  public static func read(from url: URL) throws -> SetupSummary {
    let file = try FileHandle(forReadingFrom: url)
    defer { try? file.close() }
    var data = Data()
    while data.count <= maximumBytes {
      guard let chunk = try file.read(upToCount: min(65_536, maximumBytes + 1 - data.count)),
        !chunk.isEmpty
      else { break }
      data.append(chunk)
    }
    return try parse(data)
  }

  public static func parse(_ data: Data) throws -> SetupSummary {
    guard data.count <= maximumBytes else { throw InspectionError.tooLarge }
    // Check the envelope first so newer records produce an actionable schema error.
    struct Envelope: Decodable {
      let kind: String
      let schemaVersion: Int
    }
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    let envelope = try decoder.decode(Envelope.self, from: data)
    guard envelope.kind == "stela_setup" else { throw InspectionError.wrongKind }
    guard envelope.schemaVersion == 9 else {
      throw InspectionError.unsupportedSchema(envelope.schemaVersion)
    }
    let record = try decoder.decode(Record.self, from: data)
    let versions = record.stelaVersions ?? []
    let validVersion: (String) -> Bool = { value in
      value.utf8.count == 16
        && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    let validLabel: (String) -> Bool = { value in
      !value.isEmpty && value.utf8.count <= 256
        && !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
    guard validLabel(record.build), validLabel(record.model),
      record.stelaVersion.map(validVersion) ?? true,
      versions.count <= 64, versions.allSatisfy(validVersion),
      (record.installs?.count ?? 0) <= 256,
      record.bundleSchema > 0, record.bundleRevision >= 0,
      record.pending.map({ ["stela", "os"].contains($0.kind) }) ?? true
    else {
      throw InspectionError.invalidRecord
    }
    return SetupSummary(
      schema: record.schemaVersion, installBuild: record.build, model: record.model,
      complete: record.complete, bootVersion: record.stelaVersion,
      retainedVersionCount: versions.count, installCount: record.installs?.count ?? 0,
      bundleSchema: record.bundleSchema, bundleRevision: record.bundleRevision,
      updatePending: record.pending != nil, inspectedAt: Date()
    )
  }
}
