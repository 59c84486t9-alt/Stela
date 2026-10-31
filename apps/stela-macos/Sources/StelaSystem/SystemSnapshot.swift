// Read-only, exportable observations of the current macOS environment.
import Foundation

public struct GraphicsDevice: Codable, Equatable, Sendable {
  public let name: String
  public let unifiedMemory: Bool
  public let workingSetBytes: UInt64

  public init(name: String, unifiedMemory: Bool, workingSetBytes: UInt64) {
    self.name = name
    self.unifiedMemory = unifiedMemory
    self.workingSetBytes = workingSetBytes
  }
}

public struct SystemSnapshot: Codable, Sendable {
  public let capturedAt: Date
  public let osVersion: String
  public let osBuild: String?
  public let kernelVersion: String?
  public let model: String?
  public let processor: String?
  public let architecture: String?
  public let processArchitecture: String
  public let physicalCores: Int64?
  public let logicalCores: Int64?
  public let memoryBytes: Int64?
  public let uptimeSeconds: TimeInterval
  public let features: [CPUFeature]
  public var graphics: [GraphicsDevice] = []
  public var storageTotalBytes: Int64?
  public var storageAvailableBytes: Int64?

  public static func collect(using control: any SystemControlReading) -> SystemSnapshot {
    let info = ProcessInfo.processInfo
    let version = info.operatingSystemVersion
    let architecture = control.string("hw.machine")
    #if arch(arm64)
      let processArchitecture = "arm64"
    #elseif arch(x86_64)
      let processArchitecture = "x86_64"
    #else
      let processArchitecture = "Unknown"
    #endif
    return SystemSnapshot(
      capturedAt: Date(),
      osVersion: "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
      osBuild: control.string("kern.osversion"),
      kernelVersion: control.string("kern.osrelease"),
      model: control.string("hw.model"),
      processor: control.string("machdep.cpu.brand_string"),
      architecture: architecture,
      processArchitecture: processArchitecture,
      physicalCores: positive(control.integer("hw.physicalcpu")),
      logicalCores: positive(control.integer("hw.logicalcpu")),
      memoryBytes: positive(control.integer("hw.memsize")),
      uptimeSeconds: info.systemUptime,
      features: CPUFeatures.read(architecture: architecture, using: control)
    )
  }

  private static func positive(_ value: Int64?) -> Int64? {
    value.flatMap { $0 > 0 ? $0 : nil }
  }
}

public struct SystemReport: Encodable {
  public let schemaVersion = 1
  public let appVersion: String
  public let appBuild: String
  public let scope =
    "macOS-reported observations; not a native PC inventory or instruction-coverage certification"
  public let runtimeConnection = "unavailable"
  public let system: SystemSnapshot
  public let inspectedSetup: SetupSummary?

  public init(
    appVersion: String, appBuild: String, system: SystemSnapshot, inspectedSetup: SetupSummary?
  ) {
    self.appVersion = appVersion
    self.appBuild = appBuild
    self.system = system
    self.inspectedSetup = inspectedSetup
  }

  public func json() throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    encoder.dateEncodingStrategy = .iso8601
    return try encoder.encode(self)
  }
}
