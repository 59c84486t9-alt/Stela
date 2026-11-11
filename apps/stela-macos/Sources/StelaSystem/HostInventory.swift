// The physical PC as stela.efi describes it in the StelaGPU kext's `StelaHost`
// registry dictionary (docs/design/updates.md#host-inventory). Model names and
// counts only: the record carries no serial numbers, addresses or user data.
import Foundation

public struct HostGPU: Codable, Equatable, Sendable {
  public let chip: String?
  public let pciID: String?
  public let vramBytes: UInt64?

  /// The product name for a known PCI device, else NVIDIA's chip name.
  public var name: String? {
    if let pciID, let product = HostInventory.nvidiaProducts[pciID.lowercased()] {
      return "NVIDIA GeForce \(product)"
    }
    return chip.map { "NVIDIA \($0)" }
  }
}

public struct HostInventory: Codable, Equatable, Sendable {
  public var stelaVersion: String?
  public var translatorTarget: String?
  public var translatorID: String?
  public var cpuBrand: String?
  public var cpuVendor: String?
  public var hostCores: UInt64?
  public var hostThreads: UInt64?
  public var hostMemoryBytes: UInt64?
  public var firmwareVendor: String?
  public var systemVendor: String?
  public var systemModel: String?
  public var boardVendor: String?
  public var gpus: [HostGPU] = []

  /// Reads the registry dictionary, whose values are strings and numbers.
  /// Unknown keys are ignored, missing ones stay nil.
  public init(properties: [String: Any]) {
    func text(_ key: String) -> String? {
      (properties[key] as? String).flatMap { Self.meaningful($0) }
    }
    func number(_ key: String) -> UInt64? {
      switch properties[key] {
      case let value as UInt64: return value
      case let value as Int where value >= 0: return UInt64(value)
      case let value as NSNumber: return value.uint64Value
      default: return nil
      }
    }
    stelaVersion = text("StelaVersion")
    translatorTarget = text("TranslatorTarget")
    translatorID = text("TranslatorID")
    cpuBrand = text("CPUBrand")
    cpuVendor = text("CPUVendor")
    hostCores = number("HostCores")
    hostThreads = number("HostThreads")
    hostMemoryBytes = number("HostMemoryBytes")
    firmwareVendor = text("FirmwareVendor")
    systemVendor = text("SystemVendor")
    systemModel = text("SystemModel")
    boardVendor = text("BoardVendor")
    var index = 0
    while text("GPU\(index)Chip") != nil || text("GPU\(index)PCIID") != nil {
      gpus.append(
        HostGPU(
          chip: text("GPU\(index)Chip"), pciID: text("GPU\(index)PCIID"),
          vramBytes: number("GPU\(index)VRAMBytes")))
      index += 1
    }
  }

  /// A sample in the registry's JSON form, for layout checks without Stela.
  public static func decode(json: Data) throws -> HostInventory {
    guard let properties = try JSONSerialization.jsonObject(with: json) as? [String: Any] else {
      throw CocoaError(.coderReadCorrupt)
    }
    return HostInventory(properties: properties)
  }

  /// The widest vector extension the translator emits, from its target id
  /// (`x86_64-baseline+ssse3+…+avx2+…`).
  public var instructionTier: String? {
    guard let translatorTarget else { return nil }
    let features = Set(translatorTarget.split(separator: "+").map(String.init))
    let tiers: [(String, String)] = [
      ("avx512f", "AVX-512"), ("avx2", "AVX2"), ("avx", "AVX"), ("sse4.2", "SSE4.2"),
      ("sse4.1", "SSE4.1"), ("ssse3", "SSSE3"),
    ]
    return tiers.first { features.contains($0.0) }?.1 ?? "SSE2"
  }

  /// The system's maker and model, falling back to the board's maker.
  public var system: String? {
    let maker = systemVendor ?? boardVendor
    switch (maker, systemModel) {
    case let (maker?, model?): return model.hasPrefix(maker) ? model : "\(maker) \(model)"
    case let (maker?, nil): return maker
    case let (nil, model?): return model
    default: return nil
    }
  }

  /// Firmware tables often hold placeholders instead of names.
  static func meaningful(_ value: String) -> String? {
    let trimmed = value.trimmingCharacters(in: .whitespaces)
    let placeholders = [
      "", "to be filled by o.e.m.", "system product name", "system manufacturer", "default string",
      "not applicable", "none", "o.e.m.", "oem",
    ]
    return placeholders.contains(trimmed.lowercased()) ? nil : trimmed
  }

  /// NVIDIA desktop parts by PCI device ID, for the GPUs Stela drives.
  static let nvidiaProducts: [String: String] = [
    "10de:2b85": "RTX 5090", "10de:2c02": "RTX 5080", "10de:2c05": "RTX 5070 Ti",
    "10de:2684": "RTX 4090", "10de:2704": "RTX 4080", "10de:2702": "RTX 4080 SUPER",
    "10de:2782": "RTX 4070 Ti", "10de:2705": "RTX 4070 Ti SUPER", "10de:2783": "RTX 4070 SUPER",
    "10de:2786": "RTX 4070", "10de:2803": "RTX 4060 Ti", "10de:2882": "RTX 4060",
    "10de:2203": "RTX 3090 Ti", "10de:2204": "RTX 3090", "10de:2208": "RTX 3080 Ti",
    "10de:2206": "RTX 3080", "10de:2482": "RTX 3070 Ti", "10de:2484": "RTX 3070",
    "10de:2486": "RTX 3060 Ti", "10de:2503": "RTX 3060", "10de:1e04": "RTX 2080 Ti",
    "10de:1e87": "RTX 2080", "10de:1f07": "RTX 2070", "10de:1f08": "RTX 2060",
    "10de:2182": "GTX 1660 Ti", "10de:2184": "GTX 1660", "10de:21c4": "GTX 1660 SUPER",
  ]

  /// The text the Copy button puts on the pasteboard.
  public func summary(
    osVersion: String, guestMemoryBytes: Int64?, presentedModel: String?, presentedChip: String?
  ) -> String {
    var lines = ["macOS \(osVersion)"]
    if let cpuBrand {
      let counts = [hostCores.map { "\($0) cores" }, hostThreads.map { "\($0) threads" }]
        .compactMap { $0 }
      lines.append((["Processor: \(cpuBrand)"] + counts).joined(separator: ", "))
    }
    for gpu in gpus {
      if let name = gpu.name {
        lines.append(
          (["Graphics: \(name)"] + [gpu.vramBytes.map { Self.bytes($0) }].compactMap { $0 })
            .joined(separator: ", "))
      }
    }
    if let hostMemoryBytes {
      let guest = guestMemoryBytes.map { " (\(Self.bytes(UInt64(max(0, $0)))) for macOS)" } ?? ""
      lines.append("Memory: \(Self.bytes(hostMemoryBytes))\(guest)")
    }
    if let system { lines.append("System: \(system)") }
    if let firmwareVendor { lines.append("Firmware: \(firmwareVendor)") }
    if let instructionTier { lines.append("Translation: \(instructionTier)") }
    if let stelaVersion { lines.append("Stela \(stelaVersion)") }
    let presented = [presentedModel, presentedChip].compactMap { $0 }
    if !presented.isEmpty { lines.append("Presented as \(presented.joined(separator: ", "))") }
    return lines.joined(separator: "\n")
  }

  /// Memory sizes in binary units, as macOS shows installed memory.
  public static func bytes(_ value: UInt64) -> String {
    let gib = Double(value) / 1_073_741_824
    if gib >= 1 {
      return gib >= 2 || gib.rounded() == gib
        ? "\(Int(gib.rounded())) GB" : String(format: "%.1f GB", gib)
    }
    return "\(Int((Double(value) / 1_048_576).rounded())) MB"
  }
}
