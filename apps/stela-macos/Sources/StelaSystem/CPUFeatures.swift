// CPU capability observations belong to the OS that answered the query, not to a hidden host.
import Foundation

public protocol SystemControlReading {
  func string(_ name: String) -> String?
  func integer(_ name: String) -> Int64?
}

public enum FeatureSupport: String, Codable, CaseIterable, Sendable {
  case supported
  case unsupported
  case notReported

  public var label: String {
    switch self {
    case .supported: return "Supported"
    case .unsupported: return "Not supported"
    case .notReported: return "Not reported"
    }
  }
}

public struct CPUFeature: Codable, Identifiable, Equatable, Sendable {
  public var id: String { key }
  public let name: String
  public let detail: String
  public let group: String
  public let key: String
  public let support: FeatureSupport
}

public enum CPUFeatures {
  private struct Definition {
    let name: String
    let detail: String
    let group: String
    let key: String
  }

  // These are OS capability selectors, not a table of Stela instruction coverage.
  // https://developer.apple.com/documentation/kernel/1387446-sysctlbyname/determining_instruction_set_characteristics
  private static let arm: [Definition] = [
    .init(
      name: "NEON", detail: "Advanced SIMD", group: "Vector & floating point",
      key: "hw.optional.neon"),
    .init(
      name: "FP16", detail: "Half-precision arithmetic", group: "Vector & floating point",
      key: "hw.optional.arm.FEAT_FP16"),
    .init(
      name: "DotProd", detail: "Vector dot products", group: "Vector & floating point",
      key: "hw.optional.arm.FEAT_DotProd"),
    .init(
      name: "FHM", detail: "Half-precision multiply-add", group: "Vector & floating point",
      key: "hw.optional.arm.FEAT_FHM"),
    .init(
      name: "FCMA", detail: "Complex arithmetic", group: "Vector & floating point",
      key: "hw.optional.arm.FEAT_FCMA"),
    .init(
      name: "BF16", detail: "BFloat16 arithmetic", group: "Vector & floating point",
      key: "hw.optional.arm.FEAT_BF16"),
    .init(
      name: "I8MM", detail: "8-bit matrix multiplication", group: "Vector & floating point",
      key: "hw.optional.arm.FEAT_I8MM"),
    .init(
      name: "SVE", detail: "Scalable vectors", group: "Vector & floating point",
      key: "hw.optional.arm.FEAT_SVE"),
    .init(
      name: "SVE2", detail: "Scalable vector extensions 2", group: "Vector & floating point",
      key: "hw.optional.arm.FEAT_SVE2"),
    .init(
      name: "SME", detail: "Scalable matrix extension", group: "Vector & floating point",
      key: "hw.optional.arm.FEAT_SME"),
    .init(
      name: "SME2", detail: "Scalable matrix extension 2", group: "Vector & floating point",
      key: "hw.optional.arm.FEAT_SME2"),
    .init(
      name: "AES", detail: "AES cryptography", group: "Cryptography",
      key: "hw.optional.arm.FEAT_AES"),
    .init(
      name: "PMULL", detail: "Polynomial multiplication", group: "Cryptography",
      key: "hw.optional.arm.FEAT_PMULL"),
    .init(
      name: "SHA-1", detail: "SHA-1 hashing", group: "Cryptography",
      key: "hw.optional.arm.FEAT_SHA1"),
    .init(
      name: "SHA-256", detail: "SHA-256 hashing", group: "Cryptography",
      key: "hw.optional.arm.FEAT_SHA256"),
    .init(
      name: "SHA-512", detail: "SHA-512 hashing", group: "Cryptography",
      key: "hw.optional.arm.FEAT_SHA512"),
    .init(
      name: "SHA-3", detail: "SHA-3 hashing", group: "Cryptography",
      key: "hw.optional.arm.FEAT_SHA3"),
    .init(
      name: "CRC32", detail: "CRC32 checksums", group: "Memory & integer",
      key: "hw.optional.armv8_crc32"),
    .init(
      name: "LSE", detail: "Large-system atomics", group: "Memory & integer",
      key: "hw.optional.arm.FEAT_LSE"),
    .init(
      name: "LSE2", detail: "Atomic memory operations", group: "Memory & integer",
      key: "hw.optional.arm.FEAT_LSE2"),
    .init(
      name: "RDM", detail: "Rounding multiply-add", group: "Memory & integer",
      key: "hw.optional.arm.FEAT_RDM"),
    .init(
      name: "FlagM", detail: "Flag manipulation", group: "Memory & integer",
      key: "hw.optional.arm.FEAT_FlagM"),
    .init(
      name: "PAuth", detail: "Pointer authentication", group: "Security",
      key: "hw.optional.arm.FEAT_PAuth"),
    .init(
      name: "BTI", detail: "Branch target identification", group: "Security",
      key: "hw.optional.arm.FEAT_BTI"),
    .init(
      name: "DIT", detail: "Data-independent timing", group: "Security",
      key: "hw.optional.arm.FEAT_DIT"),
    .init(
      name: "MTE", detail: "Memory tagging", group: "Security", key: "hw.optional.arm.FEAT_MTE"),
  ]

  private static let intel: [Definition] = [
    .init(
      name: "SSE2", detail: "Streaming SIMD extensions 2", group: "Vector & floating point",
      key: "hw.optional.sse2"),
    .init(
      name: "SSE3", detail: "Streaming SIMD extensions 3", group: "Vector & floating point",
      key: "hw.optional.sse3"),
    .init(
      name: "SSSE3", detail: "Supplemental SSE3", group: "Vector & floating point",
      key: "hw.optional.supplementalsse3"),
    .init(
      name: "SSE4.1", detail: "Streaming SIMD extensions 4.1", group: "Vector & floating point",
      key: "hw.optional.sse4_1"),
    .init(
      name: "SSE4.2", detail: "Streaming SIMD extensions 4.2", group: "Vector & floating point",
      key: "hw.optional.sse4_2"),
    .init(
      name: "AVX", detail: "Advanced vector extensions", group: "Vector & floating point",
      key: "hw.optional.avx1_0"),
    .init(
      name: "AVX2", detail: "Advanced vector extensions 2", group: "Vector & floating point",
      key: "hw.optional.avx2_0"),
    .init(
      name: "AVX-512F", detail: "AVX-512 foundation", group: "Vector & floating point",
      key: "hw.optional.avx512f"),
    .init(
      name: "FMA", detail: "Fused multiply-add", group: "Vector & floating point",
      key: "hw.optional.fma"),
    .init(
      name: "AES-NI", detail: "AES cryptography", group: "Cryptography", key: "hw.optional.aes"),
    .init(
      name: "BMI1", detail: "Bit manipulation", group: "Memory & integer", key: "hw.optional.bmi1"),
    .init(
      name: "BMI2", detail: "Bit manipulation 2", group: "Memory & integer", key: "hw.optional.bmi2"
    ),
    .init(
      name: "ADX", detail: "Multi-precision arithmetic", group: "Memory & integer",
      key: "hw.optional.adx"),
  ]

  public static func read(architecture: String?, using control: any SystemControlReading)
    -> [CPUFeature]
  {
    let definitions: [Definition]
    switch architecture {
    case "arm64", "arm64e": definitions = arm
    case "x86_64": definitions = intel
    default: definitions = []
    }
    return definitions.map { definition in
      let value = control.integer(definition.key)
      // Missing selectors and unexpected values are not negative capability answers.
      let support: FeatureSupport =
        value == 1 ? .supported : value == 0 ? .unsupported : .notReported
      return CPUFeature(
        name: definition.name, detail: definition.detail,
        group: definition.group, key: definition.key, support: support
      )
    }
  }
}
