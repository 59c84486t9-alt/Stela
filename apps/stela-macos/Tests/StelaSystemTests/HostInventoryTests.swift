import Foundation
import XCTest

@testable import StelaSystem

final class HostInventoryTests: XCTestCase {
  static let sample: [String: Any] = [
    "StelaVersion": "0.1.0", "CPUBrand": "AMD Ryzen 9 9950X 16-Core Processor",
    "CPUVendor": "AuthenticAMD", "HostCores": 16, "HostThreads": NSNumber(value: 32),
    "HostMemoryBytes": UInt64(68_406_829_056), "FirmwareVendor": "American Megatrends",
    "FirmwareVersion": "1001", "SystemVendor": "ASUS", "SystemModel": "System Product Name",
    "BoardVendor": "ASUSTeK", "BoardModel": "ROG STRIX X870E-E GAMING WIFI",
    "GPU0Chip": "GB203", "GPU0PCIID": "10de:2c02", "GPU0VRAMBytes": UInt64(17_179_869_184),
    "TranslatorTarget":
      "x86_64-baseline+ssse3+sse4.1+sse4.2+pclmulqdq+fma+f16c+popcnt+bmi1+aes+sha+atomic-load16"
      + "+cx8+cx16+avx2+lzcnt+bmi2+fast-pdep+movbe+gfni",
    "Unknown": "ignored",
  ]

  func testTheRegistryDictionaryBecomesNamedHardware() {
    let host = HostInventory(properties: Self.sample)
    XCTAssertEqual(host.cpuBrand, "AMD Ryzen 9 9950X 16-Core Processor")
    XCTAssertEqual(host.hostCores, 16)
    XCTAssertEqual(host.hostThreads, 32)
    XCTAssertEqual(host.gpus.first?.name, "NVIDIA GeForce RTX 5080")
    XCTAssertEqual(host.instructionTier, "AVX2")
    XCTAssertEqual(host.translationLevel, "AVX2, FMA")
    XCTAssertEqual(
      host.notableExtensions,
      ["F16C", "AES-NI", "SHA", "PCLMUL", "BMI2", "LZCNT", "POPCNT", "MOVBE", "GFNI"])
    // A placeholder system model gives way to the board's.
    XCTAssertEqual(host.system, "ASUS ROG STRIX X870E-E GAMING WIFI")
    XCTAssertEqual(HostInventory.brand("ASUSTeK COMPUTER INC."), "ASUSTeK")
    XCTAssertEqual(HostInventory.brand("Micro-Star International Co., Ltd."), "Micro-Star International")
    XCTAssertEqual(HostInventory.brand("Inc."), "Inc.")
    XCTAssertEqual(host.firmware, "American Megatrends 1001")
    XCTAssertEqual(HostInventory.bytes(68_406_829_056), "64 GB")
    XCTAssertEqual(HostInventory.bytes(17_179_869_184), "16 GB")
  }

  func testMissingValuesStayMissingAndUnknownPartsKeepTheirChip() {
    let host = HostInventory(properties: ["GPU0Chip": "AD102", "GPU0PCIID": "10de:ffff"])
    XCTAssertNil(host.cpuBrand)
    XCTAssertNil(host.instructionTier)
    XCTAssertNil(host.translationLevel)
    XCTAssertNil(host.system)
    XCTAssertNil(host.firmware)
    XCTAssertEqual(host.gpus.first?.name, "NVIDIA AD102")
    XCTAssertNil(host.gpus.first?.vramBytes)
    XCTAssertEqual(
      HostInventory(properties: ["TranslatorTarget": "x86_64-baseline+ssse3+sse4.1+sse4.2+avx2"])
        .translationLevel, "AVX2")
    let legacy = HostInventory(properties: [
      "TranslatorTarget": "x86_64-baseline+ssse3+sse4.1+sse4.2+popcnt+bmi1+cx16"
    ])
    XCTAssertEqual(legacy.translationLevel, "SSE4.2")
    XCTAssertEqual(legacy.notableExtensions, ["BMI1", "POPCNT"])
    XCTAssertEqual(
      HostInventory(properties: ["TranslatorTarget": "x86_64-baseline+avx512f+avx2+fma"])
        .translationLevel, "AVX-512, FMA")
    XCTAssertEqual(
      HostInventory(properties: ["SystemVendor": "Framework", "SystemModel": "Framework Desktop"])
        .system, "Framework Desktop")
  }

  func testTheCopiedSummaryNamesOnlyWhatIsKnown() throws {
    let json = try JSONSerialization.data(withJSONObject: Self.sample)
    let host = try HostInventory.decode(json: json)
    XCTAssertEqual(
      host.summary(
        osVersion: "27.0", guestMemoryBytes: 12_884_901_888, presentedModel: "Mac14,3",
        presentedChip: "Apple M2"),
      """
      macOS 27.0
      Processor: AMD Ryzen 9 9950X 16-Core Processor, 16 cores, 32 threads
      Graphics: NVIDIA GeForce RTX 5080, 16 GB
      Memory: 64 GB (12 GB for macOS)
      System: ASUS ROG STRIX X870E-E GAMING WIFI
      Firmware: American Megatrends 1001
      Translation: AVX2, FMA
      Extensions: F16C, AES-NI, SHA, PCLMUL, BMI2, LZCNT, POPCNT, MOVBE, GFNI
      Target: x86_64-baseline+ssse3+sse4.1+sse4.2+pclmulqdq+fma+f16c+popcnt+bmi1+aes+sha+atomic-load16+cx8+cx16+avx2+lzcnt+bmi2+fast-pdep+movbe+gfni
      Stela 0.1.0
      Presented as Mac14,3, Apple M2
      """)
    XCTAssertEqual(
      HostInventory(properties: [:]).summary(
        osVersion: "14.6", guestMemoryBytes: nil, presentedModel: nil, presentedChip: nil),
      "macOS 14.6")
  }
}
