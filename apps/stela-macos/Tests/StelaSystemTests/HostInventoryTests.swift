import Foundation
import XCTest

@testable import StelaSystem

final class HostInventoryTests: XCTestCase {
  static let sample: [String: Any] = [
    "StelaVersion": "0.1.0", "CPUBrand": "AMD Ryzen 9 9950X 16-Core Processor",
    "CPUVendor": "AuthenticAMD", "HostCores": 16, "HostThreads": NSNumber(value: 32),
    "HostMemoryBytes": UInt64(68_406_829_056), "FirmwareVendor": "American Megatrends",
    "SystemVendor": "ASUS", "SystemModel": "System Product Name", "BoardVendor": "ASUSTeK",
    "GPU0Chip": "GB203", "GPU0PCIID": "10de:2c02", "GPU0VRAMBytes": UInt64(17_179_869_184),
    "TranslatorTarget": "x86_64-baseline+ssse3+sse4.1+sse4.2+popcnt+avx+avx2+avx512f",
    "Unknown": "ignored",
  ]

  func testTheRegistryDictionaryBecomesNamedHardware() {
    let host = HostInventory(properties: Self.sample)
    XCTAssertEqual(host.cpuBrand, "AMD Ryzen 9 9950X 16-Core Processor")
    XCTAssertEqual(host.hostCores, 16)
    XCTAssertEqual(host.hostThreads, 32)
    XCTAssertEqual(host.gpus.first?.name, "NVIDIA GeForce RTX 5080")
    XCTAssertEqual(host.instructionTier, "AVX-512")
    // A placeholder model leaves the maker alone.
    XCTAssertEqual(host.system, "ASUS")
    XCTAssertEqual(HostInventory.bytes(68_406_829_056), "64 GB")
    XCTAssertEqual(HostInventory.bytes(17_179_869_184), "16 GB")
  }

  func testMissingValuesStayMissingAndUnknownPartsKeepTheirChip() {
    let host = HostInventory(properties: ["GPU0Chip": "AD102", "GPU0PCIID": "10de:ffff"])
    XCTAssertNil(host.cpuBrand)
    XCTAssertNil(host.instructionTier)
    XCTAssertNil(host.system)
    XCTAssertEqual(host.gpus.first?.name, "NVIDIA AD102")
    XCTAssertNil(host.gpus.first?.vramBytes)
    XCTAssertEqual(
      HostInventory(properties: ["TranslatorTarget": "x86_64-baseline+ssse3+sse4.1+sse4.2+avx2"])
        .instructionTier, "AVX2")
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
      System: ASUS
      Firmware: American Megatrends
      Translation: AVX-512
      Stela 0.1.0
      Presented as Mac14,3, Apple M2
      """)
    XCTAssertEqual(
      HostInventory(properties: [:]).summary(
        osVersion: "14.6", guestMemoryBytes: nil, presentedModel: nil, presentedChip: nil),
      "macOS 14.6")
  }
}
