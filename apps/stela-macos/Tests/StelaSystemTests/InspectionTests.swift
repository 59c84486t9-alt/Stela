import Foundation
import XCTest

@testable import StelaSystem

final class InspectionTests: XCTestCase {
  #if canImport(Darwin)
    func testDarwinReaderHandlesSystemValuesAndMissingSelectors() throws {
      let control = DarwinSystemControl()
      XCTAssertGreaterThan(try XCTUnwrap(control.integer("hw.memsize")), 0)
      XCTAssertFalse(try XCTUnwrap(control.string("kern.osrelease")).isEmpty)
      XCTAssertNil(control.integer("hw.optional.stela_nonexistent_test_selector"))
    }
  #endif

  private struct Control: SystemControlReading {
    var strings: [String: String] = [:]
    var integers: [String: Int64] = [:]
    func string(_ name: String) -> String? { strings[name] }
    func integer(_ name: String) -> Int64? { integers[name] }
  }

  func testMissingAndUnexpectedCapabilityAnswersAreNotUnsupported() {
    let control = Control(integers: [
      "hw.optional.neon": 1, "hw.optional.arm.FEAT_AES": 0, "hw.optional.arm.FEAT_SVE": 2,
    ])
    let features = CPUFeatures.read(architecture: "arm64", using: control)
    XCTAssertEqual(features.first { $0.name == "NEON" }?.support, .supported)
    XCTAssertEqual(features.first { $0.name == "AES" }?.support, .unsupported)
    XCTAssertEqual(features.first { $0.name == "SVE" }?.support, .notReported)
    XCTAssertEqual(features.first { $0.name == "SME" }?.support, .notReported)
  }

  func testGuestArchitectureDoesNotInheritHostExtensionClaims() {
    let control = Control(
      strings: ["hw.machine": "arm64", "hw.model": "Presented model"],
      integers: ["hw.optional.avx2_0": 1])
    let system = SystemSnapshot.collect(using: control)
    XCTAssertEqual(system.model, "Presented model")
    XCTAssertFalse(system.features.contains { $0.name == "AVX2" })
    XCTAssertTrue(system.features.allSatisfy { $0.support == .notReported })
    XCTAssertTrue(CPUFeatures.read(architecture: "unknown", using: control).isEmpty)
  }

  func testIntelMacFeaturesUseIntelSelectors() {
    let features = CPUFeatures.read(
      architecture: "x86_64", using: Control(integers: ["hw.optional.avx2_0": 1]))
    XCTAssertEqual(features.first { $0.name == "AVX2" }?.support, .supported)
    XCTAssertFalse(features.contains { $0.name == "NEON" })
  }

  func testInvalidResourceCountsRemainUnreported() {
    let system = SystemSnapshot.collect(
      using: Control(integers: ["hw.memsize": -1, "hw.physicalcpu": 0, "hw.logicalcpu": 8]))
    XCTAssertNil(system.memoryBytes)
    XCTAssertNil(system.physicalCores)
    XCTAssertEqual(system.logicalCores, 8)
  }

  private func record(_ changes: [String: Any] = [:]) throws -> Data {
    var json: [String: Any] = [
      "kind": "stela_setup", "schema_version": 9,
      "build": "STELA_TEST", "model": "Synthetic model", "complete": true,
      "stela_version": "0123456789abcdef", "stela_versions": ["0123456789abcdef"],
      "installs": [["name": "one", "ecid": "PRIVATE_ECID"]],
      "bundle_schema": 1, "bundle_revision": 2,
      "options": "PRIVATE_WIFI_OPTIONS", "esp": "/PRIVATE_DISK_PATH",
      "wifi": ["ssid": "PRIVATE_NETWORK"],
    ]
    json.merge(changes) { _, new in new }
    return try JSONSerialization.data(withJSONObject: json)
  }

  func testSetupInspectionProjectsOnlyDocumentedRecordValues() throws {
    let setup = try SetupSummary.parse(
      record(["pending": ["kind": "stela", "from": "old", "to": "new"]]))
    XCTAssertEqual(setup.bootVersion, "0123456789abcdef")
    XCTAssertEqual(setup.installBuild, "STELA_TEST")
    XCTAssertEqual(setup.installCount, 1)
    XCTAssertEqual(setup.retainedVersionCount, 1)
    XCTAssertTrue(setup.updatePending)
  }

  func testNewerSchemaIsDiagnosedBeforeDecodingUnknownFields() throws {
    let data = Data(#"{"kind":"stela_setup","schema_version":10}"#.utf8)
    XCTAssertThrowsError(try SetupSummary.parse(data)) { error in
      guard case SetupSummary.InspectionError.unsupportedSchema(10) = error else {
        return XCTFail("Expected an unsupported-schema diagnostic, got \(error)")
      }
    }
    XCTAssertThrowsError(try SetupSummary.parse(record(["kind": "unrelated"])))
    XCTAssertThrowsError(try SetupSummary.parse(record(["stela_version": "../../escape"])))
    XCTAssertThrowsError(try SetupSummary.parse(record(["build": "bad\nlabel"])))
    XCTAssertThrowsError(try SetupSummary.parse(Data("not JSON".utf8)))
  }

  func testInspectionRejectsOversizedInputAndBoundedFileReads() throws {
    let data = Data(repeating: 32, count: SetupSummary.maximumBytes + 1)
    XCTAssertThrowsError(try SetupSummary.parse(data))
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try data.write(to: url)
    defer { try? FileManager.default.removeItem(at: url) }
    XCTAssertThrowsError(try SetupSummary.read(from: url)) { error in
      guard case SetupSummary.InspectionError.tooLarge = error else {
        return XCTFail("Expected input limit")
      }
    }
  }

  func testReportDoesNotExportPrivateSetupFieldsOrClaimALiveConnection() throws {
    let setup = try SetupSummary.parse(record())
    let report = SystemReport(
      appVersion: "test", appBuild: "test", system: SystemSnapshot.collect(using: Control()),
      inspectedSetup: setup)
    let data = try report.json()
    let text = try XCTUnwrap(String(data: data, encoding: .utf8))
    XCTAssertFalse(text.contains("PRIVATE_"))
    XCTAssertFalse(text.contains("\"options\""))
    let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    XCTAssertEqual(json["schemaVersion"] as? Int, 1)
    XCTAssertEqual(json["runtimeConnection"] as? String, "unavailable")
    XCTAssertNotNil(json["system"])
  }
}
