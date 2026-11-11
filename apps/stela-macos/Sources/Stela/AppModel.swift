// The app's read-only system inspection and user-requested report operations.
#if os(macOS)
  import AppKit
  import Foundation
  import Metal
  import StelaSystem
  import UniformTypeIdentifiers

  enum AppSection: String, CaseIterable, Identifiable {
    case thisPC = "This PC"
    case overview = "Overview"
    case cpu = "CPU Features"
    case updates = "Updates"
    var id: String { rawValue }
  }

  @MainActor
  final class AppModel: ObservableObject {
    @Published var section: AppSection = .thisPC
    @Published private(set) var snapshot: SystemSnapshot?
    @Published private(set) var setup: SetupSummary?
    /// The PC under macOS, from Stela's `StelaHost` (or `STELA_HOST_SAMPLE`).
    @Published private(set) var host: HostInventory?
    @Published private(set) var refreshing = false
    @Published var error: String?
    @Published var notice: String?

    var appVersion: String {
      Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        ?? "Development"
    }
    var appBuild: String {
      Bundle.main.object(forInfoDictionaryKey: "StelaSourceRevision") as? String
        ?? "Unpackaged build"
    }

    /// `27.0` style, from the snapshot or this process.
    var osVersion: String {
      if let version = snapshot?.osVersion { return DisplayFormat.version(version) }
      let version = ProcessInfo.processInfo.operatingSystemVersion
      return DisplayFormat.version(
        "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)")
    }

    /// The Mac model and chip macOS believes it runs on.
    var presented: String? {
      let parts = [snapshot?.model, snapshot?.processor].compactMap { $0 }
      return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    func refresh() async {
      guard !refreshing else { return }
      refreshing = true
      notice = nil
      defer { refreshing = false }
      host = Self.readHost()
      snapshot = await Task.detached(priority: .userInitiated) {
        var system = SystemSnapshot.collect(using: DarwinSystemControl())
        system.graphics = MTLCopyAllDevices().map {
          GraphicsDevice(
            name: $0.name, unifiedMemory: $0.hasUnifiedMemory,
            workingSetBytes: $0.recommendedMaxWorkingSetSize)
        }
        let home = FileManager.default.homeDirectoryForCurrentUser
        if let volume = try? home.resourceValues(forKeys: [
          .volumeTotalCapacityKey, .volumeAvailableCapacityForImportantUsageKey,
        ]) {
          system.storageTotalBytes = volume.volumeTotalCapacity.map(Int64.init)
          system.storageAvailableBytes = volume.volumeAvailableCapacityForImportantUsage
        }
        return system
      }.value
    }

    /// `STELA_HOST_SAMPLE` names a JSON file of registry values for layout checks.
    private static func readHost() -> HostInventory? {
      if let path = ProcessInfo.processInfo.environment["STELA_HOST_SAMPLE"] {
        return (try? Data(contentsOf: URL(fileURLWithPath: path)))
          .flatMap { try? HostInventory.decode(json: $0) }
      }
      return HostRegistry.read()
    }

    func copyThisPC() {
      let text = (host ?? HostInventory(properties: [:])).summary(
        osVersion: osVersion, guestMemoryBytes: snapshot?.memoryBytes,
        presentedModel: snapshot?.model, presentedChip: snapshot?.processor)
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(text, forType: .string)
    }

    func inspectSetup() {
      let panel = NSOpenPanel()
      panel.title = "Inspect Stela Setup"
      panel.message =
        "Select EFI/stela/setup.json on a mounted Stela setup volume. Inspection does not change any files."
      panel.allowedContentTypes = [.json]
      panel.allowsMultipleSelection = false
      panel.canChooseDirectories = false
      guard panel.runModal() == .OK, let url = panel.url else { return }
      let accessed = url.startAccessingSecurityScopedResource()
      defer { if accessed { url.stopAccessingSecurityScopedResource() } }
      do {
        setup = try SetupSummary.read(from: url)
        notice = "Setup record inspected"
      } catch {
        self.error = error.localizedDescription
      }
    }

    func clearSetup() { setup = nil }

    private func report() throws -> Data? {
      guard let snapshot else { return nil }
      return try SystemReport(
        appVersion: appVersion, appBuild: appBuild, system: snapshot, host: host,
        inspectedSetup: setup
      ).json()
    }

    func copyReport() {
      do {
        guard let data = try report(), let text = String(data: data, encoding: .utf8) else {
          return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        notice = "System report copied"
      } catch {
        self.error = error.localizedDescription
      }
    }

    func exportReport() {
      do {
        guard let data = try report() else { return }
        let panel = NSSavePanel()
        panel.title = "Export System Report"
        panel.nameFieldStringValue = "Stela-system-report.json"
        panel.allowedContentTypes = [.json]
        panel.message =
          "Includes system specifications and CPU feature observations. Excludes setup keys, machine IDs, disk paths and network settings. Review before sharing."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try data.write(to: url, options: .atomic)
        notice = "System report exported"
      } catch {
        self.error = error.localizedDescription
      }
    }

    func openSystemApp(_ name: String) {
      let path =
        name == "System Information"
        ? "/System/Applications/Utilities/System Information.app"
        : "/System/Applications/System Settings.app"
      NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: path), configuration: .init()) {
        _, error in
        if let error {
          Task { @MainActor in self.error = error.localizedDescription }
        }
      }
    }
  }
#endif
