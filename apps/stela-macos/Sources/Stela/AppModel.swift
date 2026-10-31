// The app's read-only system inspection and user-requested report operations.
#if os(macOS)
  import AppKit
  import Foundation
  import Metal
  import StelaSystem
  import UniformTypeIdentifiers

  enum AppSection: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case cpu = "CPU Features"
    case updates = "Updates"
    var id: String { rawValue }
  }

  @MainActor
  final class AppModel: ObservableObject {
    @Published var section: AppSection = .overview
    @Published private(set) var snapshot: SystemSnapshot?
    @Published private(set) var setup: SetupSummary?
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

    func refresh() async {
      guard !refreshing else { return }
      refreshing = true
      notice = nil
      defer { refreshing = false }
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
        appVersion: appVersion, appBuild: appBuild, system: snapshot, inspectedSetup: setup
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
