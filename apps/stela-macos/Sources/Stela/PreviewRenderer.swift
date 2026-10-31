// Opt-in native snapshots for reviewing the same SwiftUI views used by the app.
#if os(macOS)
  import AppKit
  import Foundation

  @MainActor
  enum PreviewRenderer {
    static func renderIfRequested(model: AppModel) async {
      let args = ProcessInfo.processInfo.arguments
      guard let index = args.firstIndex(of: "--render-previews"), index + 1 < args.count else {
        return
      }
      let directory = URL(fileURLWithPath: args[index + 1], isDirectory: true)
      do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for (theme, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
          NSApp.appearance = NSAppearance(named: appearance)
          for section in AppSection.allCases {
            model.section = section
            try await Task.sleep(nanoseconds: 600_000_000)
            guard let view = NSApp.windows.first(where: { $0.isVisible })?.contentView else {
              throw RenderError.noWindow
            }
            view.layoutSubtreeIfNeeded()
            guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
              throw RenderError.noImage
            }
            view.cacheDisplay(in: view.bounds, to: bitmap)
            guard let data = bitmap.representation(using: .png, properties: [:]) else {
              throw RenderError.noImage
            }
            let name = "\(section == .cpu ? "cpu" : section.rawValue.lowercased())-\(theme).png"
            try data.write(to: directory.appendingPathComponent(name), options: .atomic)
          }
        }
        NSApp.terminate(nil)
      } catch {
        fputs("Native preview rendering failed: \(error)\n", stderr)
        exit(1)
      }
    }

    private enum RenderError: Error { case noWindow, noImage }
  }
#endif
