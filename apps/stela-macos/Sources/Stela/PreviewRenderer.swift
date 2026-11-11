// Opt-in native snapshots of the app's own windows, for reviewing layout:
// `--render-previews DIR` writes each section and the About This PC window
// in light and dark appearance, then quits.
#if os(macOS)
  import AppKit
  import Foundation
  import SwiftUI

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
        let about = NSWindow(
          contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        about.title = "About This PC"
        about.contentView = NSHostingView(
          rootView: ThisPCView(model: model).frame(width: 340).fixedSize())
        about.setContentSize(about.contentView!.fittingSize)
        about.center()
        about.orderFront(nil)
        guard let main = NSApp.windows.first(where: { $0.isVisible && $0 !== about }) else {
          throw RenderError.noWindow
        }
        for (theme, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
          NSApp.appearance = NSAppearance(named: appearance)
          for window in [main, about] { window.appearance = NSAppearance(named: appearance) }
          for section in AppSection.allCases {
            model.section = section
            try await Task.sleep(nanoseconds: 700_000_000)
            try write(main, to: directory.appendingPathComponent("\(name(section))-\(theme).png"))
          }
          try write(about, to: directory.appendingPathComponent("about-\(theme).png"))
        }
        NSApp.terminate(nil)
      } catch {
        fputs("Native preview rendering failed: \(error)\n", stderr)
        exit(1)
      }
    }

    private static func name(_ section: AppSection) -> String {
      section.rawValue.lowercased().replacingOccurrences(of: " ", with: "-")
    }

    /// The whole window as its frame view draws it: background, title bar
    /// and toolbar included.
    private static func write(_ window: NSWindow, to url: URL) throws {
      guard let view = window.contentView?.superview ?? window.contentView else {
        throw RenderError.noWindow
      }
      view.layoutSubtreeIfNeeded()
      view.display()
      guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
        throw RenderError.noImage
      }
      view.cacheDisplay(in: view.bounds, to: bitmap)
      guard let data = bitmap.representation(using: .png, properties: [:]) else {
        throw RenderError.noImage
      }
      try data.write(to: url, options: .atomic)
    }

    private enum RenderError: Error { case noWindow, noImage }
  }
#endif
