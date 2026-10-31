// Native macOS application entry point. Other hosts can build and test the inspection library.
#if os(macOS)
  import AppKit
  import SwiftUI

  @main
  @MainActor
  struct StelaApp: App {
    @StateObject private var model = AppModel()

    init() {
      NSApplication.shared.setActivationPolicy(.regular)
    }

    var body: some Scene {
      Window("Stela", id: "main") {
        ContentView(model: model)
          .frame(minWidth: 700, minHeight: 650)
          .task {
            NSApplication.shared.applicationIconImage = Brand.icon
            await model.refresh()
            await PreviewRenderer.renderIfRequested(model: model)
          }
      }
      .defaultSize(width: 820, height: 790)
      .windowResizability(.contentMinSize)
      .commands {
        CommandGroup(replacing: .newItem) {}
        CommandMenu("System") {
          Button("Refresh System Information") { Task { await model.refresh() } }
            .keyboardShortcut("r")
            .disabled(model.refreshing)
          Divider()
          Button("Copy System Report", action: model.copyReport)
            .keyboardShortcut("c", modifiers: [.command, .shift])
            .disabled(model.snapshot == nil)
          Button("Export System Report…", action: model.exportReport)
            .keyboardShortcut("e", modifiers: [.command, .shift])
            .disabled(model.snapshot == nil)
          Divider()
          Button("Inspect Stela Setup…", action: model.inspectSetup)
          Button("Open System Information…") { model.openSystemApp("System Information") }
        }
      }
    }
  }
#else
  import Foundation

  @main
  enum UnsupportedPlatform {
    static func main() {
      fputs(
        "Stela.app requires macOS 13 or later. The inspection library can be tested on this platform.\n",
        stderr)
      exit(1)
    }
  }
#endif
