// The real PC under macOS, in the manner of About This Mac.
#if os(macOS)
  import SwiftUI
  import StelaSystem

  @MainActor
  struct ThisPCView: View {
    @ObservedObject var model: AppModel
    @State private var copied = false

    var body: some View {
      VStack(spacing: Style.spacing) {
        VStack(spacing: 4) {
          Image(nsImage: Brand.icon).resizable().interpolation(.high)
            .frame(width: 76, height: 76)
            .accessibilityHidden(true)
          Text("macOS \(model.osVersion)").font(Style.title)
          if let version = model.host?.stelaVersion {
            Text("Stela \(version)").font(Style.caption).foregroundStyle(.secondary)
          }
        }
        .padding(.bottom, Style.spacing)

        if let host = model.host {
          cards(host)
        } else {
          Card(label: "Hardware", value: "No PC description from Stela")
        }

        if let presented = model.presented {
          Text("Presented as \(presented)")
            .font(Style.caption).foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .padding(.top, 4)
        }

        Button(copied ? "Copied" : "Copy") {
          model.copyThisPC()
          copied = true
          Task {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            copied = false
          }
        }
        .padding(.top, 4)
      }
      .padding(Style.page)
    }

    @ViewBuilder
    private func cards(_ host: HostInventory) -> some View {
      if let cpu = host.cpuBrand {
        Card(
          label: "Processor", value: cpu,
          detail: DisplayFormat.counts(
            cores: host.hostCores.map(Int64.init), threads: host.hostThreads.map(Int64.init)))
      }
      ForEach(Array(host.gpus.enumerated()), id: \.offset) { _, gpu in
        if let name = gpu.name {
          Card(label: "Graphics", value: name, detail: gpu.vramBytes.map(HostInventory.bytes))
        }
      }
      if let memory = host.hostMemoryBytes {
        Card(
          label: "Memory", value: HostInventory.bytes(memory),
          detail: DisplayFormat.bytes(model.snapshot?.memoryBytes).map { "\($0) for macOS" })
      }
      if let level = host.translationLevel {
        let extensions = host.notableExtensions
        // A no-break space keeps each dot after its name when the line wraps.
        Card(
          label: "Translation", value: level,
          detail: extensions.isEmpty ? nil : extensions.joined(separator: "\u{00A0}· ")
        )
        .help(host.translatorTarget ?? "")
      }
      if let system = host.system {
        Card(label: "System", value: system, detail: host.firmware.map { "Firmware \($0)" })
      }
    }
  }
#endif
