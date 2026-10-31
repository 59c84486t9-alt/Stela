// The current guest-visible system and separately identified setup-record versions.
#if os(macOS)
  import SwiftUI
  import StelaSystem

  @MainActor
  struct OverviewView: View {
    @ObservedObject var model: AppModel
    let system: SystemSnapshot

    var body: some View {
      VStack(alignment: .leading, spacing: 22) {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
          SpecificationTile(
            symbol: "macwindow", title: "Operating system", value: "macOS \(system.osVersion)",
            detail: system.osBuild.map { "Build \($0)" } ?? "Build not reported")
          SpecificationTile(
            symbol: "cpu", title: "Processor", value: system.processor ?? "Not reported",
            detail: DisplayFormat.cores(system))
          SpecificationTile(
            symbol: "memorychip", title: "Memory", value: DisplayFormat.bytes(system.memoryBytes),
            detail: "Reported to macOS")
          SpecificationTile(
            symbol: "display", title: "Graphics",
            value: system.graphics.first?.name ?? "No Metal device reported", detail: graphicsDetail
          )
        }

        VStack(alignment: .leading, spacing: 0) {
          SectionHeading(title: "System")
          Surface {
            InformationRow(title: "Model", value: system.model ?? "Not reported")
            Divider().padding(.horizontal, 18)
            InformationRow(
              title: "Architecture", value: system.architecture ?? "Not reported", monospaced: true)
            Divider().padding(.horizontal, 18)
            InformationRow(title: "Uptime", value: DisplayFormat.uptime(system.uptimeSeconds))
            if let capacity = system.storageTotalBytes {
              Divider().padding(.horizontal, 18)
              InformationRow(
                title: "Data volume",
                value:
                  "\(DisplayFormat.bytes(system.storageAvailableBytes)) available of \(DisplayFormat.bytes(capacity))"
              )
            }
          }
          Text(
            "Reported by macOS. The presented model and processor may differ from the physical PC."
          )
          .font(.system(size: 11)).foregroundStyle(.secondary).padding(.top, 9)
        }

        VStack(alignment: .leading, spacing: 0) {
          SectionHeading(title: "Versions")
          Surface {
            InformationRow(title: "Stela app", value: model.appVersion)
            Divider().padding(.horizontal, 18)
            InformationRow(title: "Running Stela", value: "Connection unavailable")
            Divider().padding(.horizontal, 18)
            InformationRow(
              title: "Darwin kernel", value: system.kernelVersion ?? "Not reported",
              monospaced: true)
            if let setup = model.setup {
              Divider().padding(.horizontal, 18)
              InformationRow(
                title: "Inspected boot version", value: setup.bootVersion ?? "Not recorded",
                monospaced: true)
            }
          }
        }
      }
    }

    private var graphicsDetail: String {
      guard let first = system.graphics.first else { return "As enumerated by macOS" }
      if system.graphics.count > 1 { return "\(system.graphics.count) Metal devices reported" }
      return first.unifiedMemory
        ? "Unified memory · Metal device" : "Dedicated memory · Metal device"
    }
  }
#endif
