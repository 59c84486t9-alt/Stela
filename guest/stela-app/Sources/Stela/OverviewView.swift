// What macOS reports about the system it runs on.
#if os(macOS)
  import SwiftUI
  import StelaSystem

  @MainActor
  struct OverviewView: View {
    @ObservedObject var model: AppModel
    let system: SystemSnapshot

    var body: some View {
      VStack(alignment: .leading, spacing: Style.spacing) {
        let cards = self.cards
        Grid(horizontalSpacing: Style.spacing, verticalSpacing: Style.spacing) {
          ForEach(Array(stride(from: 0, to: cards.count, by: 2)), id: \.self) { index in
            GridRow {
              cards[index]
              if index + 1 < cards.count { cards[index + 1] } else { Color.clear }
            }
          }
        }
        Surface {
          Rows(rows: [
            ("Model", system.model, false),
            ("Architecture", system.architecture, true),
            ("Kernel", system.kernelVersion, true),
            ("Uptime", DisplayFormat.uptime(system.uptimeSeconds), false),
            ("Data volume", dataVolume, false),
          ])
        }
      }
    }

    private var cards: [Card] {
      var cards = [
        Card(label: "macOS", value: DisplayFormat.version(system.osVersion), detail: system.osBuild)
      ]
      if let processor = system.processor {
        cards.append(
          Card(
            label: "Processor", value: processor,
            detail: DisplayFormat.counts(cores: system.physicalCores, threads: system.logicalCores)))
      }
      if let memory = DisplayFormat.bytes(system.memoryBytes) {
        cards.append(Card(label: "Memory", value: memory))
      }
      if let graphics = system.graphics.first {
        cards.append(
          Card(
            label: "Graphics", value: graphics.name,
            detail: graphics.unifiedMemory ? "Unified memory" : "Dedicated memory"))
      }
      return cards
    }

    private var dataVolume: String? {
      guard let total = DisplayFormat.bytes(system.storageTotalBytes) else { return nil }
      guard let free = DisplayFormat.bytes(system.storageAvailableBytes) else { return total }
      return "\(free) free of \(total)"
    }
  }
#endif
