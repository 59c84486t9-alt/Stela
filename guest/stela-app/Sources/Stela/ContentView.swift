// The main window: one page per section, chosen in the toolbar.
#if os(macOS)
  import SwiftUI

  @MainActor
  struct ContentView: View {
    @ObservedObject var model: AppModel

    var body: some View {
      ScrollView {
        Group {
          switch model.section {
          case .thisPC:
            ThisPCView(model: model).frame(width: 380)
          case .overview, .cpu, .updates:
            if let system = model.snapshot {
              switch model.section {
              case .cpu: CPUFeaturesView(system: system)
              case .updates: UpdatesView(model: model)
              default: OverviewView(model: model, system: system)
              }
            } else {
              ProgressView().frame(maxWidth: .infinity, minHeight: 240)
            }
          }
        }
        .frame(maxWidth: 720)
        .padding(Style.page)
        .frame(maxWidth: .infinity)
      }
      .toolbar {
        ToolbarItem(placement: .principal) {
          Picker("Section", selection: $model.section) {
            ForEach(AppSection.allCases) { Text($0.rawValue).tag($0) }
          }
          .pickerStyle(.segmented)
          .labelsHidden()
        }
        ToolbarItemGroup {
          Button {
            Task { await model.refresh() }
          } label: {
            Label("Refresh", systemImage: "arrow.clockwise")
          }
          .help("Refresh (⌘R)")
          .disabled(model.refreshing)
          Button(action: model.exportReport) {
            Label("Export Report", systemImage: "square.and.arrow.up")
          }
          .help("Export Report (⇧⌘E)")
          .disabled(model.snapshot == nil)
        }
      }
      .alert(
        "Unable to Complete Action",
        isPresented: Binding(
          get: { model.error != nil }, set: { if !$0 { model.error = nil } }
        )
      ) {
        Button("OK", role: .cancel) { model.error = nil }
      } message: {
        Text(model.error ?? "")
      }
    }
  }
#endif
