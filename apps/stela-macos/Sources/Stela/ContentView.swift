// One quiet window for local specifications, CPU observations and Stela maintenance status.
#if os(macOS)
  import SwiftUI

  @MainActor
  struct ContentView: View {
    @ObservedObject var model: AppModel

    var body: some View {
      VStack(spacing: 0) {
        header
        Picker("Section", selection: $model.section) {
          ForEach(AppSection.allCases) { Text($0.rawValue).tag($0) }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .frame(width: 350)
        .padding(.bottom, 24)

        ScrollView {
          Group {
            if let system = model.snapshot {
              switch model.section {
              case .overview: OverviewView(model: model, system: system)
              case .cpu: CPUFeaturesView(system: system)
              case .updates: UpdatesView(model: model)
              }
            } else {
              ProgressView("Reading system information…")
                .frame(maxWidth: .infinity, minHeight: 280)
            }
          }
          .frame(maxWidth: 880)
          .padding(.horizontal, 32).padding(.bottom, 28)
          .frame(maxWidth: .infinity)
        }
        Divider()
        footer
      }
      .background(Color(nsColor: .windowBackgroundColor))
      .toolbar {
        ToolbarItemGroup {
          Button {
            Task { await model.refresh() }
          } label: {
            Label("Refresh", systemImage: "arrow.clockwise")
          }
          .help("Refresh information reported by macOS (⌘R)")
          .disabled(model.refreshing)
          Button(action: model.exportReport) {
            Label("Export Report", systemImage: "square.and.arrow.up")
          }
          .help("Export a system report (⇧⌘E)")
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

    private var header: some View {
      HStack(spacing: 16) {
        Image(nsImage: Brand.icon).resizable().interpolation(.high)
          .frame(width: 88, height: 88)
          .accessibilityHidden(true)
        VStack(alignment: .leading, spacing: 5) {
          Text("Stela").font(.system(size: 34, weight: .semibold, design: .rounded))
          Text("System information & maintenance")
            .font(.system(size: 13)).foregroundStyle(.secondary)
        }
        Spacer()
        Text(model.appVersion)
          .font(.system(size: 11, weight: .medium, design: .monospaced))
          .foregroundStyle(.secondary)
          .padding(.horizontal, 11).padding(.vertical, 6)
          .background(Color.primary.opacity(0.045), in: Capsule())
          .help("Stela app version")
      }
      .padding(.horizontal, 32).padding(.top, 23).padding(.bottom, 22)
    }

    private var footer: some View {
      HStack(spacing: 12) {
        if model.refreshing {
          ProgressView().controlSize(.small)
        } else if let notice = model.notice {
          Label(notice, systemImage: "checkmark.circle").foregroundStyle(.secondary)
        } else if let date = model.snapshot?.capturedAt {
          Text("Updated \(date.formatted(date: .omitted, time: .shortened))")
            .foregroundStyle(.secondary)
        }
        Spacer()
        Button("System Information…") { model.openSystemApp("System Information") }
          .buttonStyle(.link)
        Button("Copy Report", action: model.copyReport).disabled(model.snapshot == nil)
      }
      .font(.system(size: 11))
      .padding(.horizontal, 24).padding(.vertical, 13)
    }
  }
#endif
