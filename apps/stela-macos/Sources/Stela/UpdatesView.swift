// Versions, and a read-only look at a Stela setup record.
#if os(macOS)
  import SwiftUI

  @MainActor
  struct UpdatesView: View {
    @ObservedObject var model: AppModel

    var body: some View {
      VStack(alignment: .leading, spacing: Style.spacing) {
        Surface {
          Rows(rows: [
            ("Stela", model.host?.stelaVersion, false),
            ("Translator", model.host?.translatorID, true),
            ("App", model.appVersion, false),
            ("Revision", model.appBuild, true),
          ])
        }
        HStack(spacing: Style.spacing) {
          Button("Inspect Setup…", action: model.inspectSetup)
          Button("Software Update…") { model.openSystemApp("System Settings") }
        }

        if let setup = model.setup {
          VStack(alignment: .leading, spacing: 6) {
            HStack {
              SectionTitle(title: "Setup record")
              Spacer()
              Button("Clear", action: model.clearSetup).buttonStyle(.link).font(Style.caption)
            }
            Surface {
              Rows(rows: [
                ("Boot version", setup.bootVersion, true),
                ("Installer build", setup.installBuild, true),
                ("Model", setup.model, false),
                ("Retained versions", "\(setup.retainedVersionCount)", false),
                ("Installations", "\(setup.installCount)", false),
                ("Preparation", setup.complete ? "Complete" : "Incomplete", false),
                ("Pending update", setup.updatePending ? "Yes" : "No", false),
              ])
            }
          }
          .padding(.top, 4)
        }
      }
    }
  }
#endif
