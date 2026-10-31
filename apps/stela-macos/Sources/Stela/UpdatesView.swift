// Read-only setup inspection until authenticated in-guest activation is available.
#if os(macOS)
  import SwiftUI

  @MainActor
  struct UpdatesView: View {
    @ObservedObject var model: AppModel

    var body: some View {
      VStack(alignment: .leading, spacing: 23) {
        Surface {
          HStack(alignment: .top, spacing: 17) {
            Image(systemName: "shippingbox")
              .font(.system(size: 28)).foregroundStyle(Color.accentColor)
              .frame(width: 42, height: 45).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 9) {
              Text("Stela updates").font(.system(size: 20, weight: .semibold))
              Text("Automatic updates aren’t available in this build.")
                .font(.system(size: 13))
              Text(
                "Inspect an existing setup to see its recorded boot version, retained versions and update status."
              )
              .font(.system(size: 12)).foregroundStyle(.secondary)
              Button("Inspect Stela Setup…", action: model.inspectSetup)
                .padding(.top, 6)
            }
            Spacer(minLength: 0)
          }
          .padding(24)
        }

        if let setup = model.setup {
          VStack(alignment: .leading, spacing: 0) {
            HStack {
              SectionHeading(title: "Inspected setup")
              Spacer()
              Button("Clear", action: model.clearSetup).buttonStyle(.link).font(.system(size: 11))
            }
            Surface {
              InformationRow(
                title: "Boot version", value: setup.bootVersion ?? "Not recorded", monospaced: true)
              Divider().padding(.horizontal, 18)
              InformationRow(
                title: "Installer macOS build", value: setup.installBuild, monospaced: true)
              Divider().padding(.horizontal, 18)
              InformationRow(title: "Presented model", value: setup.model)
              Divider().padding(.horizontal, 18)
              InformationRow(title: "Retained versions", value: "\(setup.retainedVersionCount)")
              Divider().padding(.horizontal, 18)
              InformationRow(title: "Installations", value: "\(setup.installCount)")
              Divider().padding(.horizontal, 18)
              InformationRow(
                title: "Setup status",
                value: setup.complete ? "Preparation complete" : "Preparation incomplete")
              Divider().padding(.horizontal, 18)
              InformationRow(
                title: "Update transaction",
                value: setup.updatePending
                  ? "Pending — inspect with stela setup status" : "None recorded")
            }
            Text(
              "Read from the selected setup record at \(setup.inspectedAt.formatted(date: .abbreviated, time: .shortened)). These are recorded values, not verified running versions or a file-integrity check."
            )
            .font(.system(size: 11)).foregroundStyle(.secondary).padding(.top, 10)
          }
        }

        VStack(alignment: .leading, spacing: 0) {
          SectionHeading(title: "This app")
          Surface {
            InformationRow(title: "Version", value: model.appVersion)
            Divider().padding(.horizontal, 18)
            InformationRow(title: "Source revision", value: model.appBuild, monospaced: true)
            Divider().padding(.horizontal, 18)
            InformationRow(title: "Runtime connection", value: "Unavailable in this build")
          }
        }

        HStack(alignment: .top, spacing: 12) {
          Image(systemName: "macwindow").font(.system(size: 19)).foregroundStyle(.secondary)
          VStack(alignment: .leading, spacing: 7) {
            Text("macOS updates").font(.system(size: 13, weight: .semibold))
            Text(
              "macOS updates are managed in System Settings. Check compatibility with your Stela release before upgrading."
            )
            .font(.system(size: 12)).foregroundStyle(.secondary)
            Button("Open System Settings…") { model.openSystemApp("System Settings") }
              .buttonStyle(.link).font(.system(size: 12))
          }
        }
        .padding(.horizontal, 3)
      }
    }
  }
#endif
