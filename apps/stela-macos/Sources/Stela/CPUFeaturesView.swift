// Searchable capability reports, keeping negative answers distinct from missing selectors.
#if os(macOS)
  import SwiftUI
  import StelaSystem

  struct CPUFeaturesView: View {
    let system: SystemSnapshot
    @State private var search = ""
    @State private var filter = "all"

    private var visible: [CPUFeature] {
      system.features.filter {
        (filter == "all" || $0.support.rawValue == filter)
          && (search.isEmpty
            || "\($0.name) \($0.detail) \($0.group) \($0.key)".localizedCaseInsensitiveContains(
              search))
      }
    }

    private var groups: [String] {
      var result: [String] = []
      for feature in visible where !result.contains(feature.group) { result.append(feature.group) }
      return result
    }

    var body: some View {
      VStack(alignment: .leading, spacing: 20) {
        VStack(alignment: .leading, spacing: 7) {
          Text("CPU features").font(.system(size: 22, weight: .semibold))
          Text("Capabilities reported by macOS for \(system.architecture ?? "this architecture").")
            .font(.system(size: 13)).foregroundStyle(.secondary)
          HStack(spacing: 16) {
            ForEach(FeatureSupport.allCases, id: \.self) { support in
              Text(
                "\(system.features.filter { $0.support == support }.count) \(support.label.lowercased())"
              )
              .foregroundStyle(support == .supported ? Color.green : Color.secondary)
            }
          }
          .font(.system(size: 11, weight: .medium)).padding(.top, 5)
        }

        HStack(spacing: 12) {
          HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Find an extension", text: $search).textFieldStyle(.plain)
              .accessibilityLabel("Search CPU extensions")
            if !search.isEmpty {
              Button {
                search = ""
              } label: {
                Image(systemName: "xmark.circle.fill")
              }
              .buttonStyle(.plain).foregroundStyle(.secondary)
              .accessibilityLabel("Clear search")
            }
          }
          .padding(10)
          .background(
            Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
          Picker("Show", selection: $filter) {
            Text("All features").tag("all")
            ForEach(FeatureSupport.allCases, id: \.self) { Text($0.label).tag($0.rawValue) }
          }
          .labelsHidden().frame(width: 155)
          .accessibilityLabel("Filter CPU feature support")
        }

        if visible.isEmpty {
          VStack(spacing: 10) {
            Image(systemName: "cpu").font(.system(size: 26)).foregroundStyle(.secondary)
            Text(
              system.features.isEmpty
                ? "No feature catalog for this architecture" : "No matching extensions")
            Text(
              system.features.isEmpty
                ? "The app has no capability selectors for the reported architecture."
                : "Try another search or support filter."
            )
            .font(.system(size: 12)).foregroundStyle(.secondary)
          }
          .frame(maxWidth: .infinity).padding(.vertical, 30)
        }

        ForEach(groups, id: \.self) { group in
          VStack(alignment: .leading, spacing: 0) {
            SectionHeading(title: group)
            Surface {
              let features = visible.filter { $0.group == group }
              ForEach(Array(features.enumerated()), id: \.element.id) { index, feature in
                if index > 0 { Divider().padding(.horizontal, 16) }
                HStack(spacing: 12) {
                  Text(feature.name)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .frame(width: 82, alignment: .leading)
                  Text(feature.detail).font(.system(size: 12)).foregroundStyle(.secondary)
                  Spacer(minLength: 4)
                  SupportBadge(support: feature.support)
                }
                .padding(.horizontal, 16).padding(.vertical, 10)
                .help(feature.key)
              }
            }
          }
        }

        VStack(alignment: .leading, spacing: 7) {
          Text("About these results").font(.system(size: 12, weight: .semibold))
          Text(
            "“Not reported” means macOS did not provide a usable answer. It does not mean the extension is unsupported. These reports do not certify Stela’s implementation of every instruction."
          )
          Text(
            "Physical PC extensions and Stela’s selected acceleration tier require a runtime connection, which is unavailable in this build."
          )
        }
        .font(.system(size: 11)).foregroundStyle(.secondary)
      }
    }
  }
#endif
