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
      VStack(alignment: .leading, spacing: Style.spacing) {
        HStack(spacing: Style.spacing) {
          HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Search", text: $search).textFieldStyle(.plain)
              .accessibilityLabel("Search CPU extensions")
          }
          .padding(8)
          .background(Style.fill, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
          Picker("Show", selection: $filter) {
            Text("All").tag("all")
            ForEach(FeatureSupport.allCases, id: \.self) {
              Text("\($0.label) (\(count($0)))").tag($0.rawValue)
            }
          }
          .labelsHidden().frame(width: 170)
        }

        if visible.isEmpty {
          Text("No matches").font(Style.value).foregroundStyle(.secondary)
            .frame(maxWidth: .infinity).padding(.vertical, Style.page)
        }

        ForEach(groups, id: \.self) { group in
          VStack(alignment: .leading, spacing: 6) {
            SectionTitle(title: group)
            Surface {
              let features = visible.filter { $0.group == group }
              ForEach(Array(features.enumerated()), id: \.element.id) { index, feature in
                if index > 0 { Divider() }
                HStack(spacing: Style.spacing) {
                  Text(feature.name)
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .frame(width: 82, alignment: .leading)
                  Text(feature.detail).font(Style.value).foregroundStyle(.secondary)
                  Spacer(minLength: 4)
                  SupportBadge(support: feature.support)
                }
                .help(feature.key)
              }
            }
          }
          .padding(.top, 4)
        }
      }
    }

    private func count(_ support: FeatureSupport) -> Int {
      system.features.filter { $0.support == support }.count
    }
  }
#endif
