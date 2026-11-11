// One set of spacing, shape and type for every view.
#if os(macOS)
  import SwiftUI
  import StelaSystem

  enum Style {
    /// Inside every card, on all four edges.
    static let padding: CGFloat = 14
    /// Between cards, and between rows inside a card.
    static let spacing: CGFloat = 10
    static let radius: CGFloat = 12
    /// Around a page's content.
    static let page: CGFloat = 24
    static let title = Font.system(size: 22, weight: .semibold)
    static let value = Font.system(size: 13, weight: .medium)
    static let caption = Font.system(size: 11)
    static let fill = Color.primary.opacity(0.05)
  }

  enum DisplayFormat {
    static func bytes(_ bytes: Int64?) -> String? {
      guard let bytes, bytes > 0 else { return nil }
      return HostInventory.bytes(UInt64(bytes))
    }

    static func uptime(_ seconds: TimeInterval) -> String? {
      let formatter = DateComponentsFormatter()
      formatter.allowedUnits = seconds >= 86400 ? [.day, .hour] : [.hour, .minute]
      formatter.unitsStyle = .abbreviated
      formatter.maximumUnitCount = 2
      return formatter.string(from: max(0, seconds))
    }

    static func counts(cores: Int64?, threads: Int64?) -> String? {
      let parts = [cores.map { "\($0) cores" }, threads.map { "\($0) threads" }].compactMap { $0 }
      return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    /// `27.0` for 27.0.0, `14.6.1` as it is.
    static func version(_ version: String) -> String {
      version.hasSuffix(".0") && version.split(separator: ".").count == 3
        ? String(version.dropLast(2)) : version
    }
  }

  /// A label, a value and an optional detail on the card background.
  struct Card: View {
    let label: String
    let value: String
    var detail: String?

    var body: some View {
      VStack(alignment: .leading, spacing: 3) {
        Text(label).font(Style.caption).foregroundStyle(.secondary)
        Text(value).font(Style.value).textSelection(.enabled)
        if let detail {
          Text(detail).font(Style.caption).foregroundStyle(.secondary)
        }
      }
      // Fills a grid row's height, so cards side by side end together.
      .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
      .padding(Style.padding)
      .background(Style.fill, in: RoundedRectangle(cornerRadius: Style.radius, style: .continuous))
    }
  }

  /// Rows on one card background, separated by dividers; the card's padding
  /// is the same on every edge.
  struct Surface<Content: View>: View {
    private let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }

    var body: some View {
      VStack(alignment: .leading, spacing: Style.spacing) { content }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Style.padding)
        .background(Style.fill, in: RoundedRectangle(cornerRadius: Style.radius, style: .continuous))
    }
  }

  /// A titled value inside a Surface.
  struct InformationRow: View {
    let title: String
    let value: String
    var monospaced = false

    var body: some View {
      HStack(alignment: .firstTextBaseline, spacing: 16) {
        Text(title).foregroundStyle(.secondary)
        Spacer(minLength: 8)
        Text(value)
          .font(monospaced ? .system(size: 12, weight: .medium, design: .monospaced) : Style.value)
          .textSelection(.enabled)
          .multilineTextAlignment(.trailing)
      }
      .font(Style.value)
    }
  }

  /// Rows with a divider between each, skipping rows without a value.
  struct Rows: View {
    let rows: [(String, String?, Bool)]

    var body: some View {
      let shown = rows.compactMap { row in row.1.map { (row.0, $0, row.2) } }
      ForEach(Array(shown.enumerated()), id: \.offset) { index, row in
        if index > 0 { Divider() }
        InformationRow(title: row.0, value: row.1, monospaced: row.2)
      }
    }
  }

  struct SectionTitle: View {
    let title: String
    var body: some View {
      Text(title).font(Style.caption).foregroundStyle(.secondary)
    }
  }

  struct SupportBadge: View {
    let support: FeatureSupport
    private var color: Color { support == .supported ? .green : .secondary }
    private var symbol: String {
      switch support {
      case .supported: return "checkmark.circle.fill"
      case .unsupported: return "minus.circle"
      case .notReported: return "questionmark.circle"
      }
    }

    var body: some View {
      Image(systemName: symbol)
        .font(Style.value)
        .foregroundStyle(color)
        .help(support.label)
        .accessibilityLabel(support.label)
    }
  }
#endif
