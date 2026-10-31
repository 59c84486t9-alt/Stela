// Shared native layout and formatting for the system overview.
#if os(macOS)
  import SwiftUI
  import StelaSystem

  enum DisplayFormat {
    static func bytes(_ bytes: Int64?) -> String {
      guard let bytes, bytes >= 0 else { return "Not reported" }
      return ByteCountFormatter.string(fromByteCount: bytes, countStyle: .memory)
    }

    static func uptime(_ seconds: TimeInterval) -> String {
      let formatter = DateComponentsFormatter()
      formatter.allowedUnits = seconds >= 86400 ? [.day, .hour] : [.hour, .minute]
      formatter.unitsStyle = .abbreviated
      formatter.maximumUnitCount = 2
      return formatter.string(from: max(0, seconds)) ?? "Not reported"
    }

    static func cores(_ system: SystemSnapshot) -> String {
      let parts = [
        system.physicalCores.map { "\($0) physical cores" },
        system.logicalCores.map { "\($0) logical cores" },
      ]
      return parts.compactMap { $0 }.joined(separator: " · ")
    }
  }

  struct Surface<Content: View>: View {
    private let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }

    var body: some View {
      VStack(alignment: .leading, spacing: 0) { content }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(
          RoundedRectangle(cornerRadius: 14, style: .continuous)
            .strokeBorder(Color(nsColor: .separatorColor).opacity(0.45), lineWidth: 0.5))
    }
  }

  struct SectionHeading: View {
    let title: String
    var body: some View {
      Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(.secondary)
        .padding(.bottom, 8)
    }
  }

  struct InformationRow: View {
    let title: String
    let value: String
    var monospaced = false

    var body: some View {
      HStack(alignment: .firstTextBaseline, spacing: 20) {
        Text(title).foregroundStyle(.secondary).frame(width: 140, alignment: .leading)
        Text(value)
          .font(monospaced ? .system(size: 12, design: .monospaced) : .system(size: 13))
          .textSelection(.enabled)
          .frame(maxWidth: .infinity, alignment: .trailing)
          .multilineTextAlignment(.trailing)
      }
      .font(.system(size: 13))
      .padding(.horizontal, 18).padding(.vertical, 11)
    }
  }

  struct SpecificationTile: View {
    let symbol: String
    let title: String
    let value: String
    let detail: String

    var body: some View {
      Surface {
        HStack(alignment: .top, spacing: 14) {
          Image(systemName: symbol)
            .font(.system(size: 20, weight: .regular))
            .foregroundStyle(Color.accentColor)
            .frame(width: 34, height: 38)
            .accessibilityHidden(true)
          VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 12)).foregroundStyle(.secondary)
            Text(value).font(.system(size: 17, weight: .semibold)).lineLimit(2)
            if !detail.isEmpty {
              Text(detail).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(2)
            }
          }
          Spacer(minLength: 0)
        }
        .padding(18)
        .frame(minHeight: 112, alignment: .topLeading)
      }
    }
  }

  struct SupportBadge: View {
    let support: FeatureSupport
    private var color: Color {
      switch support {
      case .supported: return .green
      case .unsupported, .notReported: return .secondary
      }
    }
    private var symbol: String {
      switch support {
      case .supported: return "checkmark.circle.fill"
      case .unsupported: return "minus.circle"
      case .notReported: return "questionmark.circle"
      }
    }

    var body: some View {
      Label(support.label, systemImage: symbol)
        .font(.system(size: 11, weight: .medium))
        .foregroundStyle(color)
        .padding(.horizontal, 9).padding(.vertical, 5)
        .background(color.opacity(0.08), in: Capsule())
        .accessibilityLabel(support.label)
    }
  }
#endif
