// Bounded access to Darwin's sysctl observations, without executing shell commands.
#if canImport(Darwin)
  import Darwin
  import Foundation

  public struct DarwinSystemControl: SystemControlReading {
    public init() {}

    private func bytes(_ name: String) -> [UInt8]? {
      var size = 0
      guard sysctlbyname(name, nil, &size, nil, 0) == 0,
        size > 0, size <= 65_536
      else { return nil }
      var bytes = [UInt8](repeating: 0, count: size)
      let result = bytes.withUnsafeMutableBytes { buffer in
        sysctlbyname(name, buffer.baseAddress, &size, nil, 0)
      }
      guard result == 0, size <= bytes.count else { return nil }
      return Array(bytes.prefix(size))
    }

    public func string(_ name: String) -> String? {
      guard let bytes = bytes(name) else { return nil }
      let content = bytes.prefix { $0 != 0 }
      guard !content.isEmpty else { return nil }
      return String(bytes: content, encoding: .utf8)
    }

    public func integer(_ name: String) -> Int64? {
      guard let bytes = bytes(name) else { return nil }
      return bytes.withUnsafeBytes { buffer in
        switch buffer.count {
        case MemoryLayout<Int32>.size: return Int64(buffer.loadUnaligned(as: Int32.self))
        case MemoryLayout<Int64>.size: return buffer.loadUnaligned(as: Int64.self)
        default: return nil
        }
      }
    }
  }
#endif
