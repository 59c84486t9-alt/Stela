// Reads the StelaGPU kext's `StelaHost` dictionary from the I/O Registry.
#if canImport(IOKit)
  import Foundation
  import IOKit

  public enum HostRegistry {
    /// The PC Stela runs on, or nil on a Mac or a Stela that does not report it.
    public static func read() -> HostInventory? {
      let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("StelaGPU"))
      guard service != 0 else { return nil }
      defer { IOObjectRelease(service) }
      guard
        let value = IORegistryEntryCreateCFProperty(
          service, "StelaHost" as CFString, kCFAllocatorDefault, 0)?
          .takeRetainedValue() as? [String: Any]
      else { return nil }
      return HostInventory(properties: value)
    }
  }
#endif
