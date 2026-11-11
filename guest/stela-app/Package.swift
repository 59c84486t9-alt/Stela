// swift-tools-version: 5.9
import PackageDescription

let package = Package(
  name: "Stela",
  platforms: [.macOS(.v13)],
  products: [.executable(name: "Stela", targets: ["Stela"])],
  targets: [
    .target(name: "StelaSystem"),
    .executableTarget(name: "Stela", dependencies: ["StelaSystem"]),
    .testTarget(name: "StelaSystemTests", dependencies: ["StelaSystem"]),
  ]
)
