// swift-tools-version:5.9
import PackageDescription

// The only dependency is Pgpbridge.xcframework, built LOCALLY from ./PGPBridge
// (Go, wrapping ProtonMail GopenPGP) by scripts/build-pgp.sh. No remote binaries.
let package = Package(
    name: "PassBarKit",
    platforms: [.macOS(.v14)],
    products: [.library(name: "PassBarKit", targets: ["PassBarKit"])],
    targets: [
        .binaryTarget(name: "Pgpbridge", path: "Pgpbridge.xcframework"),
        .target(name: "PassBarKit", dependencies: ["Pgpbridge"]),
        .testTarget(name: "PassBarKitTests", dependencies: ["PassBarKit"]),
    ]
)
