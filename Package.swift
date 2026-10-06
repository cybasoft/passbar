// swift-tools-version:5.9
import PackageDescription

// The only dependency is Pgpbridge.xcframework, built LOCALLY from ./PGPBridge
// (Go, wrapping ProtonMail GopenPGP) by scripts/build-pgp.sh. No remote binaries.
let package = Package(
    name: "PassboltKit",
    platforms: [.macOS(.v14)],
    products: [.library(name: "PassboltKit", targets: ["PassboltKit"])],
    targets: [
        .binaryTarget(name: "Pgpbridge", path: "Pgpbridge.xcframework"),
        .target(name: "PassboltKit", dependencies: ["Pgpbridge"]),
        .testTarget(name: "PassboltKitTests", dependencies: ["PassboltKit"]),
    ]
)
