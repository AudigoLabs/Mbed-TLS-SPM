// swift-tools-version:5.5

import PackageDescription

let package = Package(
    name: "MbedTLS",
    platforms: [
        .iOS(.v13),
    ],
    products: [
        .library(
            name: "MbedTLS",
            targets: ["MbedTLS"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "MbedTLS",
            dependencies: []
        ),
    ],
    swiftLanguageVersions: [.v5]
)
