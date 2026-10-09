// swift-tools-version: 5.10
// Host-side trust cache tool. TrustCache sources vendored from
// https://github.com/Lakr233/swift-trustcache (MIT, see LICENSE.swift-trustcache).
import PackageDescription

let package = Package(
    name: "trustcache",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "trustcache", targets: ["trustcache"]),
    ],
    dependencies: [
        .package(url: "https://github.com/p-x9/MachOKit", exact: "0.46.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "4.0.0"),
    ],
    targets: [
        .target(
            name: "TrustCache",
            dependencies: [.product(name: "MachOKit", package: "MachOKit")]
        ),
        .executableTarget(
            name: "trustcache",
            dependencies: [
                "TrustCache",
                .product(name: "MachOKit", package: "MachOKit"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
    ]
)
