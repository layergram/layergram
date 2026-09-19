// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "SystemKeyboardCore",
    platforms: [
        .iOS(.v15),
        .macOS(.v11)
    ],
    products: [
        .library(name: "SystemKeyboardCore", targets: ["SystemKeyboardCore"])
    ],
    targets: [
        .target(
            name: "SystemKeyboardCore",
            path: "Sources/SystemKeyboardCore"
        ),
        .testTarget(
            name: "SystemKeyboardCoreTests",
            dependencies: ["SystemKeyboardCore"],
            path: "Tests/SystemKeyboardCoreTests"
        )
    ]
)
