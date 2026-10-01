#!/usr/bin/env python3
"""Put stdin on an iOS Simulator clipboard when simctl pbcopy is broken.

Builds a disposable local app, writes the carrier into its sandbox, launches
it, and verifies the simulator pasteboard byte-for-byte. It does not open or
decode the carrier in Layergram; the tester must still use the app's Paste and
Decode button. Never pass identity secrets to this helper.
"""

from __future__ import annotations

import hashlib
import platform
import plistlib
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


BUNDLE_ID = "com.layergram.localtest.clipboardbridge"
SOURCE = Path(__file__).with_suffix(".swift")


def run_xcrun(*arguments: str) -> str:
    result = subprocess.run(["xcrun", *arguments], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {Path(sys.argv[0]).name} SIMULATOR_UDID < carrier.txt", file=sys.stderr)
        return 2

    try:
        simulator = str(uuid.UUID(sys.argv[1]))
    except ValueError:
        print("Select a simulator by its UUID.", file=sys.stderr)
        return 2
    carrier = sys.stdin.buffer.read()
    if not carrier:
        print("The carrier is empty.", file=sys.stderr)
        return 2
    try:
        carrier.decode("utf-8")
    except UnicodeDecodeError:
        print("The carrier is not UTF-8 text.", file=sys.stderr)
        return 2

    arch = platform.machine()
    if arch not in {"arm64", "x86_64"}:
        print(f"Unsupported simulator host architecture: {arch}", file=sys.stderr)
        return 2

    sdk = run_xcrun("--sdk", "iphonesimulator", "--show-sdk-path")
    with tempfile.TemporaryDirectory(prefix="layergram-ios-clipboard-") as temporary:
        app = Path(temporary) / "ClipboardBridge.app"
        app.mkdir()
        (app / "Info.plist").write_bytes(
            plistlib.dumps(
                {
                    "CFBundleIdentifier": BUNDLE_ID,
                    "CFBundleExecutable": "ClipboardBridge",
                    "CFBundleName": "ClipboardBridge",
                    "CFBundlePackageType": "APPL",
                    "CFBundleVersion": "1",
                    "CFBundleShortVersionString": "1.0",
                    "LSRequiresIPhoneOS": True,
                    "MinimumOSVersion": "17.0",
                }
            )
        )
        run_xcrun(
            "--sdk", "iphonesimulator", "swiftc",
            "-parse-as-library",
            "-target", f"{arch}-apple-ios17.0-simulator",
            "-sdk", sdk,
            "-framework", "UIKit",
            "-o", str(app / "ClipboardBridge"),
            str(SOURCE),
        )
        run_xcrun("simctl", "install", simulator, str(app))

    data_container = Path(
        run_xcrun("simctl", "get_app_container", simulator, BUNDLE_ID, "data")
    )
    documents = data_container / "Documents"
    documents.mkdir(exist_ok=True)
    (documents / "carrier.txt").write_bytes(carrier)
    run_xcrun(
        "simctl", "launch", "--terminate-running-process",
        simulator, BUNDLE_ID,
    )

    for _ in range(50):
        current = subprocess.run(
            ("xcrun", "simctl", "pbpaste", simulator),
            check=True,
            capture_output=True,
        ).stdout
        if current == carrier:
            print(
                f"Simulator pasteboard verified: {len(carrier)} bytes, "
                f"SHA-256 {hashlib.sha256(carrier).hexdigest()}"
            )
            return 0
        time.sleep(0.1)

    print("Simulator pasteboard did not match the input carrier.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
