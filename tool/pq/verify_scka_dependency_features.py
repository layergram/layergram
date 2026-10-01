#!/usr/bin/env python3
"""Check the actual AES instance used by AES-GCM-SIV in Cargo's resolved graph."""

import json
import sys


def verify(metadata):
    packages = {package["id"]: package for package in metadata["packages"]}
    resolution = metadata["resolve"]
    nodes = {node["id"]: node for node in resolution["nodes"]}
    root = resolution["root"]
    if packages[root]["name"] != "layergram-scka":
        raise ValueError("Expected the layergram-scka dependency graph")
    if "candidate-ffi" not in nodes[root]["features"]:
        raise ValueError("Resolve the graph with the candidate-ffi feature")

    reachable = set()
    pending = [root]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        pending.extend(nodes[package_id]["dependencies"])

    ciphers = [
        package_id
        for package_id in sorted(reachable)
        if packages[package_id]["name"] == "aes-gcm-siv"
    ]
    if not ciphers:
        raise ValueError("No resolved AES-GCM-SIV implementation found")

    for cipher_id in ciphers:
        aes_dependencies = [
            package_id
            for package_id in nodes[cipher_id]["dependencies"]
            if packages[package_id]["name"] == "aes"
        ]
        if len(aes_dependencies) != 1:
            raise ValueError("Expected one resolved AES dependency for AES-GCM-SIV")
        aes_id = aes_dependencies[0]
        if "zeroize" not in nodes[aes_id]["features"]:
            cipher_version = packages[cipher_id]["version"]
            aes_version = packages[aes_id]["version"]
            raise ValueError(
                f"AES-GCM-SIV {cipher_version} uses AES {aes_version} "
                "without the required zeroize feature"
            )
    return len(ciphers)


def main():
    try:
        count = verify(json.load(sys.stdin))
    except (ValueError, KeyError, TypeError) as error:
        print(f"SCKA dependency-feature check failed: {error}", file=sys.stderr)
        return 1
    print(f"SCKA dependency features: PASS ({count} cipher implementation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
