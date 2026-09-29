#!/usr/bin/env python3
"""Fail before installation when a device profile cannot authorize the keyboard."""
import argparse
import datetime
import fnmatch
import pathlib
import plistlib
import subprocess


def verify_profile(profile, signed, identifier, groups, device=None):
    allowed = profile.get("Entitlements", {})
    if set(signed.get("com.apple.security.application-groups", [])) != groups:
        raise ValueError("signed App Groups differ from the requested groups")
    if not groups.issubset(set(allowed.get("com.apple.security.application-groups", []))):
        raise ValueError("provisioning profile does not authorize every App Group")
    application_id = signed.get("application-identifier", "")
    allowed_id = allowed.get("application-identifier", "")
    if not application_id.endswith("." + identifier) or not allowed_id or not fnmatch.fnmatchcase(application_id, allowed_id):
        raise ValueError("provisioning profile does not authorize the signed application")
    team = signed.get("com.apple.developer.team-identifier")
    if not team or team != allowed.get("com.apple.developer.team-identifier"):
        raise ValueError("signed team differs from the provisioning profile")
    expiration = profile.get("ExpirationDate")
    if not isinstance(expiration, datetime.datetime) or expiration.replace(tzinfo=datetime.timezone.utc) <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("provisioning profile has expired or lacks an expiration")
    if device and not profile.get("ProvisionsAllDevices", False) and device not in profile.get("ProvisionedDevices", []):
        raise ValueError("provisioning profile does not authorize the selected device")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, type=pathlib.Path)
    parser.add_argument("--identifier", required=True)
    parser.add_argument("--device")
    parser.add_argument("--kind", choices=["keyboard", "custody"], default="keyboard")
    args = parser.parse_args()
    root, identifier = args.app, args.identifier
    products = [
        (root, identifier, {f"group.{identifier}", f"group.{identifier}.keyboard"}),
        (root / "PlugIns/LayergramKeyboard.appex", f"{identifier}.keyboard", {f"group.{identifier}.keyboard"}),
        (root / "PlugIns/Share Extension.appex", f"{identifier}.share", {f"group.{identifier}"}),
    ]
    if args.kind == "custody":
        if identifier != "app.layergram.keyboardvalidation.qa":
            raise SystemExit("Custody lifecycle checks require the fixed disposable identifier")
        products = [(root, identifier, {f"group.{identifier}"})]
    for bundle, bundle_id, groups in products:
        if plistlib.loads((bundle / "Info.plist").read_bytes())["CFBundleIdentifier"] != bundle_id:
            raise SystemExit(f"Bundle identifier mismatch: {bundle.name}")
        signed = plistlib.loads(subprocess.check_output(
            ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(bundle)], stderr=subprocess.DEVNULL))
        profile = plistlib.loads(subprocess.check_output(
            ["/usr/bin/security", "cms", "-D", "-i", str(bundle / "embedded.mobileprovision")], stderr=subprocess.DEVNULL))
        try:
            verify_profile(profile, signed, bundle_id, groups, args.device)
        except ValueError as error:
            raise SystemExit(f"Invalid keyboard signing in {bundle.name}: {error}") from error
    print("Device profiles authorize the app, keyboard, share extension and their App Groups.")


if __name__ == "__main__":
    main()
