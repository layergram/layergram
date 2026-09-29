"""Collect one ciphertext attachment from a passing physical transport test."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile


def validate_carrier(text: str) -> str:
    carrier = text.strip()
    if not carrier or len(carrier.encode("utf-16-le")) // 2 > 4000:
        raise ValueError("Expected a complete carrier within the transport limit")
    if any(re.fullmatch(r"(?:p1|m3|b3)\.[A-Za-z0-9_-]+", line) is None
           for line in carrier.splitlines()):
        raise ValueError("Expected a complete V3 text carrier without fractions")
    return carrier


def collect(directory: Path, attachment_name: str) -> str:
    manifest = json.loads((directory / "manifest.json").read_text())
    matches = [a for test in manifest for a in test.get("attachments", [])
               if a.get("suggestedHumanReadableName", "") == attachment_name
               or a.get("suggestedHumanReadableName", "").startswith(attachment_name + "_")]
    if len(matches) != 1 or matches[0].get("isAssociatedWithFailure"):
        raise ValueError("Expected exactly one successful carrier attachment")
    name = matches[0]["exportedFileName"]
    if Path(name).name != name:
        raise ValueError("Invalid attachment file name")
    return validate_carrier((directory / name).read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--attachment", default="QA outgoing reply carrier")
    args = parser.parse_args()
    summary = json.loads(subprocess.check_output([
        "xcrun", "xcresulttool", "get", "test-results", "summary", "--path", str(args.result)]))
    if (summary.get("result") != "Passed" or summary.get("failedTests") != 0
            or summary.get("skippedTests") != 0 or not summary.get("passedTests")):
        raise SystemExit("Cannot collect a carrier from failed or skipped tests")
    with tempfile.TemporaryDirectory(prefix="layergram-transport-attachments-") as folder:
        subprocess.run(["xcrun", "xcresulttool", "export", "attachments", "--path", str(args.result),
                        "--output-path", folder], check=True, stdout=subprocess.DEVNULL)
        carrier = collect(Path(folder), args.attachment)
    args.output.write_text(carrier)
    print("QA carrier collected; code units=" + str(len(carrier.encode("utf-16-le")) // 2))


if __name__ == "__main__":
    main()
