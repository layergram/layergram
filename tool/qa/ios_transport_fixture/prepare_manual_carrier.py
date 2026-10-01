"""Load a fresh QA carrier in the retained offline host for a manual privacy gate."""
import argparse
import os
from pathlib import Path
import subprocess

from collect_carrier import validate_carrier


def prepare(device: str, carrier: str, runner=subprocess.run):
    # The carrier is passed through devicectl's documented child environment,
    # never a shell interpolation, launch argument or printed test result.
    environment = dict(os.environ)
    environment["DEVICECTL_CHILD_LAYERGRAM_QA_INCOMING_CARRIER"] = validate_carrier(carrier)
    runner(["xcrun", "devicectl", "device", "process", "launch", "--device", device,
            "--terminate-existing", "app.layergram.keyboardprobe"],
           env=environment, check=True, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--disposable-device", choices=["YES"], required=True)
    args = parser.parse_args()
    carrier = validate_carrier(args.input.read_text())
    prepare(args.device, carrier)
    print("QA incoming prepared; code units=" + str(len(carrier.encode("utf-16-le")) // 2))
    print("This prepares the host only; it does not attest authentication or decoding.")


if __name__ == "__main__":
    main()
