"""Load only a complete QA carrier into the offline Android host."""
import argparse
from pathlib import Path
import re
import shlex
import subprocess


def load_command(adb: str, serial: str, carrier: str) -> list[str]:
    if not serial or not carrier or len(carrier.encode("utf-16-le")) // 2 > 4000:
        raise ValueError("Select a device and a bounded complete carrier")
    if any(not re.fullmatch(r"(?:p1|m3|b3)\.[A-Za-z0-9_-]+", line)
           for line in carrier.splitlines()):
        raise ValueError("Expected complete canonical V3 text lines")
    # adb joins shell arguments. Quoting here preserves literal newlines in
    # one intent extra; passing a Python argument list alone does not do this.
    return [adb, "-s", serial, "shell", "am", "start", "-n",
            "app.layergram.keyboardprobe/.TransportActivity", "--es",
            "qa_carrier", shlex.quote(carrier)]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--host-instrumentation", action="store_true",
                        help="Prepare the offline host's fixed input file without opening UI")
    args = parser.parse_args()
    carrier = args.input.read_text().strip()
    command = load_command(args.adb, args.serial, carrier)
    input_text = None
    if args.host_instrumentation:
        command = [args.adb, "-s", args.serial, "shell", "run-as",
                   "app.layergram.keyboardprobe", "sh", "-c",
                   shlex.quote("umask 077 && mkdir -p no_backup && "
                               "cat > no_backup/qa-transport-incoming.carrier")]
        input_text = carrier
    result = subprocess.run(command, input=input_text, capture_output=True, text=True)
    if result.returncode or "Error" in result.stdout + result.stderr:
        # am's diagnostic can contain ciphertext. Do not print it.
        raise SystemExit("Could not load the QA carrier into the offline host")
    print(f"Loaded QA carrier; code units={len(carrier.encode('utf-16-le')) // 2}")


if __name__ == "__main__":
    main()
