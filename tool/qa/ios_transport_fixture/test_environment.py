"""Prepare a physical UI run without exposing QA ciphertext on the command line."""
import os
from pathlib import Path
import plistlib
import sys

def main():
    output = Path(os.environ["LAYERGRAM_QA_TRANSPORT_OUTPUT"])
    products = output / "DerivedData/Build/Products"
    files = [p for p in products.glob("*.xctestrun") if p.name != "transport.xctestrun"]
    if len(files) != 1:
        raise SystemExit("Expected exactly one built transport test configuration")
    config = plistlib.loads(files[0].read_bytes())
    environment = {
        "LAYERGRAM_QA_ROOT_BUNDLE": "app.layergram.keyboardvalidation",
        "LAYERGRAM_QA_CONTACT_NAME": os.environ.get("LAYERGRAM_QA_CONTACT_NAME", "QA Android"),
    }
    if sys.argv[1] == "history":
        plaintext = os.environ.get("LAYERGRAM_QA_HISTORY_PLAINTEXT", "")
        if not plaintext:
            raise SystemExit("Specify a unique plaintext from a passed keyboard exchange")
        environment["LAYERGRAM_QA_HISTORY_PLAINTEXT"] = plaintext
    if os.environ.get("LAYERGRAM_QA_EXPECT_FS"):
        expected_fs = os.environ["LAYERGRAM_QA_EXPECT_FS"]
        if expected_fs not in ("active", "pending"):
            raise SystemExit("Expected FS must be active or pending")
        environment["LAYERGRAM_QA_EXPECT_FS"] = expected_fs
    if sys.argv[1] == "decode":
        if os.environ.get("LAYERGRAM_QA_START_AFTER_IDLE") == "YES":
            environment["LAYERGRAM_QA_START_AFTER_IDLE"] = "YES"
        carrier = Path(os.environ["LAYERGRAM_QA_INCOMING_FILE"]).read_text().strip()
        if len(carrier.encode("utf-16-le")) // 2 > 4000 or not carrier.startswith(("p1.", "m3.", "b3.")):
            raise SystemExit("Expected a complete, bounded QA V3 carrier")
        plaintext = os.environ["LAYERGRAM_QA_EXPECTED_PLAINTEXT"]
        if not plaintext:
            raise SystemExit("Specify the expected authenticated plaintext")
        environment.update(LAYERGRAM_QA_INCOMING_CARRIER=carrier,
                           LAYERGRAM_QA_EXPECTED_PLAINTEXT=plaintext)
        if os.environ.get("LAYERGRAM_QA_REPLY_TEXT"):
            environment["LAYERGRAM_QA_REPLY_TEXT"] = os.environ["LAYERGRAM_QA_REPLY_TEXT"]

    def configure(value):
        if isinstance(value, dict):
            if value.get("IsUITestBundle") is True:
                value.setdefault("EnvironmentVariables", {}).update(environment)
                value.setdefault("UITargetAppEnvironmentVariables", {}).update(environment)
                return 1
            return sum(configure(child) for child in value.values())
        if isinstance(value, list):
            return sum(configure(child) for child in value)
        return 0

    if configure(config) != 1:
        raise SystemExit("Expected exactly one UI transport test target")
    # __TESTROOT__ in the built configuration must continue to resolve here.
    (products / "transport.xctestrun").write_bytes(plistlib.dumps(config))


if __name__ == "__main__":
    main()
