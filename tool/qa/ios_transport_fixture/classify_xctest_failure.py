"""Classify pre-touch UI authorization failure without retrying or granting access."""
import argparse
from pathlib import Path
import re


def is_ui_authorization_block(log: str) -> bool:
    initialization_failed = "test runner failed to initialize for ui testing" in log.lower()
    mode_timeout = "Timed out while enabling automation mode" in log
    test_started = re.search(r"^\s*(?:t\s*=\s*\d|Test Case .* started)", log, re.MULTILINE)
    return initialization_failed and mode_timeout and test_started is None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    if is_ui_authorization_block(args.log.read_text(errors="replace")):
        print("QA_UI_AUTOMATION=authorizationUnavailable;noTestActions;retryRequiresExternalChange")
        raise SystemExit(75)
    print("QA_XCTEST=failed;notCertifiedAsPreTouchAuthorizationBlock")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
