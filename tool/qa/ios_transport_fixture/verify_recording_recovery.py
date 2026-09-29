"""Verify admission ordering in a device-scoped, code-only recording trace.

This does not operate Control Center or attest pixels, plaintext, FS color or
biometry. Those observations are separate physical gates. A missing event is a
failure, never an inferred success from a protected/empty accessibility tree.
"""
import argparse
from datetime import datetime
from pathlib import Path
import re


def scope_to_xctest(trace: str, test_log: str) -> str:
    """Bound observation to the single passed test, excluding host teardown.

    XCTest may hide its host after reporting the test passed. The keyboard
    must revoke on that later hide, so it cannot certify a still-live editor.
    Never trim to a grant, nor accept an absent/failed test completion.
    """
    date = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+"
    starts = re.findall(r"Start Test at (" + date + r")", test_log)
    ends = re.findall(r"Test Suite 'Selected tests' passed at (" + date + r")", test_log)
    if len(starts) != 1 or len(ends) != 1 or "** TEST EXECUTE SUCCEEDED **" not in test_log:
        raise ValueError("A single complete passed XCTest is required to bound observation")
    start, end = (datetime.fromisoformat(value) for value in (starts[0], ends[0]))
    if end <= start:
        raise ValueError("Invalid XCTest observation interval")
    lines = []
    for line in trace.splitlines():
        stamp = re.match(r"([A-Z][a-z]{2}\s+\d+ \d{2}:\d{2}:\d{2}\.\d+)", line)
        if stamp:
            instant = datetime.strptime(f"{start.year} {stamp[1]}", "%Y %b %d %H:%M:%S.%f")
            if start <= instant <= end:
                lines.append(line)
    return "\n".join(lines)


def verify(trace: str) -> None:
    # UIKit unit tests also log simulated capture changes from their Runner
    # host. Accept only the real extension/root process routes; simulated
    # controller tests must never certify a physical recording cycle.
    events = []
    for line in trace.splitlines():
        match = re.search(
            r"(?:^|\s)(Runner|LayergramKeyboard)\[\d+\] .*?"
            r"Layergram(Host|Keyboard)Trace ([A-Za-z0-9_]+)", line)
        if match and (match[1], match[2]) in {("Runner", "Host"), ("LayergramKeyboard", "Keyboard")}:
            events.append((match[2], match[3]))
    active = ("Keyboard", "captureActiveRevocation")
    stopped = ("Keyboard", "captureStoppedNoRevocation")
    starts = [i for i, event in enumerate(events) if event == active]
    if not starts:
        raise ValueError("Missing observed active-capture revocation")
    start = starts[0]
    if ("Keyboard", "runtimeReady") not in events[:start] or \
            ("Keyboard", "beginResponseGranted") not in events[:start]:
        raise ValueError("Recording did not start from an observed admitted keyboard")
    stop = next((i for i in range(start + 1, len(events)) if events[i] == stopped), None)
    if stop is None:
        raise ValueError("Missing observed end of capture")
    grants = {("Keyboard", "runtimeReady"), ("Keyboard", "beginResponseGranted"),
              ("Host", "delegateReplyOk")}
    if any(event in grants for event in events[start + 1:stop]):
        raise ValueError("Admission observed while capture remained active")
    root_return = next((i for i in range(stop + 1, len(events))
                        if events[i] == ("Host", "didBecomeActive")), len(events))
    if any(event in grants for event in events[stop + 1:root_return]):
        raise ValueError("Stopping capture admitted a session before a fresh app return")
    cursor = stop
    required = [("Host", "didBecomeActive"), ("Host", "service_runtimeProviderReady"),
                ("Host", "willResignActive"), ("Host", "windowOpened"),
                ("Host", "delegateReplyOk"), ("Keyboard", "runtimeReady"),
                ("Keyboard", "beginResponseGranted")]
    for expected in required:
        found = next((i for i in range(cursor + 1, len(events)) if events[i] == expected), None)
        if found is None:
            raise ValueError(f"Missing fresh post-capture event: {expected[1]}")
        if active in events[cursor + 1:found]:
            raise ValueError("Capture restarted during recovery")
        cursor = found
    # A delayed stop event must not invalidate the newly admitted session.
    terminal = {("Keyboard", "clearRuntime"), ("Keyboard", "biometricTicketRevokedOnInvalidation")}
    if any(event in terminal or event == active for event in events[cursor + 1:]):
        raise ValueError("Fresh post-capture session was revoked before observation ended")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--xctest-log", type=Path,
                        help="Use the single passed XCTest's actual start/end observation interval")
    args = parser.parse_args()
    trace = args.trace.read_text()
    if args.xctest_log:
        trace = scope_to_xctest(trace, args.xctest_log.read_text())
    verify(trace)
    print("QA_RECORDING_RECOVERY=freshAppAdmission;captureBlocked;scope=admissionSequence")


if __name__ == "__main__":
    main()
