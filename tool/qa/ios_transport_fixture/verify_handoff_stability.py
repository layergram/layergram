"""Check six real protected keyboard handoff cycles and hidden-editor retirement.

This verifies native admission/lifecycle only, not plaintext, FS, biometry or
long-term memory stability. Require a single successful physical XCTest and
its complete device-scoped trace. Synthetic unit-host logs cannot pass.
"""
import argparse
from datetime import datetime
from pathlib import Path
import re

from verify_recording_recovery import scope_to_xctest


def verify(trace: str, test_log: str) -> None:
    trace = scope_to_xctest(trace, test_log)
    marks = re.findall(
        r"QA_HANDOFF_CYCLE=(\d+);phase=(started|observed|retired);time="
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)", test_log)
    expected = [(str(cycle), phase) for cycle in range(1, 7)
                for phase in ("started", "observed", "retired")]
    if [(cycle, phase) for cycle, phase, _ in marks] != expected:
        raise ValueError("Require exactly six complete observed handoff cycles")
    stamps = [datetime.fromisoformat(stamp) for _, _, stamp in marks]
    # Adjacent cycles can share the same printed millisecond when the next
    # starts immediately after retirement. Each cycle must still have distinct
    # ordered phases; observation intervals may never overlap or run backward.
    for cycle in range(6):
        start, observed, retired = stamps[cycle * 3:cycle * 3 + 3]
        if not start < observed < retired or (cycle and stamps[cycle * 3 - 1] > start):
            raise ValueError("Cycle phases must increase without overlapping")
    events = []
    for line in trace.splitlines():
        stamp = re.match(r"([A-Z][a-z]{2}\s+\d+ \d{2}:\d{2}:\d{2}\.\d+)", line)
        route = re.search(r"(?:^|\s)(Runner|LayergramKeyboard)\[\d+\] .*?"
                          r"Layergram(Host|Keyboard)Trace ([A-Za-z0-9_]+)", line)
        if stamp and route and (route[1], route[2]) in {
                ("Runner", "Host"), ("LayergramKeyboard", "Keyboard")}:
            instant = datetime.strptime(f"{stamps[0].year} {stamp[1]}", "%Y %b %d %H:%M:%S.%f")
            events.append((instant, (route[2], route[3])))
    required = [("Host", "didBecomeActive"), ("Host", "service_runtimeProviderReady"),
                ("Host", "willResignActive"), ("Host", "windowOpened"),
                ("Host", "delegateReplyOk"), ("Keyboard", "runtimeReady"),
                ("Keyboard", "beginResponseGranted")]
    terminal = {("Keyboard", "clearRuntime"), ("Keyboard", "captureActiveRevocation"),
                ("Keyboard", "expiredState")}
    for cycle in range(6):
        start, observed, retired = stamps[cycle * 3:cycle * 3 + 3]
        before = [(stamp, event) for stamp, event in events if start <= stamp <= observed]
        cursor = -1
        for wanted in required:
            found = next((i for i in range(cursor + 1, len(before)) if before[i][1] == wanted), None)
            if found is None:
                raise ValueError(f"Cycle {cycle + 1} missing fresh {wanted[1]}")
            cursor = found
        if (observed - before[cursor][0]).total_seconds() < 15:
            raise ValueError(f"Cycle {cycle + 1} lacks sustained admitted observation")
        if any(event in terminal for _, event in before[cursor + 1:]):
            raise ValueError(f"Cycle {cycle + 1} revoked during visible observation")
        after = [event for stamp, event in events if observed < stamp <= retired]
        if ("Keyboard", "authorization_hidden") in after:
            if ("Keyboard", "clearRuntime") not in after:
                raise ValueError(f"Cycle {cycle + 1} missing hidden-editor runtime clearing")
        else:
            # Resigning the host's field can revoke its document binding before
            # UIKit delivers viewWillDisappear. Require the COMPLETE physical
            # retirement sequence, not document denial or a canvas alone.
            position = -1
            for code in ("authorization_document", "runtimeClosed", "clearRuntime", "viewWillDisappear"):
                position = next((i for i in range(position + 1, len(after))
                                 if after[i] == ("Keyboard", code)), -1)
                if position < 0:
                    raise ValueError(f"Cycle {cycle + 1} missing hidden-editor revocation: {code}")
        if any(event in {("Keyboard", "runtimeReady"), ("Keyboard", "beginResponseGranted")} for event in after):
            raise ValueError(f"Cycle {cycle + 1} admitted while hidden")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--xctest-log", type=Path, required=True)
    args = parser.parse_args()
    verify(args.trace.read_text(), args.xctest_log.read_text())
    print("QA_HANDOFF_STABILITY=6;freshAdmissions;visibleObservation;hiddenRevocation")


if __name__ == "__main__":
    main()
