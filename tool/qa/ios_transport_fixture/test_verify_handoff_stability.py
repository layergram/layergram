import unittest

from verify_handoff_stability import verify


def sample():
    lines = []
    log = ["Start Test at 2026-09-27 20:00:00.000"]
    for cycle in range(1, 7):
        minute = cycle - 1
        for phase, second in [("started", 0), ("observed", 40), ("retired", 45)]:
            log.append(f"QA_HANDOFF_CYCLE={cycle};phase={phase};time=2026-09-27 20:{minute:02}:{second:02}.000")
        events = [(1, "Host", "didBecomeActive"), (3, "Host", "service_runtimeProviderReady"),
                  (8, "Host", "willResignActive"), (9, "Host", "windowOpened"),
                  (10, "Host", "delegateReplyOk"), (11, "Keyboard", "runtimeReady"),
                  (12, "Keyboard", "beginResponseGranted"), (42, "Keyboard", "authorization_hidden"),
                  (43, "Keyboard", "clearRuntime")]
        for second, role, event in events:
            process = "Runner" if role == "Host" else "LayergramKeyboard"
            lines.append(f"Sep 27 20:{minute:02}:{second:02}.000 {process}[123] <Info>: Layergram{role}Trace {event}")
    log.extend(["Test Suite 'Selected tests' passed at 2026-09-27 20:06:00.000.",
                "** TEST EXECUTE SUCCEEDED **"])
    return "\n".join(lines), "\n".join(log)


class HandoffStabilityTests(unittest.TestCase):
    def test_document_revocation_before_disappearance_requires_complete_retirement(self):
        trace, log = sample()
        trace = trace.replace("authorization_hidden", "authorization_document")
        for minute in range(6):
            marker = f"Sep 27 20:{minute:02}:43.000 LayergramKeyboard[123] <Info>: LayergramKeyboardTrace clearRuntime"
            trace = trace.replace(marker,
                f"Sep 27 20:{minute:02}:42.500 LayergramKeyboard[123] <Info>: LayergramKeyboardTrace runtimeClosed\n" +
                marker +
                f"\nSep 27 20:{minute:02}:43.500 LayergramKeyboard[123] <Info>: LayergramKeyboardTrace viewWillDisappear")
        verify(trace, log)
        for missing in ["authorization_document", "runtimeClosed", "clearRuntime", "viewWillDisappear"]:
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                verify(trace.replace(missing, "omitted", 1), log)
        with self.assertRaises(ValueError):
            reversed_callbacks = trace.replace("runtimeClosed", "SWAP", 1) \
                .replace("viewWillDisappear", "runtimeClosed", 1) \
                .replace("SWAP", "viewWillDisappear", 1)
            verify(reversed_callbacks, log)

    def test_adjacent_cycles_can_share_a_printed_millisecond(self):
        trace, log = sample()
        log = log.replace("phase=retired;time=2026-09-27 20:00:45.000",
                          "phase=retired;time=2026-09-27 20:01:00.000")
        verify(trace, log)
        with self.assertRaises(ValueError):
            verify(trace, log.replace("phase=started;time=2026-09-27 20:01:00.000",
                                      "phase=started;time=2026-09-27 20:00:59.999"))

    def test_requires_each_fresh_grant_and_hidden_revocation(self):
        trace, log = sample()
        verify(trace, log)
        for missing in ["windowOpened", "beginResponseGranted", "authorization_hidden", "clearRuntime"]:
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                verify(trace.replace(missing, "omitted", 1), log)

    def test_visible_revocation_and_hidden_readmission_fail(self):
        trace, log = sample()
        for extra in ["Sep 27 20:00:30.000 LayergramKeyboard[123] <Info>: LayergramKeyboardTrace clearRuntime",
                      "Sep 27 20:00:44.000 LayergramKeyboard[123] <Info>: LayergramKeyboardTrace beginResponseGranted"]:
            with self.assertRaises(ValueError):
                verify(trace + "\n" + extra, log)

    def test_missing_failed_ambiguous_or_short_observation_fail(self):
        trace, log = sample()
        for invalid in [log.replace("passed", "failed"),
                        log.replace("phase=observed", "phase=absent", 1),
                        log + "\nQA_HANDOFF_CYCLE=6;phase=retired;time=2026-09-27 20:06:00.000",
                        log.replace("20:00:40.000", "20:00:20.000")]:
            with self.assertRaises(ValueError):
                verify(trace, invalid)

    def test_old_events_and_synthetic_test_host_cannot_certify_cycles(self):
        trace, log = sample()
        for invalid in [trace.replace("20:05:", "19:05:"),
                        trace.replace("LayergramKeyboard[123]", "Runner(RunnerTests)[123]")]:
            with self.assertRaises(ValueError):
                verify(invalid, log)


if __name__ == "__main__":
    unittest.main()
