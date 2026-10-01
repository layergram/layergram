import unittest

from verify_recording_recovery import verify, scope_to_xctest


def log(*events):
    return "\n".join(
        f"{'Runner' if process == 'Host' else 'LayergramKeyboard'}[123] <Info>: Layergram{process}Trace {code}"
        for process, code in events)


ACTIVE = ("Keyboard", "captureActiveRevocation")
STOP = ("Keyboard", "captureStoppedNoRevocation")
GRANT = ("Keyboard", "beginResponseGranted")
INITIAL = [("Keyboard", "runtimeReady"), GRANT]
RECOVERY = [("Host", "didBecomeActive"), ("Host", "service_runtimeProviderReady"),
            ("Host", "willResignActive"), ("Host", "windowOpened"),
            ("Host", "delegateReplyOk"), ("Keyboard", "runtimeReady"), GRANT]


class RecordingRecoveryTests(unittest.TestCase):
    def test_only_completed_test_interval_excludes_later_host_teardown(self):
        test_log = "Start Test at 2026-09-27 20:00:00.000\n" \
                   "Test Suite 'Selected tests' passed at 2026-09-27 20:00:20.000.\n" \
                   "** TEST EXECUTE SUCCEEDED **"
        valid = "Sep 27 20:00:05.000 " + log(*INITIAL, ACTIVE, STOP, *RECOVERY).replace(
            "\n", "\nSep 27 20:00:05.000 ")
        hidden = "\nSep 27 20:00:20.100 " + log(("Keyboard", "clearRuntime"))
        verify(scope_to_xctest(valid + hidden, test_log))
        with self.assertRaises(ValueError):
            verify(scope_to_xctest(valid + hidden.replace("20:00:20.100", "20:00:19.900"), test_log))
        for incomplete in ["", test_log.replace("passed", "failed"),
                           test_log.replace("** TEST EXECUTE SUCCEEDED **", "** TEST EXECUTE FAILED **"),
                           test_log + "\nStart Test at 2026-09-27 20:00:00.000"]:
            with self.assertRaises(ValueError):
                scope_to_xctest(valid, incomplete)

    def test_requires_actual_capture_and_fresh_app_handoff(self):
        verify(log(*INITIAL, ACTIVE, ACTIVE, STOP, *RECOVERY, STOP))

    def test_unadmitted_keyboard_cannot_attest_a_full_cycle(self):
        with self.assertRaises(ValueError):
            verify(log(ACTIVE, STOP, *RECOVERY))

    def test_simulated_uikit_host_logs_cannot_attest_physical_recording(self):
        simulated = log(ACTIVE, STOP).replace("LayergramKeyboard[123]", "Runner(RunnerTests)[123]")
        with self.assertRaises(ValueError):
            verify(simulated + "\n" + log(*RECOVERY))

    def test_missing_capture_or_stop_cannot_pass(self):
        for events in [(STOP, *RECOVERY), (ACTIVE, *RECOVERY), tuple(RECOVERY)]:
            with self.assertRaises(ValueError):
                verify(log(*events))

    def test_unlock_during_capture_is_a_failure(self):
        with self.assertRaises(ValueError):
            verify(log(*INITIAL, ACTIVE, GRANT, STOP, *RECOVERY))
        with self.assertRaises(ValueError):
            verify(log(*INITIAL, ACTIVE, GRANT, ACTIVE, STOP, *RECOVERY))
        with self.assertRaises(ValueError):
            verify(log(*INITIAL, ACTIVE, STOP, GRANT, *RECOVERY))

    def test_old_or_incomplete_grant_is_not_recovery(self):
        with self.assertRaises(ValueError):
            verify(log(*RECOVERY, ACTIVE, STOP))
        for omitted in range(len(RECOVERY)):
            with self.assertRaises(ValueError):
                verify(log(*INITIAL, ACTIVE, STOP, *(RECOVERY[:omitted] + RECOVERY[omitted + 1:])))

    def test_late_stop_revocation_or_restarted_capture_cannot_pass(self):
        with self.assertRaises(ValueError):
            verify(log(*INITIAL, ACTIVE, STOP, *RECOVERY, ("Keyboard", "clearRuntime")))
        with self.assertRaises(ValueError):
            verify(log(*INITIAL, ACTIVE, STOP, *RECOVERY[:3], ACTIVE, *RECOVERY[3:]))


if __name__ == "__main__":
    unittest.main()
