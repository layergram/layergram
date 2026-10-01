import unittest

from classify_xctest_failure import is_ui_authorization_block


BLOCK = "The test runner failed to initialize for UI testing. " \
        "(Underlying Error: Timed out while enabling automation mode.)"


class XCTestFailureClassificationTests(unittest.TestCase):
    def test_actual_pretouch_timeout_is_infrastructure(self):
        self.assertTrue(is_ui_authorization_block("Running tests...\n" + BLOCK))

    def test_layergram_or_other_infrastructure_failures_are_not_this_block(self):
        for log in ["beginResponseDenied", "testmanagerd socket missing",
                    "Timed out while enabling automation mode", "Test execute failed"]:
            self.assertFalse(is_ui_authorization_block(log))

    def test_any_test_action_prevents_pretouch_classification(self):
        for action in ["    t =     0.00s Start Test", "Test Case 'keyboard' started"]:
            self.assertFalse(is_ui_authorization_block(action + "\n" + BLOCK))


if __name__ == "__main__":
    unittest.main()
