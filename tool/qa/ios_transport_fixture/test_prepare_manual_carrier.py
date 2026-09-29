import unittest
from unittest.mock import Mock

from prepare_manual_carrier import prepare


class ManualCarrierPreparationTests(unittest.TestCase):
    def test_launch_is_scoped_and_carrier_is_only_in_child_environment(self):
        runner = Mock()
        carrier = "p1.ABC_def-123\nm3.ABC_def-456\nb3.TDNCAQIABF9_"
        prepare("qa-device", carrier, runner)
        args, options = runner.call_args
        self.assertEqual(args[0], ["xcrun", "devicectl", "device", "process", "launch",
                                  "--device", "qa-device", "--terminate-existing",
                                  "app.layergram.keyboardprobe"])
        self.assertEqual(options["env"]["DEVICECTL_CHILD_LAYERGRAM_QA_INCOMING_CARRIER"], carrier)
        self.assertTrue(options["check"])
        self.assertNotIn(carrier, args[0])

    def test_invalid_carrier_cannot_restart_host_or_replace_incoming(self):
        for carrier in ["", "1/2\nm3.ABC", "m3.ABC\n2/2", "clear text", "b3.",
                        "m3." + "A" * 4000, "b3.ABC;extra"]:
            with self.subTest(prefix=carrier[:4]):
                runner = Mock()
                with self.assertRaises(ValueError):
                    prepare("qa-device", carrier, runner)
                runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
