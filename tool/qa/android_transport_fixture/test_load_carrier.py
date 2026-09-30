import shlex
import unittest
from unittest.mock import patch

from load_carrier import load_command, main


class LoadCarrierTests(unittest.TestCase):
    def test_adb_shell_keeps_all_carrier_lines_in_one_intent_extra(self):
        carrier = "p1.A_b-0\nm3.C_D-1\nm3.E_F-2"
        command = load_command("qa-device", carrier)
        shell_arguments = shlex.split(" ".join(command[4:]))
        self.assertEqual(shell_arguments[-2:], ["qa_carrier", carrier])

    def test_accepts_active_fs_combined_carrier(self):
        carrier = "b3.TDNCAQIABF9_"
        command = load_command("qa-device", carrier)
        self.assertEqual(shlex.split(command[-1]), [carrier])

    def test_refuses_plaintext_fractions_shell_input_and_oversized_carriers(self):
        for text in ["", "2/2", "m3.abc\nplain", "m3.abc;id", "m3." + "a" * 4000, "b3.", "b3.ABC\n2/2", "b3.ABC;id"]:
            with self.subTest(text=text[:20]), self.assertRaises(ValueError):
                load_command("qa-device", text)

    def test_refuses_device_options_and_shell_metacharacters(self):
        for serial in ["", "-s", "qa device", "qa;id", "qa\nother", "a" * 129]:
            with self.subTest(serial=serial), self.assertRaises(ValueError):
                load_command(serial, "m3.ABC")
        for serial in ["qa-device", "emulator-5554", "192.0.2.1:5555"]:
            self.assertEqual(load_command(serial, "m3.ABC")[:3],
                             ["adb", "-s", serial])

    def test_cli_cannot_select_an_executable(self):
        argv = ["load_carrier.py", "--adb", "/bin/sh", "--serial", "qa-device",
                "--input", "unused.carrier"]
        with patch("sys.argv", argv), patch("load_carrier.subprocess.run") as run:
            with self.assertRaises(SystemExit) as error:
                main()
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
