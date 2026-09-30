import shlex
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from load_carrier import load_command, main


class LoadCarrierTests(unittest.TestCase):
    def test_adb_shell_keeps_all_carrier_lines_in_one_intent_extra(self):
        carrier = "p1.A_b-0\nm3.C_D-1\nm3.E_F-2"
        command = load_command("qa-device", carrier)
        shell_arguments = shlex.split(" ".join(command[2:]))
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
            command = load_command(serial, "m3.ABC")
            self.assertEqual(command[:2], ["adb", "shell"])
            self.assertNotIn(serial, command)

    def test_selects_only_the_requested_device_through_adb_environment(self):
        argv = ["load_carrier.py", "--serial", "qa-device", "--input", "unused.carrier"]
        result = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch("sys.argv", argv), patch.object(Path, "read_text", return_value="m3.ABC"), \
                patch("load_carrier.subprocess.run", return_value=result) as run:
            main()
        self.assertEqual(run.call_args.kwargs["env"]["ANDROID_SERIAL"], "qa-device")
        self.assertEqual(run.call_args.args[0][:2], ["adb", "shell"])
        self.assertIsNone(run.call_args.kwargs["input"])

    def test_host_instrumentation_keeps_carrier_in_stdin_and_a_fixed_path(self):
        argv = ["load_carrier.py", "--serial", "qa-device", "--input", "unused.carrier",
                "--host-instrumentation"]
        carrier = "p1.ABC\nm3.DEF"
        result = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch("sys.argv", argv), patch.object(Path, "read_text", return_value=carrier), \
                patch("load_carrier.subprocess.run", return_value=result) as run:
            main()
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["adb", "shell", "run-as", "app.layergram.keyboardprobe"])
        self.assertIn("no_backup/qa-transport-incoming.carrier", command[-1])
        self.assertNotIn(carrier, command)
        self.assertEqual(run.call_args.kwargs["input"], carrier)
        self.assertEqual(run.call_args.kwargs["env"]["ANDROID_SERIAL"], "qa-device")

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
