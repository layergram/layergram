# Copyright 2026 Layergram. Licensed under the Apache License, Version 2.0.
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ios_simulator_clipboard_bridge import main, run_xcrun


class SimulatorClipboardBridgeTests(unittest.TestCase):
    def test_invalid_target_cannot_reach_a_command_or_consume_input(self):
        for target in ["booted", "--help", "-d", "UUID;id", "", "a" * 128]:
            stdin = SimpleNamespace(buffer=SimpleNamespace(read=unittest.mock.Mock()))
            with self.subTest(target=target), patch("sys.argv", ["bridge.py", target]), \
                    patch("sys.stdin", stdin), patch("ios_simulator_clipboard_bridge.subprocess.run") as run:
                self.assertEqual(main(), 2)
                run.assert_not_called()
                stdin.buffer.read.assert_not_called()

    def test_target_is_canonicalized_for_every_simulator_operation(self):
        target = "00000000-ABCD-1234-5678-000000000000"
        canonical = target.lower()
        carrier = b"m3.ABC"
        stdin = SimpleNamespace(buffer=io.BytesIO(carrier))
        with tempfile.TemporaryDirectory() as temporary:
            container = Path(temporary) / "sandbox"
            container.mkdir()
            def fake_xcrun(*arguments):
                if arguments[-1] == "--show-sdk-path":
                    return "/sdk"
                if arguments[:2] == ("simctl", "get_app_container"):
                    return str(container)
                return ""
            with patch("sys.argv", ["bridge.py", target]), patch("sys.stdin", stdin), \
                    patch("ios_simulator_clipboard_bridge.platform.machine", return_value="arm64"), \
                    patch("ios_simulator_clipboard_bridge.run_xcrun", side_effect=fake_xcrun) as run, \
                    patch("ios_simulator_clipboard_bridge.subprocess.run",
                          return_value=SimpleNamespace(stdout=carrier)) as paste:
                self.assertEqual(main(), 0)
                self.assertEqual((container / "Documents" / "carrier.txt").read_bytes(), carrier)
            operations = [call.args for call in run.call_args_list if call.args[0] == "simctl"]
            self.assertEqual(len(operations), 3)
            for arguments in operations:
                self.assertIn(canonical, arguments)
                self.assertNotIn(target, arguments)
            self.assertEqual(paste.call_args.args[0], ("xcrun", "simctl", "pbpaste", canonical))

    def test_command_executable_is_fixed(self):
        with patch("ios_simulator_clipboard_bridge.subprocess.run",
                   return_value=SimpleNamespace(stdout="/sdk\n")) as run:
            self.assertEqual(run_xcrun("--sdk", "iphonesimulator", "--show-sdk-path"), "/sdk")
        self.assertEqual(run.call_args.args[0],
                         ["xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"])


if __name__ == "__main__":
    unittest.main()
