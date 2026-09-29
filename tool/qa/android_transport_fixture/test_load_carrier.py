import shlex
import unittest

from load_carrier import load_command


class LoadCarrierTests(unittest.TestCase):
    def test_adb_shell_keeps_all_carrier_lines_in_one_intent_extra(self):
        carrier = "p1.A_b-0\nm3.C_D-1\nm3.E_F-2"
        command = load_command("adb", "qa-device", carrier)
        shell_arguments = shlex.split(" ".join(command[4:]))
        self.assertEqual(shell_arguments[-2:], ["qa_carrier", carrier])

    def test_accepts_active_fs_combined_carrier(self):
        carrier = "b3.TDNCAQIABF9_"
        command = load_command("adb", "qa-device", carrier)
        self.assertEqual(shlex.split(command[-1]), [carrier])

    def test_refuses_plaintext_fractions_shell_input_and_oversized_carriers(self):
        for text in ["", "2/2", "m3.abc\nplain", "m3.abc;id", "m3." + "a" * 4000, "b3.", "b3.ABC\n2/2", "b3.ABC;id"]:
            with self.subTest(text=text[:20]), self.assertRaises(ValueError):
                load_command("adb", "qa-device", text)


if __name__ == "__main__":
    unittest.main()
