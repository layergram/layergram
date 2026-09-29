import json
from pathlib import Path
import tempfile
import unittest

from collect_carrier import collect


class CarrierCollectionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.attachment = {"suggestedHumanReadableName": "QA outgoing reply carrier_0_fixture.txt",
                           "exportedFileName": "ciphertext.txt", "isAssociatedWithFailure": False}

    def write(self, carrier="p1.ABC_def-123\nm3.ABC_def-456", attachments=None):
        (self.root / "ciphertext.txt").write_text(carrier)
        (self.root / "manifest.json").write_text(json.dumps([
            {"attachments": attachments if attachments is not None else [self.attachment]}]))

    def testRetainsAllAuthenticatedCarrierLines(self):
        carrier = "p1.ABC_def-123\nm3.ABC_def-456"
        self.write(carrier)
        self.assertEqual(collect(self.root, "QA outgoing reply carrier"), carrier)

    def test_collects_active_fs_combined_carrier(self):
        carrier = "b3.TDNCAQIABF9_"
        self.write(carrier)
        self.assertEqual(collect(self.root, "QA outgoing reply carrier"), carrier)

    def testRejectsMissingAmbiguousAndFailureAttachments(self):
        for attachments in ([], [self.attachment, self.attachment],
                            [{**self.attachment, "isAssociatedWithFailure": True}]):
            with self.subTest(attachments=attachments):
                self.write(attachments=attachments)
                with self.assertRaises(ValueError): collect(self.root, "QA outgoing reply carrier")

    def testRejectsFractionsPlaintextAndOversizedOrBrokenCarriers(self):
        for carrier in ("1/2\nm3.ABC", "clear text", "m3.", "m3.ABC\n2/9",
                        "m3." + "A" * 3998, "m3.ABC🙂", "b3.", "b3.ABC\n2/2", "b3.ABC;id"):
            with self.subTest(carrier_type=carrier[:4]):
                self.write(carrier)
                with self.assertRaises(ValueError): collect(self.root, "QA outgoing reply carrier")

    def testRejectsAttachmentPathEscape(self):
        self.write(attachments=[{**self.attachment, "exportedFileName": "../ciphertext.txt"}])
        with self.assertRaises(ValueError): collect(self.root, "QA outgoing reply carrier")


if __name__ == "__main__":
    unittest.main()
