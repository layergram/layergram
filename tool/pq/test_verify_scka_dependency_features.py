import copy
import unittest

from verify_scka_dependency_features import verify


def graph():
    versions = {"root": ("layergram-scka", "0.1.0"),
                "cipher": ("aes-gcm-siv", "0.11.1"),
                "aes-old": ("aes", "0.8.4"),
                "aes-new": ("aes", "0.9.1")}
    return {
        "packages": [{"id": key, "name": name, "version": version}
                     for key, (name, version) in versions.items()],
        "resolve": {"root": "root", "nodes": [
            {"id": "root", "features": ["candidate-ffi"],
             "dependencies": ["cipher", "aes-old", "aes-new"]},
            {"id": "cipher", "features": ["aes"], "dependencies": ["aes-old"]},
            {"id": "aes-old", "features": ["zeroize"], "dependencies": []},
            {"id": "aes-new", "features": ["zeroize"], "dependencies": []},
        ]},
    }


class DependencyFeatureTests(unittest.TestCase):
    def test_current_cipher_has_zeroize(self):
        self.assertEqual(verify(graph()), 1)

    def test_unrelated_new_aes_does_not_protect_the_cipher(self):
        metadata = graph()
        metadata["resolve"]["nodes"][2]["features"] = []
        with self.assertRaisesRegex(ValueError, "AES 0.8.4.*zeroize"):
            verify(metadata)

    def test_checker_follows_a_future_cipher_dependency(self):
        metadata = graph()
        metadata["resolve"]["nodes"][1]["dependencies"] = ["aes-new"]
        metadata["resolve"]["nodes"][2]["features"] = []
        self.assertEqual(verify(metadata), 1)

    def test_missing_aes_dependency_fails(self):
        metadata = graph()
        metadata["resolve"]["nodes"][1]["dependencies"] = []
        with self.assertRaisesRegex(ValueError, "one resolved AES"):
            verify(metadata)

    def test_missing_cipher_fails(self):
        metadata = graph()
        metadata["resolve"]["nodes"][0]["dependencies"] = ["aes-new"]
        with self.assertRaisesRegex(ValueError, "No resolved AES-GCM-SIV"):
            verify(metadata)

    def test_wrong_feature_configuration_fails(self):
        metadata = graph()
        metadata["resolve"]["nodes"][0]["features"] = []
        with self.assertRaisesRegex(ValueError, "candidate-ffi"):
            verify(metadata)

    def test_wrong_package_fails(self):
        metadata = graph()
        metadata["packages"][0]["name"] = "other-package"
        with self.assertRaisesRegex(ValueError, "layergram-scka"):
            verify(metadata)

    def test_each_reachable_cipher_is_checked(self):
        metadata = graph()
        cipher = copy.deepcopy(metadata["packages"][1])
        cipher.update(id="cipher-new", version="0.12.0")
        metadata["packages"].append(cipher)
        metadata["resolve"]["nodes"].append({"id": "cipher-new", "features": [],
                                            "dependencies": ["aes-new"]})
        metadata["resolve"]["nodes"][0]["dependencies"].append("cipher-new")
        self.assertEqual(verify(metadata), 2)
        metadata["resolve"]["nodes"][3]["features"] = []
        with self.assertRaisesRegex(ValueError, "AES 0.9.1.*zeroize"):
            verify(metadata)


if __name__ == "__main__":
    unittest.main()
