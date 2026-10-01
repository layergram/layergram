import copy
import datetime
import unittest
from verify_ios_keyboard_signing import verify_profile


class DeviceSigningTests(unittest.TestCase):
    def setUp(self):
        self.identifier = "app.layergram.keyboardvalidation.keyboard"
        self.groups = {"group.app.layergram.keyboardvalidation.keyboard"}
        self.signed = {
            "application-identifier": "TESTTEAM." + self.identifier,
            "com.apple.developer.team-identifier": "TESTTEAM",
            "com.apple.security.application-groups": list(self.groups),
        }
        self.profile = {
            "Entitlements": copy.deepcopy(self.signed),
            "ExpirationDate": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),
            "ProvisionedDevices": ["test-device"],
        }

    def test_complete_profile_accepts_selected_device(self):
        verify_profile(self.profile, self.signed, self.identifier, self.groups, "test-device")

    def test_signed_group_without_profile_permission_is_rejected(self):
        self.profile["Entitlements"]["com.apple.security.application-groups"] = []
        with self.assertRaisesRegex(ValueError, "every App Group"):
            verify_profile(self.profile, self.signed, self.identifier, self.groups)

    def test_wrong_application_is_rejected(self):
        self.profile["Entitlements"]["application-identifier"] = "TESTTEAM.other.app"
        with self.assertRaisesRegex(ValueError, "signed application"):
            verify_profile(self.profile, self.signed, self.identifier, self.groups)

    def test_wrong_team_is_rejected(self):
        self.profile["Entitlements"]["com.apple.developer.team-identifier"] = "OTHERTEAM"
        with self.assertRaisesRegex(ValueError, "signed team"):
            verify_profile(self.profile, self.signed, self.identifier, self.groups)

    def test_expired_profile_is_rejected(self):
        self.profile["ExpirationDate"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        with self.assertRaisesRegex(ValueError, "expired"):
            verify_profile(self.profile, self.signed, self.identifier, self.groups)

    def test_unregistered_device_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "selected device"):
            verify_profile(self.profile, self.signed, self.identifier, self.groups, "other-device")

    def test_additional_signed_group_is_rejected(self):
        self.signed["com.apple.security.application-groups"].append("group.other")
        with self.assertRaisesRegex(ValueError, "requested groups"):
            verify_profile(self.profile, self.signed, self.identifier, self.groups)


if __name__ == "__main__":
    unittest.main()
