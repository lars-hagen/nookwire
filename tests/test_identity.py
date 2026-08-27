import os
import unittest
from unittest import mock

from nookwire_ssh.identity import current_username, ensure_username_environment


class IdentityTests(unittest.TestCase):
    @mock.patch("nookwire_ssh.identity.getpass.getuser", side_effect=KeyError)
    def test_falls_back_when_uid_has_no_passwd_entry(self, _getuser):
        self.assertEqual(current_username(), "nookwire")

    @mock.patch("nookwire_ssh.identity.getpass.getuser", return_value="alice")
    def test_uses_resolved_username(self, _getuser):
        self.assertEqual(current_username(), "alice")

    def test_populates_username_environment_for_libraries(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(ensure_username_environment("nookwire"), "nookwire")
            self.assertEqual(os.environ["USER"], "nookwire")
            self.assertEqual(os.environ["LOGNAME"], "nookwire")


if __name__ == "__main__":
    unittest.main()
