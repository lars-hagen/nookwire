import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from nookwire_ssh.identity import current_username, ensure_username_environment
from nookwire_ssh.project_identity import (
    AUTO_IDENTITY_WARNING,
    PROJECT_DOMAIN,
    SEED_DOMAIN,
    detect_ci_project,
    detect_git_origin,
    detect_host_id,
    normalize_git_remote,
    resolve_identity,
)


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


class ProjectIdentityTests(unittest.TestCase):
    def test_remote_normalization(self):
        cases = [
            ("git@github.com:owner/repo.git", "github.com/owner/repo"),
            ("https://github.com/owner/repo", "github.com/owner/repo"),
            ("ssh://git@github.com/owner/repo.git", "github.com/owner/repo"),
            ("https://user:token@github.com/owner/repo.git", "github.com/owner/repo"),
            ("git@github.com:owner/repo", "github.com/owner/repo"),
            ("https://GITHUB.COM/owner/repo.git/", "github.com/owner/repo"),
            ("git@gitlab.com:group/subgroup/project.git", "gitlab.com/group/subgroup/project"),
            ("https://gitlab.com/group/subgroup/project", "gitlab.com/group/subgroup/project"),
            ("ssh://user@host.xz:22/path/to/repo.git/", "host.xz/path/to/repo"),
            ("", ""),
        ]
        for raw, expected in cases:
            self.assertEqual(normalize_git_remote(raw), expected, f"Failed for {raw}")

    def test_explicit_seed_backward_compatibility(self):
        seed = "my-secret-seed-value"
        legacy_expected = hashlib.sha256(b"nookwire-ssh/srv.us/v1\0" + seed.encode()).digest()

        # Legacy env var
        info_legacy = resolve_identity(env={"NOOKWIRE_SSH_IDENTITY_SEED": seed})
        self.assertEqual(info_legacy.mode, "seeded")
        self.assertEqual(info_legacy.source, "NOOKWIRE_SSH_IDENTITY_SEED")
        self.assertEqual(info_legacy.derived_bytes, legacy_expected)
        self.assertEqual(info_legacy.warning, None)

        # Preferred env var
        info_preferred = resolve_identity(env={"NOOKWIRE_IDENTITY_SEED": seed})
        self.assertEqual(info_preferred.mode, "seeded")
        self.assertEqual(info_preferred.source, "NOOKWIRE_IDENTITY_SEED")
        self.assertEqual(info_preferred.derived_bytes, legacy_expected)
        self.assertEqual(info_preferred.warning, None)

        # Byte-for-byte exact equality between legacy and preferred
        self.assertEqual(info_preferred.derived_bytes, info_legacy.derived_bytes)

        # Preferred takes precedence over legacy
        info_both = resolve_identity(
            env={
                "NOOKWIRE_IDENTITY_SEED": "preferred-seed",
                "NOOKWIRE_SSH_IDENTITY_SEED": "legacy-seed",
            }
        )
        self.assertEqual(info_both.source, "NOOKWIRE_IDENTITY_SEED")
        self.assertEqual(
            info_both.derived_bytes,
            hashlib.sha256(b"nookwire-ssh/srv.us/v1\0" + b"preferred-seed").digest(),
        )

    def test_selector_precedence(self):
        with tempfile.TemporaryDirectory() as temp:
            repo_root = Path(temp) / "repo"
            repo_root.mkdir()
            # Create a fake git repo with origin
            git_dir = repo_root / ".git"
            git_dir.mkdir()
            (git_dir / "config").write_text(
                '[remote "origin"]\n  url = https://github.com/my-org/my-repo.git\n'
            )

            # 1. Seed beats all
            env = {
                "NOOKWIRE_IDENTITY_SEED": "seed1",
                "NOOKWIRE_IDENTITY": "custom-project",
                "GITHUB_REPOSITORY": "org/ci-repo",
            }
            info = resolve_identity(root=repo_root, username="u1", env=env)
            self.assertEqual(info.mode, "seeded")
            self.assertEqual(info.source, "NOOKWIRE_IDENTITY_SEED")

            # 2. Explicit identity beats git and CI
            env.pop("NOOKWIRE_IDENTITY_SEED")
            info = resolve_identity(root=repo_root, username="u1", env=env)
            self.assertEqual(info.mode, "project")
            self.assertEqual(info.source, "env:NOOKWIRE_IDENTITY")
            expected_derived = hashlib.sha256(
                PROJECT_DOMAIN + b"u1@custom-project"
            ).digest()
            self.assertEqual(info.derived_bytes, expected_derived)

            # 3. Legacy explicit identity alias beats git and CI
            env.pop("NOOKWIRE_IDENTITY")
            env["NOOKWIRE_SSH_IDENTITY"] = "legacy-custom-project"
            info = resolve_identity(root=repo_root, username="u1", env=env)
            self.assertEqual(info.mode, "project")
            self.assertEqual(info.source, "env:NOOKWIRE_SSH_IDENTITY")
            self.assertEqual(
                info.derived_bytes,
                hashlib.sha256(PROJECT_DOMAIN + b"u1@legacy-custom-project").digest(),
            )

            # 4. Git origin beats CI env var
            env.pop("NOOKWIRE_SSH_IDENTITY")
            info = resolve_identity(root=repo_root, username="u1", env=env)
            self.assertEqual(info.mode, "project")
            self.assertEqual(info.source, "git:origin")
            self.assertEqual(
                info.derived_bytes,
                hashlib.sha256(PROJECT_DOMAIN + b"u1@github.com/my-org/my-repo").digest(),
            )

            # 5. CI env var when git origin is absent
            empty_root = Path(temp) / "empty"
            empty_root.mkdir()
            info = resolve_identity(root=empty_root, username="u1", env=env)
            self.assertEqual(info.mode, "project")
            self.assertEqual(info.source, "env:GITHUB_REPOSITORY")
            self.assertEqual(
                info.derived_bytes,
                hashlib.sha256(PROJECT_DOMAIN + b"u1@org/ci-repo").digest(),
            )

            # 6. Host-local when no git and no CI
            env.pop("GITHUB_REPOSITORY")
            with mock.patch(
                "nookwire_ssh.project_identity.detect_host_id",
                return_value=("host:node", "my-host"),
            ):
                info = resolve_identity(root=empty_root, username="u1", env=env)
                self.assertEqual(info.mode, "host")
                self.assertEqual(info.source, "host:node")
                expected_raw = f"u1@my-host:{empty_root.resolve()}"
                self.assertEqual(
                    info.derived_bytes,
                    hashlib.sha256(PROJECT_DOMAIN + expected_raw.encode()).digest(),
                )

            # 7. Random fallback when host detection returns None
            with mock.patch(
                "nookwire_ssh.project_identity.detect_host_id", return_value=None
            ):
                info = resolve_identity(root=empty_root, username="u1", env=env)
                self.assertEqual(info.mode, "random")
                self.assertEqual(info.source, "random")
                self.assertIsNone(info.derived_bytes)
                self.assertEqual(info.fingerprint, "")

    def test_deterministic_auto_identity_simulated_reboot(self):
        # Two distinct temporary runs simulating containers before and after a reboot
        with tempfile.TemporaryDirectory() as temp1, tempfile.TemporaryDirectory() as temp2:
            root1 = Path(temp1) / "work"
            root1.mkdir()
            (root1 / ".git").mkdir()
            (root1 / ".git" / "config").write_text(
                '[remote "origin"]\n  url = git@github.com:myorg/myapp.git\n'
            )

            root2 = Path(temp2) / "work"
            root2.mkdir()
            (root2 / ".git").mkdir()
            (root2 / ".git" / "config").write_text(
                '[remote "origin"]\n  url = https://github.com/myorg/myapp\n'
            )

            info1 = resolve_identity(root=root1, username="appuser", env={})
            info2 = resolve_identity(root=root2, username="appuser", env={})

            self.assertEqual(info1.mode, "project")
            self.assertEqual(info2.mode, "project")
            self.assertEqual(info1.fingerprint, info2.fingerprint)
            self.assertEqual(info1.derived_bytes, info2.derived_bytes)
            self.assertEqual(len(info1.derived_bytes), 32)

    def test_no_leakage(self):
        secret_seed = "super-secret-high-entropy-token-12345"
        info = resolve_identity(env={"NOOKWIRE_IDENTITY_SEED": secret_seed})
        self.assertEqual(info.mode, "seeded")
        self.assertNotIn(secret_seed, info.source)
        self.assertNotIn(secret_seed, info.fingerprint)
        self.assertNotIn(secret_seed, str(info))
        self.assertEqual(len(info.fingerprint), 12)

        raw_identity = "my-private-project-name"
        info2 = resolve_identity(
            env={"NOOKWIRE_IDENTITY": raw_identity}, username="alice"
        )
        self.assertNotIn(raw_identity, info2.fingerprint)
        self.assertNotIn("alice", info2.fingerprint)
        self.assertEqual(len(info2.fingerprint), 12)

    def test_streamlit_dual_container_identical_identity(self):
        """Prove the Streamlit selector from both observed containers is identical.

        Inputs were:
          repo: https://github.com/shadowdocks/blank-app
          root: /mount/src/blank-app
          user: appuser
        Volatile attributes (boot ID, pod name, IP, MAC address, inodes) differed,
        but identity selector and fingerprint must be strictly identical.
        """
        user = "appuser"
        root_path = Path("/mount/src/blank-app")

        # Container 1 environment with volatile values
        env_container1 = {
            "HOSTNAME": "blank-app-pod-7d4f9b8c6-x1z9k",
            "POD_NAME": "blank-app-pod-7d4f9b8c6-x1z9k",
            "CONTAINER_ID": "docker://6a1f8b2c4e...",
            "IP": "10.244.1.42",
            "MAC": "02:42:0a:f4:01:2a",
        }

        # Container 2 environment after restart with completely different volatile values
        env_container2 = {
            "HOSTNAME": "blank-app-pod-8e5a0c9d7-y2w8j",
            "POD_NAME": "blank-app-pod-8e5a0c9d7-y2w8j",
            "CONTAINER_ID": "docker://9f3e7a1b5d...",
            "IP": "10.244.2.89",
            "MAC": "02:42:0a:f4:02:5b",
        }

        with tempfile.TemporaryDirectory() as temp1, tempfile.TemporaryDirectory() as temp2:
            dir1 = Path(temp1) / "mount" / "src" / "blank-app"
            dir1.mkdir(parents=True)
            (dir1 / ".git").mkdir()
            (dir1 / ".git" / "config").write_text(
                '[remote "origin"]\n  url = https://github.com/shadowdocks/blank-app\n'
            )

            dir2 = Path(temp2) / "mount" / "src" / "blank-app"
            dir2.mkdir(parents=True)
            (dir2 / ".git").mkdir()
            (dir2 / ".git" / "config").write_text(
                '[remote "origin"]\n  url = git@github.com:shadowdocks/blank-app.git\n'
            )

            info1 = resolve_identity(root=dir1, username=user, env=env_container1)
            info2 = resolve_identity(root=dir2, username=user, env=env_container2)

            self.assertEqual(info1.mode, "project")
            self.assertEqual(info2.mode, "project")
            self.assertEqual(info1.source, "git:origin")
            self.assertEqual(info2.source, "git:origin")
            self.assertEqual(info1.fingerprint, info2.fingerprint)
            self.assertEqual(info1.derived_bytes, info2.derived_bytes)
            self.assertEqual(info1.warning, AUTO_IDENTITY_WARNING)
            self.assertEqual(info2.warning, AUTO_IDENTITY_WARNING)


if __name__ == "__main__":
    unittest.main()
