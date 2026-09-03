import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from nookwire_ssh import __version__

PROJECT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def install_env(self, prefix, uv_tool_dir, use_preferred_names=False):
        env = {
            **os.environ,
            "UV_TOOL_DIR": str(uv_tool_dir),
        }
        if use_preferred_names:
            env["NOOKWIRE_PACKAGE"] = "."
            env["NOOKWIRE_PREFIX"] = str(prefix)
        else:
            env["NOOKWIRE_SSH_PACKAGE"] = "."
            env["NOOKWIRE_SSH_PREFIX"] = str(prefix)
        return env

    def test_install_layout_from_local_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            prefix = temp / "prefix"
            uv_tool_dir = temp / "uvtools"
            env = self.install_env(prefix, uv_tool_dir, use_preferred_names=True)
            completed = subprocess.run(
                ["sh", "install.sh"],
                cwd=PROJECT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                completed.returncode, 0, completed.stdout + completed.stderr
            )

            # Both primary and compatibility launchers must be installed and executable
            primary = prefix / "bin" / "nookwire"
            compat = prefix / "bin" / "nookwire-ssh"

            for launcher in (primary, compat):
                self.assertTrue(launcher.is_file(), f"{launcher} should exist")
                mode = launcher.stat().st_mode
                self.assertTrue(mode & stat.S_IXUSR, f"{launcher} should be executable")

                help_run = subprocess.run(
                    [str(launcher), "--version"],
                    env=env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(help_run.returncode, 0, help_run.stderr)
                self.assertIn(__version__, help_run.stdout)

                config_run = subprocess.run(
                    [str(launcher), "ssh-config"],
                    env=env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(config_run.returncode, 0, config_run.stderr)
                self.assertIn("Host *.srv.us", config_run.stdout)

    def test_install_legacy_env_vars_supported(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            prefix = temp / "prefix"
            uv_tool_dir = temp / "uvtools"
            env = self.install_env(prefix, uv_tool_dir, use_preferred_names=False)
            completed = subprocess.run(
                ["sh", "install.sh"],
                cwd=PROJECT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                completed.returncode, 0, completed.stdout + completed.stderr
            )
            self.assertTrue((prefix / "bin" / "nookwire").is_file())
            self.assertTrue((prefix / "bin" / "nookwire-ssh").is_file())

    def test_install_refuses_unsafe_destination(self):
        for bad_name in ("nookwire", "nookwire-ssh"):
            with tempfile.TemporaryDirectory() as temp:
                temp = Path(temp)
                prefix = temp / "prefix"
                uv_tool_dir = temp / "uvtools"
                (prefix / "bin").mkdir(parents=True)
                (prefix / "bin" / bad_name).mkdir()  # a directory, not a file
                env = self.install_env(prefix, uv_tool_dir)
                completed = subprocess.run(
                    ["sh", "install.sh"],
                    cwd=PROJECT,
                    env=env,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("refusing unsafe install destination", completed.stderr)

    def test_install_rolls_back_on_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            prefix = temp / "prefix"
            uv_tool_dir = temp / "uvtools"
            bin_dir = prefix / "bin"
            bin_dir.mkdir(parents=True)
            primary = bin_dir / "nookwire"
            compat = bin_dir / "nookwire-ssh"
            primary.write_text("#!/bin/sh\necho do-not-touch-primary\n")
            primary.chmod(0o755)
            compat.write_text("#!/bin/sh\necho do-not-touch-compat\n")
            compat.chmod(0o755)

            env = {
                **self.install_env(prefix, uv_tool_dir),
                "NOOKWIRE_PACKAGE": "definitely-not-a-real-package-nookwire-xyz",
            }
            completed = subprocess.run(
                ["sh", "install.sh"],
                cwd=PROJECT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("install failed", completed.stderr)
            self.assertEqual(
                primary.read_text(), "#!/bin/sh\necho do-not-touch-primary\n"
            )
            self.assertEqual(
                compat.read_text(), "#!/bin/sh\necho do-not-touch-compat\n"
            )


if __name__ == "__main__":
    unittest.main()
