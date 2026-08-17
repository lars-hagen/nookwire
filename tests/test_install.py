import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from nookwire_ssh import __version__

PROJECT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def install_env(self, prefix, uv_tool_dir):
        return {
            **os.environ,
            "NOOKWIRE_SSH_PACKAGE": ".",
            "NOOKWIRE_SSH_PREFIX": str(prefix),
            "UV_TOOL_DIR": str(uv_tool_dir),
        }

    def test_install_layout_from_local_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            prefix = temp / "prefix"
            uv_tool_dir = temp / "uvtools"
            env = self.install_env(prefix, uv_tool_dir)
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
            launcher = prefix / "bin" / "nookwire-ssh"
            self.assertTrue(launcher.is_file())
            mode = launcher.stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR)
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

    def test_install_refuses_unsafe_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            prefix = temp / "prefix"
            uv_tool_dir = temp / "uvtools"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "nookwire-ssh").mkdir()  # a directory, not a file
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
            launcher = bin_dir / "nookwire-ssh"
            launcher.write_text("#!/bin/sh\necho do-not-touch\n")
            launcher.chmod(0o755)

            env = {
                **self.install_env(prefix, uv_tool_dir),
                "NOOKWIRE_SSH_PACKAGE": "definitely-not-a-real-package-nookwire-xyz",
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
                launcher.read_text(), "#!/bin/sh\necho do-not-touch\n"
            )


if __name__ == "__main__":
    unittest.main()
