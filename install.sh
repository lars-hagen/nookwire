#!/bin/sh
set -eu

VERSION=${NOOKWIRE_SSH_VERSION:-1.6.0}
BASE_URL=${NOOKWIRE_SSH_BASE_URL:-https://raw.githubusercontent.com/lars-hagen/nookwire-ssh/v$VERSION}
PREFIX=${NOOKWIRE_SSH_PREFIX:-"$HOME/.local"}
BIN_DIR="$PREFIX/bin"
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/nookwire-ssh-install.XXXXXX")
HAD_LAUNCHER=0
HAD_SERVER=0
HAD_TUNNEL=0
INSTALL_STARTED=0
COMMITTED=0

restore() {
  if [ "$1" -eq 1 ]; then
    mv "$TEMP_DIR/backup/$2" "$BIN_DIR/$2"
  else
    rm -f "$BIN_DIR/$2"
  fi
}

cleanup() {
  status=$?
  trap - 0 HUP INT TERM
  if [ "$INSTALL_STARTED" -eq 1 ] && [ "$COMMITTED" -ne 1 ]; then
    restore "$HAD_LAUNCHER" nookwire-ssh
    restore "$HAD_SERVER" nookwire_ssh.py
    restore "$HAD_TUNNEL" nookwire_tunnel.py
  fi
  rm -rf "$TEMP_DIR"
  exit "$status"
}
trap cleanup 0 HUP INT TERM

command -v curl >/dev/null 2>&1 || {
  printf '%s\n' "nookwire-ssh: curl is required" >&2
  exit 1
}

if ! command -v uv >/dev/null 2>&1; then
  printf 'nookwire-ssh: uv not found; installing from https://astral.sh/uv\n'
  curl -LsSf https://astral.sh/uv/install.sh | sh
  for uv_bin in "${XDG_BIN_HOME:-}" "$HOME/.local/bin" "$HOME/.cargo/bin"; do
    [ -n "$uv_bin" ] && [ -x "$uv_bin/uv" ] || continue
    case ":$PATH:" in *":$uv_bin:"*) ;; *) PATH="$uv_bin:$PATH" ;; esac
  done
  command -v uv >/dev/null 2>&1 || {
    printf 'nookwire-ssh: uv install failed; install it manually and re-run\n' >&2
    exit 1
  }
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf 'nookwire-ssh: python3 not found; installing a managed Python via uv\n'
  if ! uv python install --preview-features python-install-default --default; then
    printf 'nookwire-ssh: python3 install failed; install it manually and re-run\n' >&2
    exit 1
  fi
  py_shim_dir=
  for py_bin in "${XDG_BIN_HOME:-}" "$HOME/.local/bin"; do
    [ -n "$py_bin" ] && [ -x "$py_bin/python3" ] || continue
    case ":$PATH:" in *":$py_bin:"*) ;; *) PATH="$py_bin:$PATH" ;; esac
    py_shim_dir="$py_bin"
  done
  command -v python3 >/dev/null 2>&1 || {
    printf 'nookwire-ssh: python3 install failed; install it manually and re-run\n' >&2
    exit 1
  }
  if [ -n "$py_shim_dir" ]; then
    printf 'nookwire-ssh: managed Python at %s; keep it on PATH for future sessions\n' "$py_shim_dir"
  fi
fi

curl -fsSL "$BASE_URL/nookwire-ssh" -o "$TEMP_DIR/nookwire-ssh"
curl -fsSL "$BASE_URL/nookwire_ssh.py" -o "$TEMP_DIR/nookwire_ssh.py"
curl -fsSL "$BASE_URL/nookwire_tunnel.py" -o "$TEMP_DIR/nookwire_tunnel.py"

mkdir -p "$BIN_DIR"
chmod 755 "$TEMP_DIR/nookwire-ssh"
chmod 644 "$TEMP_DIR/nookwire_ssh.py"
chmod 644 "$TEMP_DIR/nookwire_tunnel.py"
mkdir "$TEMP_DIR/backup"
for destination in "$BIN_DIR/nookwire-ssh" "$BIN_DIR/nookwire_ssh.py" "$BIN_DIR/nookwire_tunnel.py"; do
  if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then
    printf 'nookwire-ssh: refusing unsafe install destination: %s\n' "$destination" >&2
    exit 1
  fi
done
if [ -f "$BIN_DIR/nookwire-ssh" ]; then
  cp -p "$BIN_DIR/nookwire-ssh" "$TEMP_DIR/backup/nookwire-ssh"
  HAD_LAUNCHER=1
fi
if [ -f "$BIN_DIR/nookwire_ssh.py" ]; then
  cp -p "$BIN_DIR/nookwire_ssh.py" "$TEMP_DIR/backup/nookwire_ssh.py"
  HAD_SERVER=1
fi
if [ -f "$BIN_DIR/nookwire_tunnel.py" ]; then
  cp -p "$BIN_DIR/nookwire_tunnel.py" "$TEMP_DIR/backup/nookwire_tunnel.py"
  HAD_TUNNEL=1
fi
INSTALL_STARTED=1
mv "$TEMP_DIR/nookwire-ssh" "$BIN_DIR/nookwire-ssh"
mv "$TEMP_DIR/nookwire_ssh.py" "$BIN_DIR/nookwire_ssh.py"
mv "$TEMP_DIR/nookwire_tunnel.py" "$BIN_DIR/nookwire_tunnel.py"
COMMITTED=1

# Best-effort companion for the cloudflare backend; the srvus and cloudflared
# backends do not need it, so a missing file must not fail the install.
if [ ! -L "$BIN_DIR/nookwire_ws.py" ]; then
  if curl -fsSL "$BASE_URL/nookwire_ws.py" -o "$TEMP_DIR/nookwire_ws.py" 2>/dev/null; then
    chmod 644 "$TEMP_DIR/nookwire_ws.py"
    mv "$TEMP_DIR/nookwire_ws.py" "$BIN_DIR/nookwire_ws.py"
  fi
fi

printf 'Installed nookwire-ssh to %s\n' "$BIN_DIR/nookwire-ssh"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) printf 'Add %s to PATH: export PATH="%s:$PATH"\n' "$BIN_DIR" "$BIN_DIR" ;;
esac

# Any remaining arguments are handed to nookwire-ssh, so a single piped command
# can install and then run (curl ... | sh -s -- start . 8022 1).
if [ "$#" -gt 0 ]; then
  rm -rf "$TEMP_DIR"
  trap - 0 HUP INT TERM
  exec "$BIN_DIR/nookwire-ssh" "$@"
fi
