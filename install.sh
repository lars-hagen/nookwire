#!/bin/sh
set -eu

# Install Nookwire SSH as a uv tool. Everything after this one shell artifact is
# Python in the src/nookwire_ssh package: there are no companion scripts to drop
# beside a launcher anymore, so the whole install is a single `uv tool install`.
#
# Env overrides:
#   NOOKWIRE_SSH_VERSION   pin a release tag (e.g. 1.6.0) instead of the default.
#   NOOKWIRE_SSH_BASE_URL  override the source (repo URL/path) for the package.
#   NOOKWIRE_SSH_PACKAGE   fully override the `uv tool install` package spec.
#   NOOKWIRE_SSH_PREFIX    install the console script into $PREFIX/bin.
#   UV_TOOL_DIR / UV_TOOL_BIN_DIR  standard uv tool isolation (honored).

VERSION=${NOOKWIRE_SSH_VERSION:-2.3.0}
PACKAGE=${NOOKWIRE_SSH_PACKAGE:-}
if [ -z "$PACKAGE" ]; then
  BASE=${NOOKWIRE_SSH_BASE_URL:-git+https://github.com/lars-hagen/nookwire-ssh}
  # A base that already names a ref (…/nookwire-ssh@main, as `upgrade` passes)
  # is used as-is. Appending the pinned version as well would build
  # …/nookwire-ssh@main@v2.1.2, which uv cannot parse.
  case "${BASE#*://}" in
    *@*)
      PACKAGE="$BASE"
      ;;
    *)
      REF=$VERSION
      case "$VERSION" in
        v*) ;;
        *) REF="v$VERSION" ;;
      esac
      PACKAGE="$BASE@$REF"
      ;;
  esac
fi
PREFIX=${NOOKWIRE_SSH_PREFIX:-"$HOME/.local"}
BIN_DIR="$PREFIX/bin"
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/nookwire-ssh-install.XXXXXX")

cleanup() {
  status=$?
  trap - 0 HUP INT TERM
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

# Reflect NOOKWIRE_SSH_PREFIX (and the temp tool dirs used by tests) into uv so
# the console script lands where the caller asked.
export UV_TOOL_BIN_DIR=${UV_TOOL_BIN_DIR:-"$BIN_DIR"}
export UV_TOOL_DIR=${UV_TOOL_DIR:-"$PREFIX/share/uv/tools"}
mkdir -p "$BIN_DIR"

# The destination of the console script must not be a directory.
# uv owns this path and installs a symlink into its tool
# environment, so a symlink or a regular file here is the normal state after a
# previous install and --force replaces it. Refusing those broke every upgrade.
# A directory is the one case worth catching, since uv cannot replace it and
# its error is far less clear than this one.
for destination in "$UV_TOOL_BIN_DIR/nookwire-ssh"; do
  if [ -d "$destination" ]; then
    printf 'nookwire-ssh: refusing unsafe install destination: %s\n' "$destination" >&2
    exit 1
  fi
done

# uv owns the atomicity of the tool environment: it builds into its own staging
# area and only swaps the console script in once the install succeeds, so a
# failure leaves any previous installation in place. Copying the console script
# aside here would not add a guarantee, since that script is only a shim into
# the tool environment uv would have already replaced.
if ! uv tool install --force "$PACKAGE"; then
  printf 'nookwire-ssh: install failed; the previous installation was left in place\n' >&2
  exit 1
fi

printf 'Installed nookwire-ssh to %s\n' "$UV_TOOL_BIN_DIR/nookwire-ssh"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) printf 'Add %s to PATH: export PATH="%s:$PATH"\n' "$BIN_DIR" "$BIN_DIR" ;;
esac

# Any remaining arguments are handed to nookwire-ssh, so a single piped command
# can install and then run (curl ... | sh -s -- start . 8022 1).
if [ "$#" -gt 0 ]; then
  rm -rf "$TEMP_DIR"
  trap - 0 HUP INT TERM
  exec "$UV_TOOL_BIN_DIR/nookwire-ssh" "$@"
fi
