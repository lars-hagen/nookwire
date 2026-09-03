# Nookwire

Nookwire gives an agent or human temporary SSH command, SFTP, and SCP access to an ephemeral workspace. It uses [AsyncSSH](https://github.com/ronf/asyncssh) for the server and a pluggable public ingress: [srv.us](https://docs.srv.us/) by default, [Upterm](https://upterm.dev/) over WSS, a Cloudflare Worker relay, or Cloudflare Tunnel (`cloudflared`).

The server binds to localhost, authenticates as the host's own OS user with standard `~/.ssh/authorized_keys` or a generated password fallback, maps SFTP and SCP paths into a configured root, and starts shell commands in that root. Interactive clients get a real login PTY with job control, window resizing, and the account's normal shell and prompt. The srv.us and Cloudflare backends carry opaque SSH bytes end to end. Upterm terminates and re-establishes SSH at its relay, so it uses public keys or `--accept`, not Nookwire passwords, and requires trusting the selected Upterm relay. The printed commands disable host-key persistence for these disposable environments.

Use Nookwire only on systems and workspaces you own or are explicitly authorized to administer. It provides authenticated access with the permissions of the host OS account and is not an OS-level sandbox. Public-key authentication is the recommended default. See [Security model](#security-model) and [SECURITY.md](SECURITY.md) before exposing a workspace.

## Prerequisites

The remote machine needs Python 3 and uv, and nothing else for the `srvus` or `upterm` backends. The `cloudflare` backend needs a deployed Worker; the `cloudflared` backend needs the `cloudflared` binary. A connecting machine's requirements depend on the backend (see [Backends](#backends)): `srvus` needs OpenSSH and OpenSSL; `upterm` and `cloudflare` need OpenSSH and Nookwire installed for their WSS ProxyCommand; `cloudflared` needs OpenSSH and `cloudflared`.

## Install

### Post-publication (PyPI)

Once published to PyPI, install using `uv tool install`:

```sh
uv tool install nookwire
```

Both `nookwire` (primary) and `nookwire-ssh` (legacy alias) console scripts are installed.

### Git installer

Until PyPI publication, or to run directly from the GitHub repository:

```sh
curl -fsSL https://raw.githubusercontent.com/lars-hagen/nookwire/main/install.sh | sh
```

Run it on the remote machine you want to expose. It installs `nookwire` as a [uv tool](https://docs.astral.sh/uv/reference/cli/#uv-tool) from the Git repository, dropping both `nookwire` and `nookwire-ssh` console scripts into `~/.local/bin`; add that directory to `PATH` if needed. If `uv` is missing, the installer fetches it from `https://astral.sh/uv` first; if `python3` is missing, it provisions a managed Python through uv.

Once installed, `nookwire upgrade` re-runs the installer in place (`nookwire upgrade REF` pins a branch or tag; default `main`). Background processes are launched as `sys.executable -m nookwire_ssh.server` / `nookwire_ssh.tunnel`, so uv is never needed at runtime. Restart a running server with `nookwire restart` to pick up new code.

Any arguments after `--` are passed to `nookwire`, so a single command can install and start in one go. Exposing the current directory:

```sh
curl -fsSL https://raw.githubusercontent.com/lars-hagen/nookwire/main/install.sh \
  | sh -s -- start
```

Or with an explicit directory, port, and srv.us slot:

```sh
curl -fsSL https://raw.githubusercontent.com/lars-hagen/nookwire/main/install.sh \
  | sh -s -- start . 8022 1
```

### Compatibility

Nookwire preserves full backward compatibility:
- The command `nookwire-ssh` is installed as a compatibility symlink/alias invoking `nookwire`.
- The internal Python package remains `nookwire_ssh`.
- Runtime state remains at `~/.local/state/nookwire-ssh` (or `$NOOKWIRE_STATE_DIR` / `$NOOKWIRE_SSH_STATE_DIR`).
- Legacy environment variables (`NOOKWIRE_SSH_*`) are supported everywhere alongside preferred `NOOKWIRE_*` variables.

## Start

Start AsyncSSH and the tunnel together in the background. The default backend is srv.us; see [Backends](#backends) for the Cloudflare options.

```sh
nookwire start
```

`DIR` defaults to the current directory and accepts relative paths, so `start` alone exposes the directory you are in. Pass a path to expose somewhere else, and set the port or srv.us slot with flags or positionally:

```sh
nookwire start /marimo
nookwire start . --port 8022 --slot 1
nookwire start /marimo 8022 1
```

The command prints the generated password, srv.us URL, and a ready-to-run TLS-wrapped SSH command. It returns to the shell while both services keep running. `status` prints the same connection details later.

Repeated `start` is idempotent when both the server and tunnel are already running: it returns success and displays the current status rather than failing. This handles ASGI hot reloads cleanly. If only one process is running, `start` reports an error to prevent inconsistent partial state.

### Noninteractive and batch mode: `--batch`

In automated scripts, CI pipelines, or background container entrypoints, use `--batch` or `NOOKWIRE_BATCH=1`:

```sh
nookwire start --batch
```

Nookwire batch mode never opens `/dev/tty` or prompts for an authorized key. It uses the existing generated password path unless `--accept` or key-only backend rules apply.

**Important distinction**: Nookwire `--batch` controls host-side interactive prompts and TTY access. It is distinct from OpenSSH client `BatchMode` (`-o BatchMode=yes`), which disables password and passphrase querying on the connecting client machine.

### Wide-open share mode: `--accept`

`--accept` skips authentication entirely: any connecting client is admitted without a key or password, no random password is generated or stored, and the `start`/`status` output replaces the credentials with an explicit warning. Combine it with the *tcp forwarding* flag below for an instant share:

```sh
nookwire start --accept
```

Only use `--accept` in scenarios where wide-open access is intended (for example a short-lived throwaway workspace). Do not expose it publicly on a system you do not own.

### TCP forwarding: `--allow-tcp-forwarding`

By default, a connected client cannot tunnel through the session. With `--allow-tcp-forwarding`, clients can use SSH local forwarding (`ssh -L`) to reach TCP destinations visible to the host, mirroring upterm's `--allow-local-tcp-forwarding`:

```sh
nookwire start --allow-tcp-forwarding
# on the connecting machine:
ssh -L 8080:db.internal:5432 USER@HOST ... # reaches db.internal:5432 from the host's network
```

The AsyncSSH server enables `direct-tcpip` channels only when this flag is set; otherwise such requests are refused.

### Inspecting and stopping

```sh
nookwire status
nookwire connect
nookwire logs
nookwire logs tunnel -f
nookwire stop
nookwire restart
```

A successful start saves its settings in the state directory. Any options omitted on a later `start` fall back to the saved values. `--accept` and `--allow-tcp-forwarding` are never restored automatically; safety flags must be provided explicitly every time.

## Deterministic Project Identity

srv.us derives the assigned public endpoint from the client's tunnel key and slot number. When running in ephemeral containers where the filesystem is reset on reboot, Nookwire automatically establishes a deterministic project identity.

### Identity Hierarchy

When `~/.ssh/id_ed25519` does not exist, Nookwire determines tunnel identity using this strict hierarchy:

1. **Explicit secret seed** (`NOOKWIRE_IDENTITY_SEED`, alias `NOOKWIRE_SSH_IDENTITY_SEED`):
   Deterministic derivation using `sha256(b"nookwire-ssh/srv.us/v1\0" + seed)`. Keeps byte-for-byte backward compatibility with existing seeds.
2. **Explicit non-secret identity** (`NOOKWIRE_IDENTITY`, alias `NOOKWIRE_SSH_IDENTITY`):
   Derives identity from `${username}@${NOOKWIRE_IDENTITY}`.
3. **Normalized Git origin**:
   Detects the Git remote origin of the configured root directory and normalizes equivalent SSH and HTTPS remotes (e.g. `git@github.com:owner/repo.git` and `https://github.com/owner/repo`) to `github.com/owner/repo`. Combined as `${username}@${normalized_origin}`.
4. **CI/PaaS project variable**:
   Inspects a strict allowlist of project identifiers: `GITHUB_REPOSITORY`, `CI_PROJECT_PATH`, `BITBUCKET_REPO_FULL_NAME`, `CIRCLE_PROJECT_REPONAME`, `RENDER_SERVICE_NAME`, `RAILWAY_PROJECT_NAME`, `VERCEL_GIT_REPO_SLUG`. Combined as `${username}@${project_id}`.
5. **Host-local identity**:
   Derived from `${username}@${host_id}:${resolved_root}` using `/etc/machine-id`, Windows `MachineGuid`, or `platform.node()`.
6. **Secure random fallback**:
   Generates a cryptographically secure random key if no stable selector can be formed. Volatile attributes (container/pod IDs, MAC addresses, IPs, inodes, Git commit SHAs) are never used.

### Security and Endpoint Continuity

Automatic identity is **explicitly non-secret** and provides **endpoint continuity**, not ownership secrecy. Anyone with knowledge of the repository URL or project name in the same environment can derive the same tunnel identity. To prevent collision or unauthorized endpoint reuse, operators requiring exclusive ownership must provide a secret `NOOKWIRE_IDENTITY_SEED`.

The srv.us slot acts as routing input, allowing one persistent tunnel key across multiple slots.

### Identity Command

Inspect identity details:

```sh
nookwire identity
nookwire identity --json
```

Outputs mode (`seeded`, `project`, `host`, `random`), source, selector fingerprint, and key path/fingerprint without exposing secret seeds or raw selectors.

## Automation and JSON Output

Nookwire provides machine-readable outputs for agent and CI integration:

### Machine-readable status

```sh
nookwire status --json
```

Emits stable JSON to stdout without ANSI codes:
```json
{
  "version": "2.3.1",
  "backend": "srvus",
  "server_state": "running",
  "server_pid": 12345,
  "tunnel_state": "running",
  "tunnel_pid": 12346,
  "url": "https://a1b2c3d4.srv.us/",
  "host": "a1b2c3d4.srv.us",
  "ssh_username": "appuser",
  "auth_mode": "password",
  "forwarding": false,
  "identity_mode": "project",
  "identity_source": "git:origin",
  "identity_fingerprint": "8d3e91a0c4f2",
  "connect_command": "ssh appuser@a1b2c3d4.srv.us -o 'ProxyCommand=...' ..."
}
```

### Batch connect command

```sh
SSH_CMD=$(nookwire connect --batch)
eval "$SSH_CMD" uptime
```

`connect --batch` prints exactly one self-contained SSH command line with `-T -o BatchMode=yes` and required proxy options, with no prose or trailing commentary. `connect --json` is also available.

## Backends

`start --backend` selects the public ingress. The AsyncSSH server is identical across all backends; only the tunnel process and the printed connect command change. `status` reports the right command for whichever backend is running.

### srvus (default)

Reverse tunnel over srv.us. Zero account, zero domain; the connecting machine needs only OpenSSH and OpenSSL. See [Connect through TLS](#connect-through-tls).

```sh
nookwire start --backend srvus --slot 1
```

### cloudflare (Worker relay)

Relays SSH over WebSockets via a Cloudflare Worker and Durable Object. Deploy the Worker in [`worker/`](worker/README.md):

```sh
cd worker && npx wrangler deploy
```

Then start with the deployed URL as `--endpoint`:

```sh
nookwire start --backend cloudflare \
  --endpoint https://nookwire.<subdomain>.workers.dev
```

### upterm (public WSS relay)

Uses Upterm's public relay over outbound WSS on port 443 and keeps Nookwire's local AsyncSSH server, PTY, SFTP/SCP confinement, and forwarding policy:

```sh
nookwire start --backend upterm
```

The backend requires at least one key in `~/.ssh/authorized_keys`, unless `--accept` is explicitly supplied.

### cloudflared (Cloudflare Tunnel)

Uses `cloudflared` with a named tunnel:

```sh
nookwire start --backend cloudflared \
  --hostname ssh.example.com --token "$CF_TUNNEL_TOKEN"
```

## Shorten the connect command

Add the proxy command to `~/.ssh/config` once on the connecting machine:

```sh
nookwire ssh-config --write
```

Afterwards:

```sh
ssh USER@HOSTNAME.srv.us
sftp USER@HOSTNAME.srv.us
scp -O notebook.py USER@HOSTNAME.srv.us:/notebook.py
```

## Connect through TLS

The `srvus` backend wraps non-HTTP traffic in TLS. `start` and `status` print the ready-to-use SSH form:

```sh
ssh USER@HOSTNAME.srv.us \
  -o 'ProxyCommand=openssl s_client -quiet -verify_return_error -verify_hostname %h -connect %h:443 -servername %h 2>/dev/null' \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
```

## Security model

- Public-key authentication is recommended and automatically uses `~/.ssh/authorized_keys`; password authentication remains available as a temporary fallback and uses constant-time comparison.
- `--accept` disables both, admitting any client without credentials. Only use it where open access is intended.
- TCP port forwarding is disabled by default; `--allow-tcp-forwarding` enables `ssh -L` through the session.
- The generated password is removed from command environments.
- SFTP and SCP are mapped into the configured root. Paths resolving through a symlink outside that root are rejected.
- Command sessions start in the root but are not OS-chrooted. Authenticated users can access anything allowed to the server's operating-system account.
- The server generates and reuses an Ed25519 host key in a private per-user directory.
- The connection examples disable host-key persistence because this targets short-lived disposable environments.
- Automatic project identity is non-secret and provides endpoint continuity, not ownership secrecy. Use `NOOKWIRE_IDENTITY_SEED` for exclusive endpoint control.

## Release and Publishing

Release publication is automated via GitHub Actions using PyPI Trusted Publishing (`.github/workflows/publish.yml`).

The workflow triggers on GitHub Release `published`, builds the sdist and wheel distributions, verifies installation of both `nookwire` and `nookwire-ssh` console scripts, and publishes to PyPI using least-privilege OIDC tokens (`contents: read`, `id-token: write`).

To configure the PyPI pending publisher:
- **PyPI project name**: `nookwire`
- **Owner**: `lars-hagen`
- **Repository name**: `nookwire`
- **Workflow name**: `publish.yml`
- **Environment name**: `pypi`

## Development

```sh
uv sync
uv run python -W error::ResourceWarning -m unittest discover -s tests -v
uv run python -m py_compile src/nookwire_ssh/*.py tests/*.py
sh -n install.sh
```
