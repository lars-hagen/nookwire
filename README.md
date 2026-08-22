# Nookwire SSH

Nookwire SSH gives an agent or human temporary SSH command, SFTP, and SCP access to an ephemeral workspace. It uses [AsyncSSH](https://github.com/ronf/asyncssh) for the server and a pluggable public ingress: [srv.us](https://docs.srv.us/) by default, or a Cloudflare Worker relay, or Cloudflare Tunnel (`cloudflared`).

The server binds to localhost, authenticates as the host's own OS user with standard `~/.ssh/authorized_keys` or a generated password fallback, maps SFTP and SCP paths into a configured root, and starts shell commands in that root. Interactive clients get a real login PTY with job control, window resizing, and the account's normal shell and prompt. Every backend only carries bytes and never terminates SSH, so SSH's own encryption and authentication run between client and server. As with srv.us, the printed connect commands disable host-key persistence for these disposable environments, so trust in the ingress matches the existing model; do not treat any backend as protection against a hostile relay.

Use Nookwire only on systems and workspaces you own or are explicitly authorized to administer. It provides authenticated access with the permissions of the host OS account and is not an OS-level sandbox. Public-key authentication is the recommended default. See [Security model](#security-model) and [SECURITY.md](SECURITY.md) before exposing a workspace.

## Prerequisites

The remote machine needs Python 3 and uv, and nothing else for the default `srvus` backend: the tunnel speaks SSH through AsyncSSH, which the server already requires, so no OpenSSH client or `ssh-keygen` has to be installed. The `cloudflare` backend needs a deployed Worker; the `cloudflared` backend needs the `cloudflared` binary. A connecting machine's requirements depend on the backend (see [Backends](#backends)): `srvus` needs OpenSSH and OpenSSL with `s_client -verify_return_error` and `-verify_hostname` support; `cloudflare` needs OpenSSH, uv, and Nookwire SSH installed (its `proxy` subcommand is the ProxyCommand); `cloudflared` needs OpenSSH and `cloudflared`.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/lars-hagen/nookwire-ssh/main/install.sh | sh
```

Run it on the remote machine you want to expose. It installs `nookwire-ssh` as a [uv tool](https://docs.astral.sh/uv/reference/cli/#uv-tool) from the `v1.6.0` git tag, dropping the `nookwire-ssh` console script into `~/.local/bin`; add that directory to `PATH` if needed. The whole project, including the AsyncSSH server and the srv.us tunnel, is the `nookwire_ssh` Python package, so there are no companion scripts to keep in sync. If `uv` is missing, the installer fetches it from `https://astral.sh/uv` first; if `python3` is missing, it provisions a managed Python through uv. It refuses an unsafe destination (a symlink or directory where the console script belongs) and leaves any previous install in place when the new one fails.

Once installed, `nookwire-ssh upgrade` re-runs the installer in place (`nookwire-ssh upgrade REF` pins a branch or tag; default `main`). Background processes are launched as `sys.executable -m nookwire_ssh.server` / `nookwire_ssh.tunnel`, so uv is never needed at runtime. Restart a running server with `stop` then `start` to pick up new code.

### Releasing

`pyproject.toml` is the single source of truth for the version; the CLI reads it via `importlib.metadata`. `scripts/bump_version.py` updates it and regenerates the uv lockfile:

```sh
uv run scripts/bump_version.py 1.5.0
git add -A && git commit -m "chore: bump version to 1.5.0"
git tag v1.5.0 && git push origin main --tags
```

The tag matters: `install.sh` installs the package from the `v$VERSION` git tag.

Any arguments after `--` are passed to `nookwire-ssh`, so a single command can install and start in one go. Exposing the current directory:

```sh
curl -fsSL https://raw.githubusercontent.com/lars-hagen/nookwire-ssh/main/install.sh \
  | sh -s -- start
```

Or with an explicit directory, port, and srv.us slot:

```sh
curl -fsSL https://raw.githubusercontent.com/lars-hagen/nookwire-ssh/main/install.sh \
  | sh -s -- start . 8022 1
```

Nookwire automatically reads the conventional `~/.ssh/authorized_keys` file. Add the connecting machine's public key there to avoid password prompts:

```sh
mkdir -p ~/.ssh && chmod 700 ~/.ssh
printf '%s\n' 'ssh-ed25519 AAAA... client-name' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

The file is checked on each authentication attempt, so adding a key does not require restarting Nookwire.

When `start` runs interactively and `~/.ssh/authorized_keys` is empty or missing, it prompts you to paste a public key or press Enter to skip. A pasted key is validated with `ssh-keygen` and appended to `~/.ssh/authorized_keys`.

## Start

Start AsyncSSH and the tunnel together in the background. The default backend is srv.us; see [Backends](#backends) for the Cloudflare options.

```sh
nookwire-ssh start
```

`DIR` defaults to the current directory and accepts relative paths, so `start` alone exposes the directory you are in. Pass a path to expose somewhere else, and set the port or srv.us slot with flags or positionally:

```sh
nookwire-ssh start /marimo
nookwire-ssh start . --port 8022 --slot 1
nookwire-ssh start /marimo 8022 1
```

The command prints the generated password, srv.us URL, and a ready-to-run TLS-wrapped SSH command. It returns to the shell while both services keep running. `status` prints the same connection details later.

### Wide-open share mode: `--accept`

`--accept` skips authentication entirely: any connecting client is admitted without a key or password, no random password is generated or stored, and the `start`/`status` output replaces the credentials with an explicit warning. Combine it with the *tcp forwarding* flag below for an instant share:

```sh
nookwire-ssh start --accept
```

Only use `--accept` in scenarios where wide-open access is intended (for example a short-lived throwaway workspace). Do not expose it publicly on a system you do not own.

### TCP forwarding: `--allow-tcp-forwarding`

By default, a connected client cannot tunnel through the session. With `--allow-tcp-forwarding`, clients can use SSH local forwarding (`ssh -L`) to reach TCP destinations visible to the host, mirroring upterm's `--allow-local-tcp-forwarding`:

```sh
nookwire-ssh start --allow-tcp-forwarding
# on the connecting machine:
ssh -L 8080:db.internal:5432 USER@HOST ... # reaches db.internal:5432 from the host's network
```

The AsyncSSH server enables `direct-tcpip` channels only when this flag is set; otherwise such requests are refused.

Inspect them later:

```sh
nookwire-ssh status
nookwire-ssh connect
nookwire-ssh logs
nookwire-ssh logs tunnel -f
```

`status` is a short summary. `connect` prints the commands to run on the machine you are connecting from.

Stop everything:

```sh
nookwire-ssh stop
```

Start it again without retyping anything:

```sh
nookwire-ssh restart
nookwire-ssh start
```

A successful start saves its backend, root, port, slot, hostname, endpoint, and tunnel token to `config` in the state directory, owner-readable only. Any of those left off a later `start` falls back to the saved value, so a second run on the same machine needs no arguments. `--accept` and `--allow-tcp-forwarding` are never restored; a session that disabled authentication has to say so again every time.

The first start creates `~/.ssh/id_ed25519`. Reusing that key and tunnel slot gives srv.us a stable hostname. Runtime state, credentials, PID files, and logs are stored under `~/.local/state/nookwire-ssh` by default.

Ephemeral machines can recreate the same tunnel identity when that key is
missing by setting a secret seed. The seed is never sent to srv.us:

```sh
export NOOKWIRE_SSH_IDENTITY_SEED='<high-entropy secret scoped to this machine>'
nookwire-ssh start --backend srvus --slot 1
```

The seed deterministically creates the Ed25519 tunnel key only when the key file
does not exist. Existing keys remain authoritative. Reusing both the seed and
slot recreates the same srv.us hostname after local state is lost. Use a random
secret, not a public repository name, because anyone with the seed can recreate
the tunnel identity.

## Backends

`start --backend` selects the public ingress. The AsyncSSH server is identical across all three; only the tunnel process and the printed connect command change. `status` reports the right command for whichever backend is running.

### srvus (default)

Reverse tunnel over srv.us. Zero account, zero domain; the connecting machine needs only OpenSSH and OpenSSL. See [Connect through TLS](#connect-through-tls).

The tunnel runs the `nookwire_ssh.tunnel` module, which holds one AsyncSSH connection to srv.us with a remote forward back to the local server. It creates `~/.ssh/id_ed25519` on first use and reuses it, so the hostname stays stable, and it needs no OpenSSH on the remote machine.

```sh
nookwire-ssh start --backend srvus --slot 1
```

### cloudflare (Worker relay)

Skips srv.us using a Cloudflare Worker you deploy once, which relays SSH over WebSockets via a Durable Object. The remote machine dials out to the Worker (no inbound ports), so it stays NAT-friendly. Deploy the Worker in [`worker/`](worker/README.md):

```sh
cd worker && npx wrangler deploy
```

Then start with the deployed URL as `--endpoint`:

```sh
nookwire-ssh start --backend cloudflare \
  --endpoint https://nookwire-ssh-relay.<subdomain>.workers.dev
```

`status` prints an `ssh` command whose `ProxyCommand` is `nookwire-ssh proxy <wss-url>`. The connecting machine just installs Nookwire SSH the same way (the curl installer) and needs `uv` on `PATH` for that one install; no script paths to hand-edit. A per-start high-entropy tunnel id in the URL authorizes the session. Billing stays inside the free tier for interactive use: WebSocket messages bill at a 20:1 ratio and hibernation zeroes idle duration.

### cloudflared (Cloudflare Tunnel)

Uses `cloudflared` with no per-message billing. Configure a named tunnel whose ingress maps a hostname to `tcp://localhost:PORT`, then pass the hostname and connector token (or set `NOOKWIRE_CLOUDFLARED_TOKEN`):

```sh
nookwire-ssh start --backend cloudflared \
  --hostname ssh.example.com --token "$CF_TUNNEL_TOKEN"
```

The connecting machine uses `ssh -o ProxyCommand='cloudflared access ssh --hostname %h'`, which `status` prints filled in.

## Shorten the connect command

The `ProxyCommand` never varies: every srv.us hostname takes the same block, so it belongs in `~/.ssh/config` on the connecting machine once instead of on every command line. After that, and for every future session, connecting is:

```sh
ssh USER@HOSTNAME.srv.us
sftp USER@HOSTNAME.srv.us
scp -O notebook.py USER@HOSTNAME.srv.us:/notebook.py
```

`nookwire-ssh ssh-config` prints the default `Host *.srv.us` block and `nookwire-ssh ssh-config --write` appends it to `~/.ssh/config`, or paste it yourself:

```
Host *.srv.us
  ProxyCommand openssl s_client -quiet -no_ign_eof -verify_return_error -verify_hostname %h -connect %h:443 -servername %h 2>/dev/null
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
```

Pass a HOST to emit a block scoped to that host instead, using the ProxyCommand for the currently configured backend (read from state): srv.us keeps the OpenSSL wrapper, cloudflared uses `cloudflared access ssh --hostname %h`, and the cloudflare worker relay uses `nookwire-ssh proxy <wss url>`:

```sh
nookwire-ssh ssh-config ssh.example.com
nookwire-ssh ssh-config --write ssh.example.com
```

`--write` appends, because prepending would pull any leading global keywords in an existing config under this `Host` block. SSH uses the first value it finds for each keyword, so it then asks `ssh -G` whether the block actually took effect and warns if an earlier `Host *` block overrides it; move the block above that one if so. Host-key checking is disabled for the affected names, matching what the printed command already does per invocation.

`nookwire-ssh connect` prints all of this ready to paste for whichever backend is running: the `grep ... || printf ...` one-liner that appends the block to `~/.ssh/config`, the short `ssh USER@HOST` that works afterwards, and a self-contained one-line `ssh` with the `ProxyCommand` inline for machines you would rather not configure. `status` stays short and points at it.

## Connect through TLS

The `srvus` backend wraps non-HTTP traffic in TLS. `start` and `status` print the SSH form below with the real username and hostname filled in; the username is the host's OS account. Replace `USER` and `HOSTNAME.srv.us` manually for SFTP or SCP:

```sh
ssh USER@HOSTNAME.srv.us \
  -o 'ProxyCommand=openssl s_client -quiet -verify_return_error -verify_hostname %h -connect %h:443 -servername %h 2>/dev/null' \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR

sftp -o 'ProxyCommand=openssl s_client -quiet -verify_return_error -verify_hostname %h -connect %h:443 -servername %h 2>/dev/null' \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
  USER@HOSTNAME.srv.us

scp -O -o 'ProxyCommand=openssl s_client -quiet -verify_return_error -verify_hostname %h -connect %h:443 -servername %h 2>/dev/null' \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
  notebook.py nookwire@HOSTNAME.srv.us:/notebook.py
```

When the connecting machine's key is in `~/.ssh/authorized_keys`, OpenSSH uses it automatically. Otherwise, enter the generated Nookwire password. `scp -O` selects the SCP protocol implemented by AsyncSSH.

The OpenSSL wrapper verifies both the srv.us certificate chain and hostname before forwarding SSH. When the client requests a pseudo-terminal (the default for interactive `ssh`), Nookwire allocates a real PTY and starts the account's login shell, so job control, terminal resizing, and the shell's own prompt work as usual. Add `-T` to force a non-interactive pipe-backed session for scripts.

## Run directly

Inside a checkout, `uv sync` installs the package (deps included), then run the server module directly:

```sh
export NOOKWIRE_SSH_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
uv run python -m nookwire_ssh.server \
  --root /marimo \
  --host 127.0.0.1 \
  --port 8022
```

Options:

```text
--root PATH
--host ADDRESS
--port PORT
--username USER
--password-env VARIABLE
--authorized-keys PATH
--host-key PATH
--shell PATH
--accept
--allow-tcp-forwarding
```

`--accept` skips all authentication and admits any client, and skips generating a password. `--allow-tcp-forwarding` permits clients to use `ssh -L` local TCP forwarding through the session.

The first `start` creates a stable session (tunnel) id under the state directory and reuses it on later starts, so the exposed endpoint does not change every restart.

## Security model

- Public-key authentication is recommended and automatically uses `~/.ssh/authorized_keys`; password authentication remains available as a temporary fallback and uses constant-time comparison.
- `--accept` disables both, admitting any client without credentials. It also skips password generation. Only use it where open access is intended.
- TCP port forwarding is disabled by default; `--allow-tcp-forwarding` enables `ssh -L` through the session, which can reach any TCP service visible to the host's account.
- The generated password is removed from command environments.
- SFTP and SCP are mapped into the configured root. Paths resolving through a symlink to somewhere outside that root are rejected, and creating symlinks over SFTP is disabled.
- Command sessions start in the root but are not OS-chrooted. Authenticated users can access anything allowed to the server's operating-system account.
- The server generates and reuses an Ed25519 host key in a private per-user temporary directory. The directory must be owned by the server user and not accessible by group or others; a forced setgid or sticky bit is tolerated. Existing keys must have the same owner and mode `0600`.
- The connection examples disable host-key persistence because this targets short-lived disposable environments.
- The srvus tunnel does not verify the srv.us host key, matching the previous OpenSSH invocation. The ingress only carries bytes; SSH's own encryption and authentication still run end to end between client and server.
- Nookwire should only be run on systems and workspaces the operator owns or is explicitly authorized to administer.

## Development

The project is a `src/`-layout package under `src/nookwire_ssh/`: `cli.py` (subcommands), `server.py` (AsyncSSH server), `tunnel.py` (srv.us reverse tunnel), `relay.py` (WebSocket relay for the cloudflare backend), `state.py` (state dir, pid files, meta), and `sshconfig.py` (the srv.us config block).

```sh
uv sync
uv run python -W error::ResourceWarning -m unittest discover -s tests -v
uv run python -m py_compile src/nookwire_ssh/*.py tests/*.py
sh -n install.sh
```

Tests cover password and public-key authentication, command execution, password removal, confined SFTP, AsyncSSH SCP, process cleanup, background lifecycle and logs, system OpenSSH and SCP interoperability, the tunnel's key creation and remote forward, and the install layout, failure handling, and unsafe-destination refusal.
