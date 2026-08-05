# Nookwire SSH

Nookwire SSH gives an agent or human temporary SSH command, SFTP, and SCP access to an ephemeral workspace. It uses [AsyncSSH](https://github.com/ronf/asyncssh) for the server and a pluggable public ingress: [srv.us](https://docs.srv.us/) by default, or a Cloudflare Worker relay, or Cloudflare Tunnel (`cloudflared`).

The server binds to localhost, authenticates as the host's own OS user with standard `~/.ssh/authorized_keys` or a generated password fallback, maps SFTP and SCP paths into a configured root, and starts shell commands in that root. Interactive clients get a real login PTY with job control, window resizing, and the account's normal shell and prompt. Every backend only carries bytes and never terminates SSH, so SSH's own encryption and authentication run between client and server. As with srv.us, the printed connect commands disable host-key persistence for these disposable environments, so trust in the ingress matches the existing model; do not treat any backend as protection against a hostile relay.

Use Nookwire only on systems and workspaces you own or are explicitly authorized to administer. It provides authenticated access with the permissions of the host OS account and is not an OS-level sandbox. Public-key authentication is the recommended default. See [Security model](#security-model) and [SECURITY.md](SECURITY.md) before exposing a workspace.

## Prerequisites

The remote machine needs Python 3 and uv. The default `srvus` backend also needs OpenSSH and `ssh-keygen`; the `cloudflare` backend needs a deployed Worker; the `cloudflared` backend needs the `cloudflared` binary. A connecting machine's requirements depend on the backend (see [Backends](#backends)): `srvus` needs OpenSSH and OpenSSL with `s_client -verify_return_error` and `-verify_hostname` support; `cloudflare` needs OpenSSH, uv, and Nookwire SSH installed (its `proxy` subcommand is the ProxyCommand); `cloudflared` needs OpenSSH and `cloudflared`.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/lars-hagen/nookwire-ssh/main/install.sh | sh
```

Run it on the remote machine you want to expose. It installs the version-pinned `v1.4.1` files (`nookwire-ssh` and its Python server companion) into `~/.local/bin`, restoring the previous pair if replacement fails; add that directory to `PATH` if needed. If `uv` is missing, the installer fetches it from `https://astral.sh/uv` first; if `python3` is missing, it provisions a managed Python through uv.

Once installed, `nookwire-ssh upgrade` re-runs the installer in place (`nookwire-ssh upgrade REF` pins a branch or tag; default `main`). Restart a running server with `stop` then `start` to pick up the new code.

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
nookwire-ssh logs
nookwire-ssh logs tunnel -f
```

Stop everything:

```sh
nookwire-ssh stop
```

The first start creates `~/.ssh/id_ed25519`. Reusing that key and tunnel slot gives srv.us a stable hostname. Runtime state, credentials, PID files, and logs are stored under `~/.local/state/nookwire-ssh` by default.

## Backends

`start --backend` selects the public ingress. The AsyncSSH server is identical across all three; only the tunnel process and the printed connect command change. `status` reports the right command for whichever backend is running.

### srvus (default)

Reverse tunnel over srv.us. Zero account, zero domain; the connecting machine needs only OpenSSH and OpenSSL. See [Connect through TLS](#connect-through-tls).

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

`status` prints an `ssh` command whose `ProxyCommand` is `nookwire-ssh proxy <wss-url>`. The connecting machine just installs Nookwire SSH the same way (the curl installer, which also drops `nookwire_ws.py` next to the launcher) and needs `uv` on `PATH`; no script paths to hand-edit. A per-start high-entropy tunnel id in the URL authorizes the session. Billing stays inside the free tier for interactive use: WebSocket messages bill at a 20:1 ratio and hibernation zeroes idle duration.

### cloudflared (Cloudflare Tunnel)

Uses `cloudflared` with no per-message billing. Configure a named tunnel whose ingress maps a hostname to `tcp://localhost:PORT`, then pass the hostname and connector token (or set `NOOKWIRE_CLOUDFLARED_TOKEN`):

```sh
nookwire-ssh start --backend cloudflared \
  --hostname ssh.example.com --token "$CF_TUNNEL_TOKEN"
```

The connecting machine uses `ssh -o ProxyCommand='cloudflared access ssh --hostname %h'`, which `status` prints filled in.

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

```sh
export NOOKWIRE_SSH_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
uv run --with asyncssh==2.24.0 python nookwire_ssh.py \
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
- Nookwire should only be run on systems and workspaces the operator owns or is explicitly authorized to administer.

## Development

```sh
uv run python -W error::ResourceWarning -m unittest discover -s tests -v
uv run python -m py_compile nookwire_ssh.py tests/test_nookwire_ssh.py
sh -n nookwire-ssh
sh -n install.sh
```

Tests cover password and public-key authentication, command execution, password removal, confined SFTP, AsyncSSH SCP, process cleanup, background lifecycle and logs, system OpenSSH and SCP interoperability, and the curl installer layout.
