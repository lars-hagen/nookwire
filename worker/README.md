# Nookwire SSH relay Worker

A Cloudflare Worker that relays SSH over WebSockets, so Nookwire's `cloudflare`
backend can skip srv.us. It pairs one origin socket (the remote machine) with
one client socket (the connecting user) per tunnel id and splices raw bytes
between them. A Durable Object per id is the rendezvous point; the WebSocket
Hibernation API keeps idle sessions off the compute-duration meter.

## Deploy

```sh
cd worker
npx wrangler deploy
```

Wrangler prints the deployed URL, e.g. `https://nookwire-ssh-relay.<subdomain>.workers.dev`.
Use it as the `--endpoint` for the remote machine:

```sh
nookwire-ssh start --backend cloudflare \
  --endpoint https://nookwire-ssh-relay.<subdomain>.workers.dev
```

`status` then prints the matching `ssh` command, whose `ProxyCommand` is
`nookwire-ssh proxy <wss-url>`. The connecting machine just installs Nookwire SSH
(same curl installer) and needs `uv` on `PATH`.

## Billing

WebSocket messages through a Durable Object are billed as requests at a 20:1
ratio (100 messages = 5 requests), and hibernation drops idle-time duration
charges to zero. An interactive SSH session stays comfortably inside the free
tier (100,000 requests/day). The initial `Upgrade` of each leg is one request.

## Security

The tunnel id in the path is a high-entropy secret generated per `start`;
possession is what authorizes a tunnel. Rotate it by restarting Nookwire. The
Worker only relays bytes and never terminates SSH, so host-key and password or
public-key authentication are still enforced end to end by the SSH server.
