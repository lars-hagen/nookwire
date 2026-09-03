# Nookwire Cloudflare Worker Relay

An edge relay running on Cloudflare Workers that proxies SSH traffic over WebSockets. This pairs with `nookwire --backend cloudflare`.

## Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- A Cloudflare account

## Quick Start

1. Install dependencies:
   ```bash
   npm install
   ```

2. Authenticate with Cloudflare:
   ```bash
   npx wrangler login
   ```

3. Deploy:
   ```bash
   npm run deploy
   ```

Note the deployed worker URL (e.g. `https://nookwire.<your-subdomain>.workers.dev`).

## Usage with Nookwire

On the host:
```bash
nookwire start . 8022 --backend cloudflare --endpoint https://nookwire.<your-subdomain>.workers.dev
```

On the client:
```bash
nookwire connect
```

## How It Works

1. The host opens a WebSocket to `wss://<worker>/tunnel/<session>?role=origin`
2. The client connects to `wss://<worker>/tunnel/<session>?role=client`
3. The Worker pairs the two WebSockets and pumps raw SSH bytes between them
4. If either party disconnects, the Worker closes the other half and terminates the session

Sessions expire after 5 minutes of inactivity if no client connects.

## Development

Run locally:
```bash
npm start
```

This starts a local dev server at `http://localhost:8787`. You can test with:
```bash
nookwire start . 8022 --backend cloudflare --endpoint http://localhost:8787
```
