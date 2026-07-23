// Nookwire SSH relay Worker.
//
// Pairs one "origin" socket (the remote machine's outbound tunnel) with one
// "client" socket (a connecting user) per tunnel id and splices raw bytes
// between them. A Durable Object per id is the rendezvous point; the WebSocket
// Hibernation API keeps idle sessions off the compute-duration meter.
//
// Wire contract:
//   GET /tunnel/<id>?role=origin   (Upgrade: websocket)
//   GET /tunnel/<id>?role=client   (Upgrade: websocket)
// The <id> is a high-entropy shared secret; possession authorizes the tunnel.

const ID_PATTERN = /^\/tunnel\/([A-Za-z0-9_-]{8,})$/;

export class Relay {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const role = url.searchParams.get("role");
    if (role !== "origin" && role !== "client") {
      return new Response("bad role", { status: 400 });
    }
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    // One socket per role: replace any stale holder (e.g. an origin reconnect).
    for (const existing of this.state.getWebSockets(role)) {
      try {
        existing.close(1000, "replaced");
      } catch (_) {}
    }

    this.state.acceptWebSocket(server, [role]);
    return new Response(null, { status: 101, webSocket: client });
  }

  peer(ws) {
    const tags = this.state.getTags(ws);
    const other = tags.includes("origin") ? "client" : "origin";
    const sockets = this.state.getWebSockets(other);
    return sockets.length ? sockets[0] : null;
  }

  async webSocketMessage(ws, message) {
    const peer = this.peer(ws);
    if (peer) {
      // send() throws if the peer is closing/closed; dropping those bytes is
      // correct since the session is tearing down anyway.
      try {
        peer.send(message);
      } catch (_) {}
    }
  }

  async webSocketClose(ws) {
    const peer = this.peer(ws);
    if (peer) {
      try {
        peer.close(1000, "peer closed");
      } catch (_) {}
    }
  }

  async webSocketError(ws) {
    const peer = this.peer(ws);
    if (peer) {
      try {
        peer.close(1011, "peer error");
      } catch (_) {}
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const match = url.pathname.match(ID_PATTERN);
    if (!match) {
      return new Response("not found", { status: 404 });
    }
    const id = match[1];
    const stub = env.RELAY.get(env.RELAY.idFromName(id));
    return stub.fetch(request);
  },
};
