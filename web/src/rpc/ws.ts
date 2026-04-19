// Reconnecting WebSocket wrapper around the node's eth_subscribe /
// adminLogs channels. A single shared manager keeps one connection
// open; callers subscribe via hooks and get detached on unmount.

type EventCb = (event: unknown) => void;

export type WSSubscriptionType =
  | "newHeads"
  | "logs"
  | "newPendingTransactions"
  | "bsvConfirmation"
  | "adminLogs";

type Subscription = {
  type: WSSubscriptionType;
  params?: unknown;
  onEvent: EventCb;
  // serverId is set when the server confirms the subscription. Until
  // then the subscription sits in pending and is registered on
  // (re)connect.
  serverId?: string;
};

type SubscriptionHandle = {
  cancel: () => void;
};

// Shared manager — single WebSocket connection per page.
class WSManager {
  private socket: WebSocket | null = null;
  private url: string;
  private pending: Map<string, Subscription> = new Map();
  private byServerId: Map<string, string> = new Map();
  private reconnectTimer: number | null = null;
  private reqSeq = 1;
  private resolvers: Map<number, (ok: boolean, result?: unknown) => void> =
    new Map();
  // authToken triggers the `admin_authenticate` message on connect.
  // Set via authenticate() before subscribing to adminLogs.
  private authToken:
    | { kind: "devAuth"; value: string }
    | { kind: "sessionNonce"; value: string }
    | null = null;

  constructor(url: string) {
    this.url = url;
  }

  setAuthToken(token: WSManager["authToken"]) {
    this.authToken = token;
    if (this.socket?.readyState === WebSocket.OPEN && token) {
      this.sendAuth(token);
    }
  }

  subscribe(sub: Subscription): SubscriptionHandle {
    const localId = this.nextLocalId();
    this.pending.set(localId, sub);
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.openSubscription(localId, sub);
    } else {
      this.connect();
    }
    return {
      cancel: () => this.cancel(localId),
    };
  }

  private nextLocalId(): string {
    return `sub-${this.reqSeq++}`;
  }

  private connect() {
    if (this.socket) return;
    const ws = new WebSocket(this.url);
    this.socket = ws;

    ws.addEventListener("open", () => {
      if (this.authToken) this.sendAuth(this.authToken);
      // Register every pending subscription.
      for (const [localId, sub] of this.pending) {
        this.openSubscription(localId, sub);
      }
    });

    ws.addEventListener("message", (evt) => {
      try {
        const payload = JSON.parse(evt.data as string);
        if (typeof payload.id === "number" && this.resolvers.has(payload.id)) {
          const r = this.resolvers.get(payload.id)!;
          this.resolvers.delete(payload.id);
          if ("error" in payload) {
            r(false, payload.error);
          } else {
            r(true, payload.result);
          }
          return;
        }
        if (payload.method === "eth_subscription") {
          const serverId = payload.params?.subscription as string | undefined;
          const localId = serverId ? this.byServerId.get(serverId) : undefined;
          if (localId) {
            const sub = this.pending.get(localId);
            sub?.onEvent(payload.params.result);
          }
        }
      } catch {
        // Ignore malformed frames.
      }
    });

    ws.addEventListener("close", () => {
      this.socket = null;
      // Clear server-id mapping; subscriptions stay pending for
      // re-registration on reconnect.
      this.byServerId.clear();
      for (const sub of this.pending.values()) sub.serverId = undefined;
      this.scheduleReconnect();
    });

    ws.addEventListener("error", () => {
      ws.close();
    });
  }

  private scheduleReconnect() {
    if (this.reconnectTimer != null) return;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      if (this.pending.size > 0) this.connect();
    }, 2_000);
  }

  private sendAuth(token: NonNullable<WSManager["authToken"]>) {
    const id = this.reqSeq++;
    const params = [
      token.kind === "devAuth"
        ? { devAuth: token.value }
        : { sessionNonce: token.value },
    ];
    this.socket?.send(
      JSON.stringify({
        jsonrpc: "2.0",
        id,
        method: "admin_authenticate",
        params,
      })
    );
  }

  private openSubscription(localId: string, sub: Subscription) {
    const id = this.reqSeq++;
    this.resolvers.set(id, (ok, result) => {
      if (ok && typeof result === "string") {
        sub.serverId = result;
        this.byServerId.set(result, localId);
      } else {
        // Keep the subscription in pending so a reconnect retries.
        sub.serverId = undefined;
      }
    });
    const params: unknown[] = [sub.type];
    if (sub.params !== undefined) params.push(sub.params);
    this.socket?.send(
      JSON.stringify({
        jsonrpc: "2.0",
        id,
        method: "eth_subscribe",
        params,
      })
    );
  }

  private cancel(localId: string) {
    const sub = this.pending.get(localId);
    this.pending.delete(localId);
    if (!sub?.serverId) return;
    const id = this.reqSeq++;
    this.socket?.send(
      JSON.stringify({
        jsonrpc: "2.0",
        id,
        method: "eth_unsubscribe",
        params: [sub.serverId],
      })
    );
    this.byServerId.delete(sub.serverId);
  }
}

let sharedManager: WSManager | null = null;

// The explorer defaults to same-origin WS, falling back to localhost
// in dev. The devnet WS port is 18546/18548/18550 per node, so in
// dev Vite proxies /ws to ws://localhost:8546.
function defaultWSURL(): string {
  if (typeof window === "undefined") return "";
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws`;
}

export function ws(): WSManager {
  if (!sharedManager) sharedManager = new WSManager(defaultWSURL());
  return sharedManager;
}
