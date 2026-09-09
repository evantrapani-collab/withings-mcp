import {
  isInitializeRequest,
  McpServer,
  WebStandardStreamableHTTPServerTransport,
} from "@modelcontextprotocol/server";
import { sessionStore } from "../auth/session-store.js";
import { registerAllTools } from "../tools/index.js";
import { createLogger } from "../utils/logger.js";
import type { AppContext } from "../types/hono.js";

const logger = createLogger({ component: "mcp-endpoints" });

// Idle sessions are evicted from memory after this many ms without any HTTP
// activity. Clients (Claude Desktop, web, mobile) usually drop the SSE stream
// without sending DELETE, so without this sweep the session Map grows
// unbounded. Eviction is now only a memory optimisation — the Supabase row
// survives, so a returning client is transparently rehydrated.
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;

// Sessions are kept alive in Supabase by refreshing `expires_at`, but doing
// that on every request would add a write to each tool call. Throttle it.
const ACTIVITY_PERSIST_INTERVAL_MS = 5 * 60 * 1000;

interface Session {
  transport: WebStandardStreamableHTTPServerTransport;
  mcpToken: string;
  lastActivityAt: number;
  lastPersistedAt: number;
}

const sessions = new Map<string, Session>();

// In-flight rehydrations, so concurrent requests for the same cold session
// (clients typically reconnect their GET stream and POST at the same moment)
// share one transport instead of racing and orphaning the loser.
//
// Keyed by session id AND owner. A rehydration started for a bearer that has
// since been rotated away builds an McpServer whose tools closed over the dead
// token value, so joining it across a rotation would hand back a session that
// authenticates at this layer and then fails every Withings call.
interface Rehydration {
  mcpToken: string;
  promise: Promise<Session>;
}

const rehydrating = new Map<string, Rehydration>();

// How long a superseded transport goes on serving the requests already in
// flight on it before it is closed. See discardSession().
const SUPERSEDED_DRAIN_MS = 60 * 1000;

/**
 * Drop a session's in-memory entry — but only if it is still the entry we mean.
 *
 * A transport's `onclose` calls back into this Map, and a superseded transport
 * is closed on a drain timer (discardSession()) long after its replacement has
 * been registered under the same session id. A bare `sessions.delete(id)` from
 * a transport on its way out would evict that replacement.
 */
function forgetSession(sessionId: string, session: Session): void {
  if (sessions.get(sessionId) === session) sessions.delete(sessionId);
}

/**
 * Tear down a session whose in-memory token binding has been superseded, so it
 * can be rebuilt under the live bearer.
 *
 * Reassigning `Session.mcpToken` in place would NOT work. `createServer()`
 * hands the token to `registerAllTools()` by value, and every tool handler
 * passes that exact string to `tokenStore.getTokens()`, which filters on the
 * live `mcp_token` column only — a column `rotateToken()` has already moved.
 * A re-labelled session would sail past the ownership gate and then throw
 * "Invalid or expired token" on all 13 tools (src/withings/api.ts). That trades
 * a diagnosable rejection for a connected-but-dead session, which is worse.
 *
 * The stored row is deliberately left alone: `close()` fires `transport.onclose`
 * but not `onsessionclosed` (which only fires on an explicit DELETE), so the
 * binding the rebuild is about to read survives.
 *
 * Unbound immediately so the rebuild can take the slot, but closed only after a
 * drain. The SDK's `close()` runs `cleanup()` over every open stream and then
 * `onclose`, all synchronously — closing here and now would abort requests that
 * were authenticated while the superseded bearer was still live and have not
 * yet written a response, which on an SSE stream means a 200 with an empty body
 * and a client that waits forever. The timer is also what eventually reclaims
 * the transport: the idle sweep walks `sessions`, and this one is no longer in
 * it.
 */
function discardSession(sessionId: string, session: Session): void {
  forgetSession(sessionId, session);

  const drain = setTimeout(() => {
    session.transport.close().catch((err) => {
      logger.warn("Error closing superseded transport", {
        error: err instanceof Error ? err.message : String(err),
      });
    });
  }, SUPERSEDED_DRAIN_MS);
  drain.unref?.();
}

const sweep = setInterval(() => {
  const cutoff = Date.now() - IDLE_TIMEOUT_MS;
  for (const [id, session] of sessions) {
    if (session.lastActivityAt < cutoff) {
      forgetSession(id, session);
      session.transport.close().catch((err) => {
        logger.warn("Error closing idle transport", {
          error: err instanceof Error ? err.message : String(err),
        });
      });
      logger.info("Evicted idle MCP session from memory");
    }
  }
}, SWEEP_INTERVAL_MS);
sweep.unref?.();

function createServer(mcpToken: string): McpServer {
  const server = new McpServer(
    { name: "withings-mcp", version: "2.1.0" },
    { capabilities: { tools: {} } }
  );
  registerAllTools(server, mcpToken);
  return server;
}

/**
 * Rebuild a session this process has no memory of — after a restart, an idle
 * eviction, or because another instance handled the handshake.
 *
 * The transport is created *without* a `sessionIdGenerator`, which puts it in
 * stateless mode: `validateSession()` returns immediately instead of rejecting
 * the request with "Bad Request: Server not initialized", since the handshake
 * that would have set that flag happened in a process that no longer exists.
 * Assigning `sessionId` afterwards (a public field on the SDK's Transport
 * interface) makes the transport keep echoing the client's existing
 * Mcp-Session-Id, so the client never learns anything changed.
 *
 * Nothing else needs restoring: tool handlers close over the MCP token alone
 * and re-read every Withings credential from Supabase per call. The negotiated
 * client capabilities are lost, which is harmless here — all tools are
 * read-only and the server never initiates sampling, elicitation or roots.
 *
 * This is also the rotation-rebuild path: a session whose bearer was rotated is
 * discarded and rebuilt here under the new token value.
 */
async function rehydrateSession(
  sessionId: string,
  mcpToken: string
): Promise<Session> {
  // Declared up front so the teardown callbacks can identity-guard their Map
  // delete against the entry they actually belong to.
  let session: Session | undefined;

  const transport = new WebStandardStreamableHTTPServerTransport({
    // Close over the id rather than taking the callback argument: this SDK
    // passes `this.sessionId` (which we assign below, so it is correct today),
    // but a stateless transport has no session of its own and a future version
    // could reasonably pass `undefined` here.
    onsessionclosed: () => {
      if (session) forgetSession(sessionId, session);
      void sessionStore.delete(sessionId).catch((err) => {
        logger.warn("Failed to delete MCP session", {
          error: err instanceof Error ? err.message : String(err),
        });
      });
      logger.info("MCP session closed");
    },
  });
  transport.sessionId = sessionId;

  transport.onclose = () => {
    if (session) forgetSession(sessionId, session);
  };

  await createServer(mcpToken).connect(transport);

  session = {
    transport,
    mcpToken,
    lastActivityAt: Date.now(),
    lastPersistedAt: Date.now(),
  };

  sessions.set(sessionId, session);

  logger.info("MCP session rehydrated from store");

  return session;
}

function getOrRehydrateSession(
  sessionId: string,
  mcpToken: string
): Promise<Session> {
  const inFlight = rehydrating.get(sessionId);
  if (inFlight?.mcpToken === mcpToken) return inFlight.promise;

  const entry: Rehydration = {
    mcpToken,
    promise: rehydrateSession(sessionId, mcpToken).finally(() => {
      // Identity-guarded: a rehydration superseded by a rotation must not clear
      // the slot its replacement now holds.
      if (rehydrating.get(sessionId) === entry) rehydrating.delete(sessionId);
    }),
  };
  rehydrating.set(sessionId, entry);

  return entry.promise;
}

/**
 * An initialize request always starts a fresh session, even if the client sent
 * a stale session id alongside it — there is nothing to rehydrate, and adopting
 * one would make the SDK reject the handshake as already initialized.
 *
 * `isInitializeRequest` is wrapped rather than passed to `.some()` directly:
 * `.some()` also supplies an index and the source array, so a future signature
 * change upstream would silently start feeding it the index.
 */
function isInitializeMessage(body: unknown): boolean {
  return Array.isArray(body)
    ? body.some((message) => isInitializeRequest(message))
    : isInitializeRequest(body);
}

/**
 * Resolve the session this request names, to the extent the presented bearer is
 * entitled to it. `mcp_sessions` is the authority; the in-memory Map is a cache
 * of it, trusted only while it agrees with the presented bearer.
 *
 * The Map's binding is captured once at handshake and never updated, but the
 * bearer changes underneath it. The OAuth refresh_token grant rotates the token
 * value and `tokenStore.rotateToken()` cascades that into `mcp_sessions` — a
 * correction a live Map entry short-circuited past and never read, so the very
 * request the cascade was written for still failed (production, 2026-09-09:
 * four "token does not match session owner" warnings on the connector's
 * tool-call path, self-clearing only after the 30-minute idle sweep). Consulting
 * the row on a mismatch also makes a rotation served by one replica heal on
 * every other replica's next request.
 *
 * The store can only ever confirm that the PRESENTED bearer owns the session,
 * never that some other bearer does: a row naming a different token is refused,
 * not adopted, and refusal mutates nothing at all.
 *
 * It must never fall back to `previous_mcp_token`. That grace window belongs to
 * the /token refresh grant alone (`resolveRefreshToken`); honouring it here
 * would make a rotated-away bearer usable for real data access for 60 seconds.
 * `authenticateBearer` already rejects a superseded token with 401, so one
 * cannot reach this function today — keep it that way.
 */
async function resolveSession(
  sessionId: string,
  mcpToken: string
): Promise<Session | "not_found" | "not_owner"> {
  const cached = sessions.get(sessionId);
  if (cached?.mcpToken === mcpToken) return cached;

  // `sessionStore.get()` collapses a query error into null, so a Supabase fault
  // renders as "not_found" and the client is told to re-initialize. Failing
  // closed is deliberate for an authorization decision: there must be no
  // "store unreachable, trust the Map" branch.
  const stored = await sessionStore.get(sessionId);
  if (!stored) return "not_found";
  if (stored.mcpToken !== mcpToken) return "not_owner";

  // Re-read the Map. `cached` is a snapshot from BEFORE the store round-trip,
  // and a concurrent request for the same session id — the "client reconnects
  // its GET stream and POSTs at the same moment" pattern this file already
  // expects — may have rebuilt it while this one was waiting on Supabase.
  // Acting on the stale snapshot builds a second transport for one session id
  // and orphans the first. `rehydrating` alone cannot cover this: it is
  // consulted only after the await, whereas the decision to rebuild was made
  // before it.
  //
  // Not covered by a test, deliberately: the loser is no longer torn down, so a
  // duplicate rebuild has no HTTP-observable symptom to assert — it costs a
  // wasted McpServer and leaves a standalone GET stream attached to a transport
  // nothing routes to any more. Harmless while every tool is read-only and the
  // server never initiates messages; it stops being harmless the moment either
  // changes.
  const current = sessions.get(sessionId);
  if (current?.mcpToken === stored.mcpToken) return current;

  // Verified BEFORE anything is torn down. The tidier-looking "drop the stale
  // entry, then re-resolve" ordering would let any holder of a valid token who
  // guessed a session id kill a stranger's live transport.
  if (current) {
    logger.info("Rebuilding MCP session under a rotated bearer token");
    discardSession(sessionId, current);
  }

  // `stored.mcpToken` rather than `mcpToken`: the two are provably equal by
  // here, and reading the owner out of the row makes it plain that nothing a
  // client presents can ever become a session's owner.
  return getOrRehydrateSession(sessionId, stored.mcpToken);
}

// Keep the stored session alive without adding a write to every tool call.
function touchSession(session: Session, sessionId: string): void {
  const now = Date.now();
  session.lastActivityAt = now;

  if (now - session.lastPersistedAt < ACTIVITY_PERSIST_INTERVAL_MS) return;

  session.lastPersistedAt = now;
  void sessionStore.touch(sessionId);
}

/**
 * The one answer for "this session id is not usable by this bearer": 404, the
 * status Streamable HTTP assigns to a terminated session and the only one a
 * client has a defined recovery for — start a new session by sending a fresh
 * InitializeRequest with no session id attached.
 *
 * It used to be 403 for a session owned by someone else and 404 for one that
 * does not exist. 403 was wrong twice over. It asserts "re-authenticating will
 * not help", which is the opposite of the truth — re-initializing is exactly
 * what helps — and it was an existence oracle, telling a holder of any valid
 * token which session ids are live. Production on 2026-09-09 shows the cost:
 * two 403s at 09:22:15/09:22:19 after a re-authorization, and recovery only at
 * 09:22:21 when the connector re-handshaked out of a generic error path. A
 * client that wedges on 404 wedges at least as hard on 403, so this cannot be
 * worse.
 *
 * The two reasons answer identically on the wire — a client can do nothing
 * different with them — and stay apart only in the log, which is where the
 * original diagnosis came from.
 */
function invalidSession(c: AppContext, reason: "not_found" | "not_owner") {
  if (reason === "not_owner") {
    // Unchanged wording on purpose: this is the string the incident was found
    // with, and it is now the only machine-readable signal for a genuine
    // cross-client attempt. An unknown id logs nothing — a warn there would be
    // a log-flood amplifier for anyone spraying session ids, and the access log
    // already records the request.
    logger.warn("Session access denied: token does not match session owner");
  }

  return c.json({ error: "invalid_session" }, 404);
}

/**
 * Unified handler for /mcp endpoint (GET, POST, DELETE).
 * Uses the SDK's WebStandardStreamableHTTPServerTransport which handles
 * all protocol details internally (SSE streaming, JSON-RPC validation,
 * session lifecycle).
 */
export const handleMcp = async (c: AppContext) => {
  const mcpToken = c.get("accessToken");
  const sessionId = c.req.header("mcp-session-id");
  const parsedBody = c.get("parsedBody");

  let session: Session | undefined;

  // An initialize request always starts a fresh session, so a session id sent
  // alongside one is ignored even when this process still holds it in memory.
  // Ignoring it on the cold path only was enough while ownership was also
  // checked unconditionally further down; now that the check lives inside
  // resolveSession(), a batch of [initialize, tools/call] carrying a foreign
  // session id would otherwise be forwarded straight into the victim's
  // transport — isInitializeMessage() is true if ANY message in a batch is an
  // initialize.
  if (sessionId && !isInitializeMessage(parsedBody)) {
    const resolved = await resolveSession(sessionId, mcpToken);

    if (resolved === "not_found" || resolved === "not_owner") {
      return invalidSession(c, resolved);
    }

    session = resolved;
  }

  // Existing session — forward to its transport.
  // `parsedBody` is populated by the JSON body parser middleware that
  // `createMcpHonoApp` installs on the app, so the transport reuses it
  // instead of re-parsing the request body.
  if (session && sessionId) {
    touchSession(session, sessionId);
    return session.transport.handleRequest(c.req.raw, { parsedBody });
  }

  // No session — only POST can initialize
  if (c.req.method !== "POST") {
    return c.json({ error: "invalid_request" }, 400);
  }

  // New session — create transport + server
  //
  // Held so the teardown callbacks can identity-guard their Map delete: close()
  // settles on a later tick, and by then this id may map to a session rebuilt
  // under a rotated bearer, which must not be evicted by its predecessor.
  let established: Session | undefined;

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
    onsessioninitialized: async (id) => {
      established = {
        transport,
        mcpToken,
        lastActivityAt: Date.now(),
        lastPersistedAt: Date.now(),
      };
      sessions.set(id, established);
      // Persist so the session outlives this process. A failure here only
      // costs restart-survivability, so degrade instead of failing the
      // handshake.
      try {
        await sessionStore.create(id, mcpToken);
      } catch (err) {
        logger.warn("Failed to persist MCP session", {
          error: err instanceof Error ? err.message : String(err),
        });
      }
      logger.info("MCP session established");
    },
    onsessionclosed: (id) => {
      if (established) forgetSession(id, established);
      void sessionStore.delete(id).catch((err) => {
        logger.warn("Failed to delete MCP session", {
          error: err instanceof Error ? err.message : String(err),
        });
      });
      logger.info("MCP session closed");
    },
  });

  // Belt-and-suspenders: onsessionclosed only fires on explicit DELETE.
  // onclose fires whenever the transport itself is torn down (idle sweep,
  // server shutdown, a rotation rebuild superseding it, internal SDK errors),
  // so wire both. This one drops the in-memory entry only — the stored session
  // must survive a restart, and a rebuild depends on that row still being there.
  transport.onclose = () => {
    if (transport.sessionId && established) {
      forgetSession(transport.sessionId, established);
    }
  };

  await createServer(mcpToken).connect(transport);

  return transport.handleRequest(c.req.raw, { parsedBody });
};
