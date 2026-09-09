/**
 * Tests for MCP session ownership (`resolveSession()` in
 * src/server/mcp-endpoints.ts).
 *
 * These pin the fix for a bug that shipped: an in-memory ownership binding
 * captured once at handshake outlived the bearer token it was captured from.
 * The OAuth refresh_token grant rotates that token value and
 * `tokenStore.rotateToken()` cascades the new value into `mcp_sessions` — but a
 * live entry in the in-memory Map short-circuited the store lookup entirely, so
 * the correction was invisible to the exact code path that rejected the
 * request. Production, 2026-09-09: four "token does not match session owner"
 * warnings on the Claude connector's tool-call path, self-clearing only after
 * the 30-minute idle sweep evicted the stale entry.
 *
 * Two properties are load-bearing and easy to regress:
 *
 *   1. A rotated bearer must REBUILD its session, never re-label the cached
 *      entry. `createServer()` hands the token to `registerAllTools()` by
 *      value, so a re-labelled session passes the ownership gate and then fails
 *      every tool with "Invalid or expired token".
 *   2. Ownership must be verified BEFORE anything is torn down, or any holder
 *      of a valid token who guesses a session id can kill a stranger's stream.
 *
 * The Supabase client is mocked with in-memory maps so `handleMcp` runs for
 * real. The app is a bare Hono with a stub auth middleware rather than
 * `createApp()`, so these fail on `handleMcp`'s logic and nothing else.
 */

import { describe, test, expect, beforeEach, afterEach, mock } from "bun:test";
import { Hono } from "hono";
import { makeFakeSupabase } from "./helpers/fake-supabase.js";
import type { AppEnv } from "../src/types/hono.js";

// encrypt()/decrypt() need a >=32 char secret; the token store uses them for
// every Withings credential it hands a tool.
process.env.ENCRYPTION_SECRET =
  process.env.ENCRYPTION_SECRET ||
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const MCP_URL = "http://localhost/mcp";

/** The bearer a session is handshaken under. */
const T1 = "token-one-original";
/** The value T1 rotates into, the way the refresh_token grant rewrites it. */
const T2 = "token-two-rotated";
/** An unrelated but valid token, as a fresh authorization_code exchange mints. */
const T3 = "token-three-unrelated";

const NO_ROWS = { data: null, error: { message: "no rows", code: "PGRST116" } };

// In-memory tables, rebuilt per test. The handlers read these lazily so
// reassigning in beforeEach is picked up by every request.
let mcpSessions: Map<string, Record<string, unknown>>;
let fake: ReturnType<typeof makeFakeSupabase>;

/** Overridable per test, so a single case can simulate a store fault. */
let sessionsHandlerOverride:
  | ((op: FakeOperation) => { data: unknown; error: { message: string } | null })
  | null;

/** Which mcp_token value, if any, resolves to a usable Withings credential row. */
let liveWithingsToken: string | null;

interface FakeOperation {
  table: string;
  action: string;
  filters: { column: string; op: string; value: unknown }[];
  payload?: unknown;
}

function filterValue(op: FakeOperation, column: string): unknown {
  return op.filters.find((f) => f.column === column)?.value;
}

function buildFake() {
  return makeFakeSupabase({
    // Fire-and-forget analytics sink; withAnalytics() inserts here on every
    // successful tool call and must not be able to fail a test.
    tool_analytics: () => ({ data: null, error: null }),

    mcp_sessions: (op) => {
      if (sessionsHandlerOverride) return sessionsHandlerOverride(op as FakeOperation);

      const o = op as FakeOperation;
      const id = String(filterValue(o, "session_id"));

      if (o.action === "upsert") {
        const p = o.payload as Record<string, unknown>;
        mcpSessions.set(String(p.session_id), p);
        return { data: null, error: null };
      }
      if (o.action === "select") {
        const row = mcpSessions.get(id);
        return row ? { data: row, error: null } : NO_ROWS;
      }
      if (o.action === "update") {
        const row = mcpSessions.get(id);
        if (row) Object.assign(row, o.payload as Record<string, unknown>);
        return { data: null, error: null };
      }
      if (o.action === "delete") {
        mcpSessions.delete(id);
        return { data: null, error: null };
      }
      return { data: null, error: null };
    },

    mcp_tokens: (op) => {
      const o = op as FakeOperation;
      const presented = String(filterValue(o, "mcp_token"));

      // Only the CURRENTLY live token resolves — exactly what rotateToken()'s
      // UPDATE leaves behind, since getTokens() filters the live column only.
      if (liveWithingsToken === null || presented !== liveWithingsToken) {
        return NO_ROWS;
      }

      return {
        data: {
          mcp_token: presented,
          encrypted_access_token: encryptForTest("withings-access"),
          encrypted_refresh_token: encryptForTest("withings-refresh"),
          withings_user_id: "9001",
          // Far in the future, so makeWithingsRequest() does not take the
          // refresh path and reach for the network a second time.
          withings_expires_at: Date.now() + 60 * 60 * 1000,
          expires_at: new Date(Date.now() + 86_400_000).toISOString(),
        },
        error: null,
      };
    },
  });
}

// encrypt() is imported lazily below, after ENCRYPTION_SECRET is set.
let encryptForTest: (value: string) => string;

mock.module("../src/db/supabase.js", () => ({
  getSupabaseClient: () => fake.client,
}));

const { encrypt } = await import("../src/utils/encryption.js");
encryptForTest = encrypt;

const { handleMcp } = await import("../src/server/mcp-endpoints.js");

/**
 * A bare app with a stub bearer middleware. Deliberately NOT `authenticateBearer`
 * and NOT `createApp()`: the token store, rate limiter and Withings env vars are
 * not under test here, and routing every case through them would make a failure
 * ambiguous.
 */
const app = new Hono<AppEnv>();
app.use("/mcp", async (c, next) => {
  const auth = c.req.header("Authorization") ?? "";
  c.set("accessToken", auth.replace(/^Bearer /, ""));

  if (c.req.method === "POST") {
    // Clone so c.req.raw's stream stays unread, mirroring the body parser that
    // createMcpHonoApp installs in production.
    c.set("parsedBody", await c.req.raw.clone().json());
  }

  await next();
});
app.all("/mcp", handleMcp);

function postRequest(
  body: unknown,
  token: string,
  sessionId?: string
): Request {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    Authorization: `Bearer ${token}`,
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;

  return new Request(MCP_URL, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

function deleteRequest(token: string, sessionId: string): Request {
  return new Request(MCP_URL, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${token}`,
      "mcp-session-id": sessionId,
      Accept: "application/json, text/event-stream",
    },
  });
}

interface JsonRpcEnvelope {
  jsonrpc?: string;
  id?: unknown;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

/** Responses are SSE by default; SDK error responses are plain JSON. */
async function readJsonRpc(response: Response): Promise<JsonRpcEnvelope> {
  const text = await response.text();
  const contentType = response.headers.get("content-type") ?? "";

  if (!contentType.includes("text/event-stream")) {
    return JSON.parse(text) as JsonRpcEnvelope;
  }

  const dataLine = text.split("\n").find((line) => line.startsWith("data: "));
  if (!dataLine) throw new Error(`No SSE data line in payload: ${text}`);

  return JSON.parse(dataLine.slice("data: ".length)) as JsonRpcEnvelope;
}

function toolsListRequest(id: number): Record<string, unknown> {
  return { jsonrpc: "2.0", id, method: "tools/list", params: {} };
}

function initializeMessage(id: number = 1): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "test-client", version: "0.0.0" },
    },
  };
}

/** POST an initialize and return the session id the server assigned. */
async function handshake(token: string): Promise<string> {
  const res = await app.fetch(postRequest(initializeMessage(), token));
  expect(res.status).toBe(200);

  const sid = res.headers.get("mcp-session-id");
  expect(sid).toBeTruthy();

  // Drain, so the SSE stream is not left open across tests.
  await res.text();

  return sid as string;
}

/** Rewrite the stored row the way sessionStore.rotateToken() does. */
function rotateStoredSession(sessionId: string, newToken: string): void {
  const row = mcpSessions.get(sessionId);
  if (!row) throw new Error(`no stored session ${sessionId}`);
  row.mcp_token = newToken;
}

beforeEach(() => {
  mcpSessions = new Map();
  sessionsHandlerOverride = null;
  liveWithingsToken = null;
  fake = buildFake();
});

describe("MCP session ownership", () => {
  test("module mocking is wired up", async () => {
    const sid = await handshake(T1);

    expect(sid.length).toBeGreaterThan(0);
    // If mock.module had not resolved to src/db/supabase.ts, the real
    // getSupabaseClient() would throw "Supabase client not initialized", so
    // this fails loudly rather than passing silently.
    expect(fake.callsFor("mcp_sessions").filter((o) => o.action === "upsert"))
      .toHaveLength(1);
  });

  test("a live session owned by the presented bearer forwards with no session-store read", async () => {
    // Regression guard for the hot path: the ownership fix must not put a
    // database read on every tool call. touchSession() is throttled for five
    // minutes after creation, so any mcp_sessions op here means the check leaked.
    const sid = await handshake(T1);
    fake.reset();

    const res = await app.fetch(postRequest(toolsListRequest(2), T1, sid));
    expect(res.status).toBe(200);

    const body = await readJsonRpc(res);
    expect(body.error).toBeUndefined();
    expect(fake.callsFor("mcp_sessions")).toHaveLength(0);
  });

  test("a rotated bearer keeps its session instead of being refused (FAILURE 1)", async () => {
    const sid = await handshake(T1);
    rotateStoredSession(sid, T2);
    fake.reset();

    const res = await app.fetch(postRequest(toolsListRequest(2), T2, sid));
    expect(res.status).toBe(200);

    const body = await readJsonRpc(res);
    expect(body.error).toBeUndefined();

    const names = (body.result?.tools as { name: string }[]).map((t) => t.name);
    expect(names).toContain("get_user_goals");

    // The client must not learn anything changed.
    expect(res.headers.get("mcp-session-id")).toBe(sid);

    expect(
      fake.callsFor("mcp_sessions").filter((o) => o.action === "select")
    ).toHaveLength(1);
  });

  test("the rebuilt session resolves Withings credentials under the ROTATED token", async () => {
    // THE load-bearing test. It is the only one here that fails against a
    // `session.mcpToken = mcpToken` implementation, which passes every other
    // case in this file and then breaks in production: the tools closed over
    // the dead token value and getTokens() filters the live column only.
    const sid = await handshake(T1);
    rotateStoredSession(sid, T2);
    liveWithingsToken = T2;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({ status: 0, body: { goals: { steps: 10000 } } }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      )) as unknown as typeof fetch;

    try {
      fake.reset();

      const res = await app.fetch(
        postRequest(
          {
            jsonrpc: "2.0",
            id: 3,
            method: "tools/call",
            params: { name: "get_user_goals", arguments: {} },
          },
          T2,
          sid
        )
      );
      expect(res.status).toBe(200);

      const body = await readJsonRpc(res);
      expect(body.result?.isError).not.toBe(true);

      const text = JSON.stringify(body.result?.content ?? []);
      expect(text).not.toContain("Invalid or expired token");

      const tokenSelects = fake
        .callsFor("mcp_tokens")
        .filter((o) => o.action === "select");
      expect(tokenSelects.length).toBeGreaterThan(0);
      for (const op of tokenSelects) {
        expect(filterValue(op as FakeOperation, "mcp_token")).toBe(T2);
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("a self-heal costs one read, and only the first time", async () => {
    const sid = await handshake(T1);
    rotateStoredSession(sid, T2);

    await (await app.fetch(postRequest(toolsListRequest(2), T2, sid))).text();
    fake.reset();

    const res = await app.fetch(postRequest(toolsListRequest(3), T2, sid));
    expect(res.status).toBe(200);
    // Proves the Map was genuinely re-bound, not re-resolved per request.
    expect(fake.callsFor("mcp_sessions")).toHaveLength(0);
  });

  test("a valid bearer that does not own a live session gets 404 invalid_session, not 403 (FAILURE 2)", async () => {
    const sid = await handshake(T1);

    const res = await app.fetch(postRequest(toolsListRequest(2), T3, sid));

    expect(res.status).toBe(404);
    // Pinned explicitly so the intent survives a future refactor.
    expect(res.status).not.toBe(403);
    expect(await res.json()).toEqual({ error: "invalid_session" });
  });

  test("a refused request leaves the session it named untouched", async () => {
    // The DoS-ordering guard. This fails if someone later "simplifies"
    // resolveSession() into discard-then-resolve, which would hand any
    // valid-token holder who guessed a session id the ability to kill a
    // stranger's transport.
    const sid = await handshake(T1);

    const refused = await app.fetch(postRequest(toolsListRequest(2), T3, sid));
    expect(refused.status).toBe(404);

    fake.reset();

    const res = await app.fetch(postRequest(toolsListRequest(3), T1, sid));
    expect(res.status).toBe(200);
    // The owner's transport was never closed and did not have to be rehydrated.
    expect(fake.callsFor("mcp_sessions")).toHaveLength(0);
  });

  test("a cold session owned by someone else gets 404 and its row survives", async () => {
    const sid2 = "cold-session-owned-by-someone-else";
    mcpSessions.set(sid2, {
      session_id: sid2,
      mcp_token: T1,
      expires_at: new Date(Date.now() + 86_400_000).toISOString(),
    });

    const res = await app.fetch(postRequest(toolsListRequest(2), T3, sid2));

    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "invalid_session" });
    expect(mcpSessions.has(sid2)).toBe(true);
    expect(
      fake.callsFor("mcp_sessions").filter((o) => o.action === "delete")
    ).toHaveLength(0);
  });

  test("an unknown session id still gets 404", async () => {
    const res = await app.fetch(
      postRequest(toolsListRequest(2), T1, crypto.randomUUID())
    );

    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "invalid_session" });
  });

  test("an unknown session and a session owned by someone else are indistinguishable", async () => {
    // The anti-oracle assertion: it is what stops a later change from
    // re-splitting the two, and it is why the reasons live only in the log.
    const owned = await handshake(T1);

    const notOwner = await app.fetch(postRequest(toolsListRequest(2), T3, owned));
    const notFound = await app.fetch(
      postRequest(toolsListRequest(3), T3, crypto.randomUUID())
    );

    expect(notOwner.status).toBe(notFound.status);
    expect(notOwner.headers.get("content-type")).toBe(
      notFound.headers.get("content-type")
    );
    expect(await notOwner.text()).toBe(await notFound.text());
  });

  test("an initialize carrying a live session id it does not own creates a fresh session", async () => {
    const sid = await handshake(T1);
    fake.reset();

    const res = await app.fetch(postRequest(initializeMessage(2), T3, sid));
    expect(res.status).toBe(200);

    const newSid = res.headers.get("mcp-session-id");
    expect(newSid).toBeTruthy();
    expect(newSid).not.toBe(sid);
    await res.text();

    // The initialize path never resolves, so it costs no lookup.
    expect(
      fake.callsFor("mcp_sessions").filter((o) => o.action === "select")
    ).toHaveLength(0);

    // The victim's session survived untouched.
    const victim = await app.fetch(postRequest(toolsListRequest(4), T1, sid));
    expect(victim.status).toBe(200);
  });

  test("a batch containing an initialize cannot be smuggled into a foreign live session", async () => {
    // Security regression guard for hoisting the isInitializeMessage() check.
    // `isInitializeRequest` is true if ANY message in a batch is an initialize,
    // so gating the whole resolve path on it — rather than only the cold path,
    // as before — is what keeps this out of the victim's transport now that the
    // unconditional ownership check is gone.
    const sid = await handshake(T1);
    fake.reset();

    const res = await app.fetch(
      postRequest(
        [initializeMessage(1), { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }],
        T3,
        sid
      )
    );

    // Assert on WHICH transport rejected it, not merely that something did.
    // A header check alone is satisfied by any error response, and the SDK
    // always produces one — so it passes against the cold-path-only shape too.
    // A fresh transport is not yet initialized and falls through to the batch
    // rule; the victim's transport short-circuits with "Server already
    // initialized" (SDK index.mjs:2064-2070). Only the former proves the batch
    // never reached the victim.
    expect(res.status).toBe(400);
    expect((await readJsonRpc(res)).error?.message).toBe(
      "Invalid Request: Only one initialization request is allowed"
    );

    const victim = await app.fetch(postRequest(toolsListRequest(4), T1, sid));
    expect(victim.status).toBe(200);
    expect(
      fake.callsFor("mcp_sessions").filter((o) => o.action === "select")
    ).toHaveLength(0);
  });

  test("a session-store failure during a mismatch fails closed", async () => {
    const sid = await handshake(T1);

    sessionsHandlerOverride = () => ({
      data: null,
      error: { message: "connection refused" },
    });

    const res = await app.fetch(postRequest(toolsListRequest(2), T2, sid));

    // The ownership gate must never fail open when the store is unreachable.
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "invalid_session" });
  });

  test("DELETE under a rotated bearer terminates the session", async () => {
    // Also proves the resolve path covers bodyless methods:
    // isInitializeRequest(undefined) is false.
    const sid = await handshake(T1);
    rotateStoredSession(sid, T2);
    fake.reset();

    const res = await app.fetch(deleteRequest(T2, sid));
    expect(res.status).toBe(200);

    const deletes = fake
      .callsFor("mcp_sessions")
      .filter((o) => o.action === "delete");
    expect(deletes).toHaveLength(1);
    expect(filterValue(deletes[0] as FakeOperation, "session_id")).toBe(sid);
  });

  test("a request in flight on the superseded transport still completes", async () => {
    // The rebuild used to tear the old transport down synchronously, which the
    // SDK implements as cleanup() over every open stream. A tools/call already
    // streaming on it was cut off mid-flight: HTTP 200, text/event-stream, zero
    // bytes, no JSON-RPC response — a client that waits forever. discardSession()
    // now unbinds immediately and closes only after a drain.
    const sid = await handshake(T1);
    liveWithingsToken = T1;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      await new Promise((r) => setTimeout(r, 150));
      return new Response(
        JSON.stringify({ status: 0, body: { goals: { steps: 10000 } } }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as unknown as typeof fetch;

    try {
      // In flight on the soon-to-be-superseded transport, authenticated while
      // T1 was still the live bearer.
      const inFlight = app.fetch(
        postRequest(
          {
            jsonrpc: "2.0",
            id: 9,
            method: "tools/call",
            params: { name: "get_user_goals", arguments: {} },
          },
          T1,
          sid
        )
      );

      // Let it reach the (slow) Withings call before the rebuild lands.
      await new Promise((r) => setTimeout(r, 20));

      rotateStoredSession(sid, T2);
      liveWithingsToken = T2;

      const rebuild = await app.fetch(postRequest(toolsListRequest(10), T2, sid));
      expect(rebuild.status).toBe(200);
      await rebuild.text();

      const res = await inFlight;
      expect(res.status).toBe(200);

      const text = await res.text();
      // The regression signature is an empty body, so assert on content first.
      expect(text.length).toBeGreaterThan(0);

      const dataLine = text.split("\n").find((l) => l.startsWith("data: "));
      expect(dataLine).toBeDefined();

      const body = JSON.parse((dataLine as string).slice("data: ".length));
      expect(body.error).toBeUndefined();
      expect(body.id).toBe(9);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

});
