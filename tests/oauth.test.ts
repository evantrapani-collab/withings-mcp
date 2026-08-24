/**
 * Security tests for the OAuth broker (src/auth/oauth.ts).
 *
 * These exercise the hardening added to stop authorization-code injection:
 *   1. /authorize binds a flow to the initiating browser via a cookie, and
 *      /callback rejects a flow completed by any other browser.
 *   2. PKCE is required at /authorize.
 *   3. /register rejects script-scheme and empty redirect_uris.
 *   4. /revoke deletes the token mapping.
 *
 * The Supabase client is mocked with small in-memory maps so the full Hono
 * handlers run for real (cookies, redirects, status codes) without a database.
 */

import { describe, test, expect, beforeEach, mock } from "bun:test";
import { makeFakeSupabase, type Handler } from "./helpers/fake-supabase.js";

// encrypt() (used by storeAuthCode on the success path) needs a >=32 char secret.
process.env.ENCRYPTION_SECRET =
  process.env.ENCRYPTION_SECRET ||
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// In-memory tables, reset per test. The mock closure reads `tables` lazily, so
// reassigning them in beforeEach is picked up by every request.
let sessions: Map<string, Record<string, unknown>>;
let clients: Map<string, Record<string, unknown>>;
let authCodes: Map<string, Record<string, unknown>>;
let deletedTokens: string[];
let fake: ReturnType<typeof makeFakeSupabase>;

function filterValue(op: { filters: { column: string; value: unknown }[] }, column: string) {
  return op.filters.find((f) => f.column === column)?.value;
}

const notFound = { data: null, error: { message: "no rows", code: "PGRST116" } };

function buildFake() {
  const allow: Handler = () => ({
    data: {
      allowed: true,
      request_count: 1,
      reset_time: new Date(Date.now() + 300000).toISOString(),
    },
    error: null,
  });

  return makeFakeSupabase({
    check_rate_limit: allow,
    registered_clients: (op) => {
      if (op.action === "select") {
        const row = clients.get(String(filterValue(op, "client_id")));
        return row ? { data: row, error: null } : notFound;
      }
      if (op.action === "upsert") {
        const p = op.payload as Record<string, unknown>;
        clients.set(String(p.client_id), p);
        return { data: null, error: null };
      }
      return { data: null, error: null };
    },
    oauth_sessions: (op) => {
      if (op.action === "insert") {
        const p = op.payload as Record<string, unknown>;
        sessions.set(String(p.session_id), p);
        return { data: null, error: null };
      }
      if (op.action === "select") {
        const row = sessions.get(String(filterValue(op, "session_id")));
        return row ? { data: row, error: null } : notFound;
      }
      if (op.action === "delete") {
        sessions.delete(String(filterValue(op, "session_id")));
        return { data: null, error: null };
      }
      return { data: null, error: null };
    },
    auth_codes: (op) => {
      if (op.action === "insert") {
        const p = op.payload as Record<string, unknown>;
        authCodes.set(String(p.code), p);
        return { data: null, error: null };
      }
      return { data: null, error: null };
    },
    mcp_tokens: (op) => {
      if (op.action === "delete") {
        deletedTokens.push(String(filterValue(op, "mcp_token")));
        return { data: null, error: null };
      }
      return { data: null, error: null };
    },
  });
}

mock.module("../src/db/supabase.js", () => ({
  getSupabaseClient: () => fake.client,
}));

const { createOAuthRouter } = await import("../src/auth/oauth.js");

const CONFIG = {
  clientId: "withings-app-id",
  clientSecret: "withings-app-secret",
  redirectUri: "https://withings-mcp.test/callback",
};

const CLIENT_ID = "client-legit";
const CLIENT_REDIRECT = "https://client.example/cb";

let oauth: ReturnType<typeof createOAuthRouter>;

beforeEach(() => {
  sessions = new Map();
  clients = new Map();
  authCodes = new Map();
  deletedTokens = [];
  fake = buildFake();
  // A pre-registered legitimate client.
  clients.set(CLIENT_ID, {
    client_id: CLIENT_ID,
    client_secret: "secret",
    redirect_uris: [CLIENT_REDIRECT],
  });
  oauth = createOAuthRouter(CONFIG);
});

function authorizeUrl(overrides: Record<string, string | null> = {}): string {
  const params: Record<string, string> = {
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: CLIENT_REDIRECT,
    state: "client-state-123",
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
  };
  for (const [k, v] of Object.entries(overrides)) {
    if (v === null) delete params[k];
    else params[k] = v;
  }
  return "/authorize?" + new URLSearchParams(params).toString();
}

async function jsonBody(res: Response): Promise<Record<string, unknown>> {
  return (await res.json()) as Record<string, unknown>;
}

function cookieValue(res: Response): string | null {
  const setCookie = res.headers.get("set-cookie");
  if (!setCookie) return null;
  const m = setCookie.match(/wmcp_oauth_bt=([^;]+)/);
  return m ? m[1] : null;
}

function stateFromRedirect(res: Response): string {
  const loc = res.headers.get("location");
  if (!loc) throw new Error("no location header on authorize redirect");
  return new URL(loc).searchParams.get("state") ?? "";
}

/** Run /authorize and return the internal state + browser cookie it issues. */
async function startFlow(): Promise<{ internalState: string; cookie: string }> {
  const res = await oauth.request(authorizeUrl());
  expect(res.status).toBe(302);
  const internalState = stateFromRedirect(res);
  const cookie = cookieValue(res);
  expect(internalState).toBeTruthy();
  expect(cookie).toBeTruthy();
  return { internalState, cookie: cookie as string };
}

describe("OAuth /authorize", () => {
  test("redirects to Withings and sets an HttpOnly SameSite=Lax binding cookie", async () => {
    const res = await oauth.request(authorizeUrl());
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toStartWith(
      "https://account.withings.com/oauth2_user/authorize2"
    );
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("wmcp_oauth_bt=");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie.toLowerCase()).toContain("samesite=lax");
    // The stored session carries only the HASH of the cookie value.
    const stored = [...sessions.values()][0];
    expect(stored.browser_token_hash).toBeTruthy();
    expect(stored.browser_token_hash).not.toBe(cookieValue(res));
  });

  test("rejects a request with no PKCE code_challenge", async () => {
    const res = await oauth.request(authorizeUrl({ code_challenge: null }));
    expect(res.status).toBe(400);
    expect((await jsonBody(res)).error).toBe("invalid_request");
  });

  test("rejects a non-S256 code_challenge_method", async () => {
    const res = await oauth.request(authorizeUrl({ code_challenge_method: "plain" }));
    expect(res.status).toBe(400);
  });
});

describe("OAuth /callback browser binding", () => {
  test("completes when the same browser (matching cookie) returns", async () => {
    const { internalState, cookie } = await startFlow();

    const res = await oauth.request(`/callback?code=withings-code&state=${internalState}`, {
      headers: { Cookie: `wmcp_oauth_bt=${cookie}` },
    });

    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location") as string);
    expect(loc.origin + loc.pathname).toBe(CLIENT_REDIRECT);
    expect(loc.searchParams.get("code")).toBeTruthy();
    expect(loc.searchParams.get("state")).toBe("client-state-123");
    // An auth code was issued and the session consumed.
    expect(authCodes.size).toBe(1);
    expect(sessions.has(internalState)).toBe(false);
  });

  test("THE FIX: rejects a callback with no binding cookie (victim's browser)", async () => {
    // Models the attack: the flow was started by the attacker (server-side, so
    // the cookie lives in the attacker's client), and the victim's browser —
    // which has no cookie — is the one that lands on /callback.
    const { internalState } = await startFlow();

    const res = await oauth.request(`/callback?code=victim-withings-code&state=${internalState}`);

    expect(res.status).toBe(400);
    expect((await jsonBody(res)).error).toBe("invalid_state");
    // No auth code minted, and the session was consumed so it cannot be retried.
    expect(authCodes.size).toBe(0);
    expect(sessions.has(internalState)).toBe(false);
  });

  test("rejects a callback whose cookie does not match the flow", async () => {
    const { internalState } = await startFlow();

    const res = await oauth.request(`/callback?code=x&state=${internalState}`, {
      headers: { Cookie: "wmcp_oauth_bt=some-other-browsers-token" },
    });

    expect(res.status).toBe(400);
    expect(authCodes.size).toBe(0);
  });

  test("still rejects an unknown state", async () => {
    const res = await oauth.request(`/callback?code=x&state=does-not-exist`, {
      headers: { Cookie: "wmcp_oauth_bt=whatever" },
    });
    expect(res.status).toBe(400);
  });
});

describe("OAuth /register redirect_uri validation", () => {
  test("accepts an https redirect_uri", async () => {
    const res = await oauth.request("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://app.example/cb"] }),
    });
    expect(res.status).toBe(200);
    expect((await jsonBody(res)).client_id).toBeTruthy();
  });

  test("accepts a custom application scheme (native client)", async () => {
    const res = await oauth.request("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["com.example.app:/oauth"] }),
    });
    expect(res.status).toBe(200);
  });

  test("rejects a javascript: redirect_uri", async () => {
    const res = await oauth.request("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["javascript:alert(1)"] }),
    });
    expect(res.status).toBe(400);
    expect((await jsonBody(res)).error).toBe("invalid_redirect_uri");
  });

  test("rejects an empty redirect_uris list", async () => {
    const res = await oauth.request("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: [] }),
    });
    expect(res.status).toBe(400);
  });
});

describe("OAuth /revoke", () => {
  test("deletes the presented token and returns 200", async () => {
    const res = await oauth.request("/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: "mcp-token-abc" }).toString(),
    });
    expect(res.status).toBe(200);
    expect(deletedTokens).toContain("mcp-token-abc");
  });

  test("returns 200 even with no token (RFC 7009)", async () => {
    const res = await oauth.request("/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "",
    });
    expect(res.status).toBe(200);
    expect(deletedTokens).toHaveLength(0);
  });
});
