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

// The binding cookie is per-flow: `[__Host-]wmcp_oauth_bt_<internalState>=<value>`.
function bindingCookie(res: Response): { name: string; value: string } | null {
  const setCookie = res.headers.get("set-cookie");
  if (!setCookie) return null;
  const m = setCookie.match(/((?:__Host-)?wmcp_oauth_bt_[^=]+)=([^;]+)/);
  return m ? { name: m[1], value: m[2] } : null;
}

function stateFromRedirect(res: Response): string {
  const loc = res.headers.get("location");
  if (!loc) throw new Error("no location header on authorize redirect");
  return new URL(loc).searchParams.get("state") ?? "";
}

function flowFromCookieName(name: string): string {
  return name.replace(/^__Host-/, "").replace(/^wmcp_oauth_bt_/, "");
}

/**
 * Run /authorize (which now renders the consent screen) and return the internal
 * state + browser cookie it issues. The internal state is recovered from the
 * per-flow cookie name since /authorize no longer redirects.
 */
async function startFlow(
  init?: RequestInit
): Promise<{ internalState: string; cookie: { name: string; value: string } }> {
  const res = await oauth.request(authorizeUrl(), init);
  expect(res.status).toBe(200);
  const cookie = bindingCookie(res);
  expect(cookie).toBeTruthy();
  const c = cookie as { name: string; value: string };
  const internalState = flowFromCookieName(c.name);
  expect(internalState).toBeTruthy();
  return { internalState, cookie: c };
}

/** Approve consent for a started flow; returns the /authorize/decision response. */
async function approve(flow: {
  internalState: string;
  cookie: { name: string; value: string };
}): Promise<Response> {
  return oauth.request("/authorize/decision", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: `${flow.cookie.name}=${flow.cookie.value}`,
    },
    body: new URLSearchParams({ flow: flow.internalState, decision: "allow" }).toString(),
  });
}

describe("OAuth /authorize (consent screen)", () => {
  test("renders a consent page (not a redirect) and sets the binding cookie", async () => {
    const res = await oauth.request(authorizeUrl());
    expect(res.status).toBe(200);
    // It must NOT bounce straight to Withings anymore.
    expect(res.headers.get("location")).toBeNull();
    const html = await res.text();
    expect(html).toContain("Authorize access to your Withings");
    // The destination the code will be sent to is shown to the user.
    expect(html).toContain("client.example");
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("wmcp_oauth_bt_");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie.toLowerCase()).toContain("samesite=lax");
    // The stored session carries only the HASH of the cookie value.
    const stored = [...sessions.values()][0];
    expect(stored.browser_token_hash).toBeTruthy();
    expect(stored.browser_token_hash).not.toBe(bindingCookie(res)?.value);
  });

  test("names the cookie per-flow and sets __Host- + Secure over HTTPS", async () => {
    const res = await oauth.request(authorizeUrl(), {
      headers: { host: "withings-mcp.example", "x-forwarded-proto": "https" },
    });
    const setCookie = res.headers.get("set-cookie") ?? "";
    const internalState = flowFromCookieName((bindingCookie(res) as { name: string }).name);
    // __Host- prefix (blocks sibling-subdomain fixation) + Secure over HTTPS.
    expect(setCookie).toContain(`__Host-wmcp_oauth_bt_${internalState}=`);
    expect(setCookie).toContain("Secure");
  });

  test("two concurrent flows get distinct cookie names (no clobbering)", async () => {
    const a = await startFlow();
    const b = await startFlow();
    expect(a.internalState).not.toBe(b.internalState);
    expect(a.cookie.name).not.toBe(b.cookie.name);
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

describe("OAuth /authorize/decision (consent gate)", () => {
  test("Allow (with matching cookie) proceeds to Withings", async () => {
    const flow = await startFlow();
    const res = await approve(flow);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toStartWith(
      "https://account.withings.com/oauth2_user/authorize2"
    );
    expect(new URL(res.headers.get("location") as string).searchParams.get("state")).toBe(
      flow.internalState
    );
  });

  test("Cancel returns to the client with error=access_denied and drops the flow", async () => {
    const flow = await startFlow();
    const res = await oauth.request("/authorize/decision", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: `${flow.cookie.name}=${flow.cookie.value}`,
      },
      body: new URLSearchParams({ flow: flow.internalState, decision: "deny" }).toString(),
    });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location") as string);
    expect(loc.origin + loc.pathname).toBe(CLIENT_REDIRECT);
    expect(loc.searchParams.get("error")).toBe("access_denied");
    expect(sessions.has(flow.internalState)).toBe(false);
  });

  test("Allow WITHOUT the binding cookie is rejected (cannot forge consent cross-site)", async () => {
    const flow = await startFlow();
    const res = await oauth.request("/authorize/decision", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ flow: flow.internalState, decision: "allow" }).toString(),
    });
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
  });
});

describe("OAuth /callback browser binding", () => {
  test("completes when the same browser (matching cookie) returns", async () => {
    const { internalState, cookie } = await startFlow();

    const res = await oauth.request(`/callback?code=withings-code&state=${internalState}`, {
      headers: { Cookie: `${cookie.name}=${cookie.value}` },
    });

    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location") as string);
    expect(loc.origin + loc.pathname).toBe(CLIENT_REDIRECT);
    expect(loc.searchParams.get("code")).toBeTruthy();
    expect(loc.searchParams.get("state")).toBe("client-state-123");
    // An auth code was issued and the session consumed on success.
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
    // No auth code minted. The session is left to expire (10-min TTL) rather than
    // consumed, so a sibling flow's stray callback cannot cancel a live login.
    expect(authCodes.size).toBe(0);
  });

  test("rejects a callback whose cookie value does not match the flow", async () => {
    const { internalState, cookie } = await startFlow();

    const res = await oauth.request(`/callback?code=x&state=${internalState}`, {
      headers: { Cookie: `${cookie.name}=some-other-browsers-token` },
    });

    expect(res.status).toBe(400);
    expect(authCodes.size).toBe(0);
  });

  test("rejects a legacy session that has no stored browser_token_hash", async () => {
    // A row created before migration 010 (or by any path that did not set the
    // hash) must fail closed, not sail through with the binding disabled.
    sessions.set("legacy-state", {
      session_id: "legacy-state",
      state: "client-state-123",
      redirect_uri: CLIENT_REDIRECT,
      client_id: CLIENT_ID,
      browser_token_hash: null,
    });

    const res = await oauth.request(`/callback?code=x&state=legacy-state`, {
      headers: { Cookie: "wmcp_oauth_bt_legacy-state=anything" },
    });

    expect(res.status).toBe(400);
    expect(authCodes.size).toBe(0);
  });

  test("concurrent flows in one browser both complete (no cookie clobbering)", async () => {
    const a = await startFlow();
    const b = await startFlow();

    // Complete the FIRST flow after the second one started; its own per-flow
    // cookie is still valid.
    const resA = await oauth.request(`/callback?code=code-a&state=${a.internalState}`, {
      headers: { Cookie: `${a.cookie.name}=${a.cookie.value}` },
    });
    const resB = await oauth.request(`/callback?code=code-b&state=${b.internalState}`, {
      headers: { Cookie: `${b.cookie.name}=${b.cookie.value}` },
    });

    expect(resA.status).toBe(302);
    expect(resB.status).toBe(302);
    expect(authCodes.size).toBe(2);
  });

  test("still rejects an unknown state", async () => {
    const res = await oauth.request(`/callback?code=x&state=does-not-exist`, {
      headers: { Cookie: "wmcp_oauth_bt_x=whatever" },
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
