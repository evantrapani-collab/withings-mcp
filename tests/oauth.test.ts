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
import crypto from "node:crypto";
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
let mcpTokens: Map<string, Record<string, unknown>>;
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
      if (op.action === "update") {
        const id = String(filterValue(op, "session_id"));
        const row = sessions.get(id);
        if (row) sessions.set(id, { ...row, ...(op.payload as Record<string, unknown>) });
        return { data: null, error: null };
      }
      if (op.action === "delete") {
        // Real Supabase's `.delete().eq(...).select().single()` (used by
        // consumeSession()) returns the deleted row, not null — look the row up
        // BEFORE removing it so a `.select()`-chained delete can return it.
        const id = String(filterValue(op, "session_id"));
        const row = sessions.get(id);
        sessions.delete(id);
        if (op.returning) {
          return row ? { data: row, error: null } : notFound;
        }
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
      if (op.action === "delete") {
        // Same DELETE ... RETURNING semantics as oauth_sessions above, for
        // consumeAuthCode()'s `.delete().eq(...).select().single()`.
        const code = String(filterValue(op, "code"));
        const row = authCodes.get(code);
        authCodes.delete(code);
        if (op.returning) {
          return row ? { data: row, error: null } : notFound;
        }
        return { data: null, error: null };
      }
      return { data: null, error: null };
    },
    mcp_tokens: (op) => {
      if (op.action === "select") {
        // Mirrors resolveRefreshToken()'s two query shapes: by mcp_token, or
        // by previous_mcp_token (+ previous_token_expires_at still live).
        const byToken = filterValue(op, "mcp_token");
        if (byToken !== undefined) {
          const row = mcpTokens.get(String(byToken));
          return row ? { data: row, error: null } : notFound;
        }
        const byPrevious = filterValue(op, "previous_mcp_token");
        if (byPrevious !== undefined) {
          const row = [...mcpTokens.values()].find(
            (r) => r.previous_mcp_token === byPrevious
          );
          return row ? { data: row, error: null } : notFound;
        }
        return notFound;
      }
      if (op.action === "update") {
        // extendToken(): UPDATE ... WHERE mcp_token = ? AND expires_at > now
        // RETURNING mcp_token. The fake does not apply filters itself, so the
        // liveness guard is honoured here or the "expired row" case is vacuous.
        const row = mcpTokens.get(String(filterValue(op, "mcp_token")));
        const liveAfter = filterValue(op, "expires_at");
        const isLive =
          row !== undefined &&
          (liveAfter === undefined ||
            new Date(String(row.expires_at)) > new Date(String(liveAfter)));

        if (!isLive) return { data: [], error: null };

        Object.assign(row as Record<string, unknown>, op.payload as Record<string, unknown>);
        return {
          data: op.returning ? [{ mcp_token: row!.mcp_token }] : null,
          error: null,
        };
      }
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
  mcpTokens = new Map();
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

/** Registers a client and returns its client_id, for tests that need a fresh
 * client (a custom-scheme redirect_uri, a client_name) rather than the
 * pre-registered CLIENT_ID. */
async function registerClient(body: Record<string, unknown>): Promise<string> {
  const res = await oauth.request("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return (await jsonBody(res)).client_id as string;
}

// The binding cookie is per-flow: `[__Host-]wmcp_oauth_bt_<internalState>=<value>`.
function bindingCookie(res: Response): { name: string; value: string } | null {
  const setCookie = res.headers.get("set-cookie");
  if (!setCookie) return null;
  const m = setCookie.match(/((?:__Host-)?wmcp_oauth_bt_[^=]+)=([^;]+)/);
  return m ? { name: m[1], value: m[2] } : null;
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

  test("shows the full URI (never blank) for a custom-scheme redirect", async () => {
    const clientId = await registerClient({ redirect_uris: ["com.example.app:/oauth"] });
    const res = await oauth.request(
      authorizeUrl({
        client_id: clientId,
        redirect_uri: "com.example.app:/oauth",
        state: "s",
        code_challenge: "abc",
      })
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("com.example.app:/oauth");
    // The headline destination element must not be empty (custom schemes have no host).
    expect(html).not.toContain("<strong></strong>");
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

  // code_challenge_method is now mandatory, not just "must be S256 if present".
  // An RFC 7636 client that omits it (relying on the spec's "plain" default,
  // which /token has never implemented) used to sail through /authorize and
  // the whole Withings round trip only to fail confusingly at /token.
  test("rejects a request with code_challenge but no code_challenge_method", async () => {
    const res = await oauth.request(authorizeUrl({ code_challenge_method: null }));
    expect(res.status).toBe(400);
    expect((await jsonBody(res)).error).toBe("invalid_request");
  });

  test("shows the registered client_name on the consent screen (HTML-escaped)", async () => {
    const clientId = await registerClient({
      redirect_uris: ["https://app.example/cb"],
      client_name: 'My "Cool" App <script>alert(1)</script>',
    });
    const res = await oauth.request(
      authorizeUrl({
        client_id: clientId,
        redirect_uri: "https://app.example/cb",
        state: "s",
        code_challenge: "abc",
      })
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    // Escaped, not raw markup — the name must not be able to inject a tag.
    expect(html).toContain("My &quot;Cool&quot; App &lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  test("falls back gracefully when the client has no client_name (no literal undefined/null)", async () => {
    // CLIENT_ID was registered in beforeEach with no client_name.
    const res = await oauth.request(authorizeUrl());
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).not.toContain("undefined");
    expect(html).not.toContain("null");
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
    const flow = await startFlow();
    await approve(flow);
    const { internalState, cookie } = flow;

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

  test("rejects a consented-cookie-valid callback for a flow that never consented", async () => {
    // The consent gate is a server-side invariant: even with a valid binding
    // cookie, a flow that skipped the consent POST gets no code.
    const flow = await startFlow(); // consent page shown, but approve() NOT called
    const res = await oauth.request(`/callback?code=x&state=${flow.internalState}`, {
      headers: { Cookie: `${flow.cookie.name}=${flow.cookie.value}` },
    });
    expect(res.status).toBe(400);
    expect((await jsonBody(res)).error).toBe("invalid_state");
    expect(authCodes.size).toBe(0);
  });

  test("concurrent flows in one browser both complete (no cookie clobbering)", async () => {
    const a = await startFlow();
    const b = await startFlow();
    await approve(a);
    await approve(b);

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

  test("concurrent /callback requests for the SAME flow: only one succeeds", async () => {
    // Proves consumeSession()'s atomic DELETE ... RETURNING actually prevents
    // the double-mint race: two requests racing the same internalState must not
    // both mint an independently-redeemable auth code for the same underlying
    // Withings code.
    const flow = await startFlow();
    await approve(flow);
    const { internalState, cookie } = flow;

    const [resA, resB] = await Promise.all([
      oauth.request(`/callback?code=withings-code-a&state=${internalState}`, {
        headers: { Cookie: `${cookie.name}=${cookie.value}` },
      }),
      oauth.request(`/callback?code=withings-code-b&state=${internalState}`, {
        headers: { Cookie: `${cookie.name}=${cookie.value}` },
      }),
    ]);

    const succeeded = [resA, resB].filter((r) => r.status === 302);
    const failed = [resA, resB].filter((r) => r.status === 400);
    expect(succeeded).toHaveLength(1);
    expect(failed).toHaveLength(1);
    expect((await jsonBody(failed[0])).error).toBe("invalid_state");
    expect(authCodes.size).toBe(1);
  });

  test("binding cookie is found even when isSecureRequest() diverges between legs of one flow", async () => {
    // /authorize decides the cookie's name (and whether it gets the __Host-
    // prefix) once, from its own request's headers. A proxy that reports
    // x-forwarded-proto inconsistently across routes could make a LATER leg
    // recompute `secure` differently — readBindingCookie() must still find the
    // cookie the browser is actually presenting rather than only looking under
    // the name this request's own (possibly wrong) recomputation implies.
    //
    // isSecureRequest() returns true when x-forwarded-proto is absent (default
    // secure) and false when it is present but not "https" — so the same host,
    // with and without that header, genuinely diverges the boolean.
    const flow = await startFlow({
      headers: { host: "app.example", "x-forwarded-proto": "https" },
    });
    expect(flow.cookie.name).toStartWith("__Host-");

    const decisionRes = await oauth.request("/authorize/decision", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        host: "app.example",
        "x-forwarded-proto": "http", // diverges from leg 1's "https"
        Cookie: `${flow.cookie.name}=${flow.cookie.value}`,
      },
      body: new URLSearchParams({ flow: flow.internalState, decision: "allow" }).toString(),
    });
    expect(decisionRes.status).toBe(302);

    const callbackRes = await oauth.request(
      `/callback?code=withings-code&state=${flow.internalState}`,
      {
        headers: {
          host: "app.example",
          "x-forwarded-proto": "http", // diverges from leg 1's "https"
          Cookie: `${flow.cookie.name}=${flow.cookie.value}`,
        },
      }
    );
    expect(callbackRes.status).toBe(302);
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

describe("OAuth POST /token (authorization_code grant)", () => {
  // Node's crypto, same approach the production code uses:
  // base64url(sha256(code_verifier)).
  function pkcePair(): { verifier: string; challenge: string } {
    const verifier = crypto.randomBytes(32).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    return { verifier, challenge };
  }

  // Runs /authorize -> /authorize/decision -> /callback for a fresh flow bound
  // to the given PKCE code_challenge, and returns the minted MCP auth code.
  async function completedFlow(challenge: string): Promise<string> {
    const res = await oauth.request(authorizeUrl({ code_challenge: challenge }));
    expect(res.status).toBe(200);
    const cookie = bindingCookie(res) as { name: string; value: string };
    const internalState = flowFromCookieName(cookie.name);
    const flow = { internalState, cookie };
    const decisionRes = await approve(flow);
    expect(decisionRes.status).toBe(302);

    const callbackRes = await oauth.request(
      `/callback?code=withings-auth-code&state=${internalState}`,
      { headers: { Cookie: `${cookie.name}=${cookie.value}` } }
    );
    expect(callbackRes.status).toBe(302);
    const loc = new URL(callbackRes.headers.get("location") as string);
    return loc.searchParams.get("code") as string;
  }

  test("a full PKCE round trip succeeds and returns an access_token", async () => {
    const { verifier, challenge } = pkcePair();
    const authCode = await completedFlow(challenge);

    // Stand in for the Withings token endpoint.
    const originalFetch = global.fetch;
    global.fetch = mock(async () =>
      new Response(
        JSON.stringify({
          status: 0,
          body: {
            access_token: "wat",
            refresh_token: "wrt",
            userid: "u1",
            expires_in: 10800,
          },
        })
      )
    ) as unknown as typeof fetch;

    try {
      const res = await oauth.request("/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: authCode,
          code_verifier: verifier,
          redirect_uri: CLIENT_REDIRECT,
        }).toString(),
      });

      expect(res.status).toBe(200);
      const body = await jsonBody(res);
      expect(body.access_token).toBeTruthy();
      expect(body.token_type).toBe("Bearer");
    } finally {
      global.fetch = originalFetch;
    }
  });

  test("a wrong code_verifier is rejected with invalid_grant", async () => {
    const { challenge } = pkcePair();
    const authCode = await completedFlow(challenge);

    const res = await oauth.request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: authCode,
        code_verifier: "totally-wrong-verifier",
        redirect_uri: CLIENT_REDIRECT,
      }).toString(),
    });

    expect(res.status).toBe(400);
    expect((await jsonBody(res)).error).toBe("invalid_grant");
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

  test("revokes a token still inside its rotation grace window", async () => {
    // Shape a rotateToken() call would leave behind: the row's own mcp_token is
    // the NEW value; the superseded value only lives in previous_mcp_token.
    const future = new Date(Date.now() + 60_000).toISOString();
    mcpTokens.set("new-token", {
      mcp_token: "new-token",
      previous_mcp_token: "old-token",
      previous_token_expires_at: future,
      expires_at: future,
    });

    const res = await oauth.request("/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: "old-token" }).toString(),
    });

    expect(res.status).toBe(200);
    // The CURRENT live value was deleted, not the superseded one that was
    // presented — "old-token" never existed as any row's own mcp_token, so
    // deleting it verbatim would silently no-op while the live token stayed
    // usable at /mcp.
    expect(deletedTokens).toEqual(["new-token"]);
  });
});

/**
 * The refresh_token grant no longer rotates.
 *
 * It used to mint a new opaque value on every refresh. But this project issues
 * ONE value as both access_token and refresh_token, so each rotation
 * invalidated the bearer that every other concurrent holder was still using.
 * Whichever holder missed the 60s single-slot grace was left with a value that
 * was at once a dead bearer and a dead refresh token — nothing left to recover
 * with — and span 401 -> refresh -> invalid_grant until the rate limiter cut it
 * off. Production, 2026-09-09: 78 failed refreshes in 16 seconds, then 10x 429,
 * after which the user had to redo the entire Withings authorization.
 */
const { encrypt } = await import("../src/utils/encryption.js");

describe("/token refresh_token grant", () => {
  const LIVE = "live-token";

  function seedLiveToken(overrides: Record<string, unknown> = {}) {
    const row = {
      mcp_token: LIVE,
      // Full Withings payload, so isValid()/getTokens() can decrypt the row
      // rather than throwing on absent columns.
      encrypted_access_token: encrypt("withings-access"),
      encrypted_refresh_token: encrypt("withings-refresh"),
      withings_user_id: "9001",
      withings_expires_at: Date.now() + 60 * 60_000,
      expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
      ...overrides,
    };
    mcpTokens.set(String(row.mcp_token), row);
    return row;
  }

  function refresh(token: string) {
    return oauth.request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: token,
      }).toString(),
    });
  }

  test("returns the SAME token rather than rotating to a new one", async () => {
    // The core regression guard. A rotating implementation passes almost
    // everything else in this file and still strands concurrent holders.
    seedLiveToken();

    const res = await refresh(LIVE);
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBe(LIVE);
    expect(body.refresh_token).toBe(LIVE);
  });

  test("the token a client was already using stays valid across a refresh", async () => {
    // The storm's actual cause: a refresh used to invalidate the live bearer.
    seedLiveToken();

    await refresh(LIVE);

    const { tokenStore } = await import("../src/auth/token-store.js");
    expect(await tokenStore.isValid(LIVE)).toBe(true);
  });

  test("extends the TTL", async () => {
    const soon = new Date(Date.now() + 60_000).toISOString();
    seedLiveToken({ expires_at: soon });

    await refresh(LIVE);

    const row = mcpTokens.get(LIVE) as Record<string, unknown>;
    expect(new Date(String(row.expires_at)).getTime()).toBeGreaterThan(
      new Date(soon).getTime()
    );
  });

  test("is idempotent: repeated refreshes keep returning the same token", async () => {
    // A client whose first response was lost retries and is handed the same
    // value, instead of a terminal invalid_grant. This is what makes a dropped
    // response survivable at all.
    seedLiveToken();

    const first = (await (await refresh(LIVE)).json()) as Record<string, unknown>;
    const second = (await (await refresh(LIVE)).json()) as Record<string, unknown>;
    const third = (await (await refresh(LIVE)).json()) as Record<string, unknown>;

    expect(first.access_token).toBe(LIVE);
    expect(second.access_token).toBe(LIVE);
    expect(third.access_token).toBe(LIVE);
  });

  test("a token rotated away BEFORE this change still resolves, inside its grace", async () => {
    // Recovery for rows already carrying a previous_mcp_token when this shipped.
    const future = new Date(Date.now() + 60_000).toISOString();
    mcpTokens.set("current", {
      mcp_token: "current",
      previous_mcp_token: "superseded",
      previous_token_expires_at: future,
      expires_at: future,
    });

    const res = await refresh("superseded");
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBe("current");
  });

  test("an unknown refresh token is a terminal invalid_grant", async () => {
    const res = await refresh("never-issued");

    expect(res.status).toBe(400);
    expect((await res.json()) as Record<string, unknown>).toMatchObject({
      error: "invalid_grant",
    });
  });

  test("an expired row is not resurrected by a refresh", async () => {
    seedLiveToken({ expires_at: new Date(Date.now() - 1000).toISOString() });

    const res = await refresh(LIVE);

    expect(res.status).toBe(400);
    expect((await res.json()) as Record<string, unknown>).toMatchObject({
      error: "invalid_grant",
    });
  });

  test("a missing refresh_token parameter is invalid_request, not invalid_grant", async () => {
    const res = await oauth.request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token" }).toString(),
    });

    expect(res.status).toBe(400);
    expect((await res.json()) as Record<string, unknown>).toMatchObject({
      error: "invalid_request",
    });
  });
});
