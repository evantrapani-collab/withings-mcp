import { Hono, type Context } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { tokenStore } from "./token-store.js";
import crypto from "node:crypto";
import { getSupabaseClient } from "../db/supabase.js";
import { createLogger } from "../utils/logger.js";
import { rateLimit } from "../server/rate-limiter.js";
import { encrypt, decrypt } from "../utils/encryption.js";
import { Buffer } from "node:buffer";

const logger = createLogger({ component: "oauth" });

const WITHINGS_AUTH_URL = "https://account.withings.com/oauth2_user/authorize2";
const WITHINGS_TOKEN_URL = "https://wbsapi.withings.net/v2/oauth2";

const SESSION_TTL_MS = 10 * 60 * 1000; // 10 minutes

// Cookie that binds an authorization flow to the browser that started it. It is
// set on the /authorize response and required (and matched) on the Withings
// /callback, so a flow initiated server-side by a third party cannot be
// completed by a victim's browser (authorization-code injection).
const BROWSER_BINDING_COOKIE = "wmcp_oauth_bt";

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

interface OAuthSession {
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  redirectUri: string;
  clientId?: string;
  browserTokenHash?: string;
  consented?: boolean;
}

interface OAuthSessionRow {
  session_id: string;
  state: string;
  code_challenge: string | null;
  code_challenge_method: string | null;
  redirect_uri: string;
  client_id: string | null;
  browser_token_hash: string | null;
  consented_at: string | null;
}

interface AuthCode {
  withingsCode: string;
  clientId?: string;
  redirectUri: string;
  codeChallenge?: string;
}

interface AuthCodeRow {
  code: string;
  withings_code: string;
  client_id: string | null;
  redirect_uri: string;
  code_challenge: string | null;
}

interface RegisteredClient {
  clientId: string;
  clientSecret?: string;
  redirectUris: string[];
  clientName?: string;
}

interface RegisteredClientRow {
  client_id: string;
  client_secret: string | null;
  redirect_uris: string[];
  client_name: string | null;
}

class OAuthStore {
  async init(): Promise<void> {
    // No initialization needed - Supabase client is initialized separately
  }

  async storeSession(sessionId: string, session: OAuthSession): Promise<void> {
    const supabase = getSupabaseClient();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

    const { error } = await supabase.from("oauth_sessions").insert({
      session_id: sessionId,
      state: session.state,
      code_challenge: session.codeChallenge || null,
      code_challenge_method: session.codeChallengeMethod || null,
      redirect_uri: session.redirectUri,
      client_id: session.clientId || null,
      browser_token_hash: session.browserTokenHash || null,
      expires_at: expiresAt,
    });

    if (error) {
      throw new Error(`Failed to store OAuth session: ${error.message}`);
    }
  }

  async getSession(sessionId: string): Promise<OAuthSession | null> {
    const supabase = getSupabaseClient();
    const now = new Date().toISOString();

    const { data, error } = await supabase
      .from("oauth_sessions")
      .select("*")
      .eq("session_id", sessionId)
      .gt("expires_at", now)
      .single();

    if (error || !data) {
      return null;
    }

    const row = data as OAuthSessionRow;

    return {
      state: row.state,
      codeChallenge: row.code_challenge || undefined,
      codeChallengeMethod: row.code_challenge_method || undefined,
      redirectUri: row.redirect_uri,
      clientId: row.client_id || undefined,
      browserTokenHash: row.browser_token_hash || undefined,
      consented: Boolean(row.consented_at),
    };
  }

  // Record that the user approved this flow on the consent screen. /callback
  // requires this, so an authorization code is issued only for a flow the user
  // explicitly consented to — not merely one whose secret state was observed.
  async markConsented(sessionId: string): Promise<void> {
    const supabase = getSupabaseClient();

    const { error } = await supabase
      .from("oauth_sessions")
      .update({ consented_at: new Date().toISOString() })
      .eq("session_id", sessionId);

    if (error) {
      throw new Error(`Failed to mark OAuth session consented: ${error.message}`);
    }
  }

  /**
   * Atomically consume an OAuth session: delete and return in one operation.
   * Modeled on consumeAuthCode() — the same atomic DELETE ... RETURNING
   * pattern, guarded by the same TTL filter. Ensures two concurrent /callback
   * requests for the same flow cannot both pass and each mint an
   * independently-redeemable auth code for the same underlying Withings code.
   */
  async consumeSession(sessionId: string): Promise<OAuthSession | null> {
    const supabase = getSupabaseClient();
    const now = new Date().toISOString();

    const { data, error } = await supabase
      .from("oauth_sessions")
      .delete()
      .eq("session_id", sessionId)
      .gt("expires_at", now)
      .select()
      .single();

    if (error || !data) {
      return null;
    }

    const row = data as OAuthSessionRow;

    return {
      state: row.state,
      codeChallenge: row.code_challenge || undefined,
      codeChallengeMethod: row.code_challenge_method || undefined,
      redirectUri: row.redirect_uri,
      clientId: row.client_id || undefined,
      browserTokenHash: row.browser_token_hash || undefined,
      consented: Boolean(row.consented_at),
    };
  }

  async deleteSession(sessionId: string): Promise<void> {
    const supabase = getSupabaseClient();

    const { error } = await supabase
      .from("oauth_sessions")
      .delete()
      .eq("session_id", sessionId);

    if (error) {
      throw new Error(`Failed to delete OAuth session: ${error.message}`);
    }
  }

  async storeAuthCode(code: string, data: AuthCode): Promise<void> {
    const supabase = getSupabaseClient();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

    const { error } = await supabase.from("auth_codes").insert({
      code,
      withings_code: encrypt(data.withingsCode),
      client_id: data.clientId || null,
      redirect_uri: data.redirectUri,
      code_challenge: data.codeChallenge || null,
      expires_at: expiresAt,
    });

    if (error) {
      throw new Error(`Failed to store auth code: ${error.message}`);
    }
  }

  /**
   * Atomically consume an auth code: delete and return in one operation.
   * Prevents replay attacks by ensuring a code can only be used once.
   */
  async consumeAuthCode(code: string): Promise<AuthCode | null> {
    const supabase = getSupabaseClient();
    const now = new Date().toISOString();

    // Atomic delete + select: removes the row and returns it in one query
    const { data, error } = await supabase
      .from("auth_codes")
      .delete()
      .eq("code", code)
      .gt("expires_at", now)
      .select()
      .single();

    if (error || !data) {
      return null;
    }

    const row = data as AuthCodeRow;

    return {
      withingsCode: decrypt(row.withings_code),
      clientId: row.client_id || undefined,
      redirectUri: row.redirect_uri,
      codeChallenge: row.code_challenge || undefined,
    };
  }

  async registerClient(clientId: string, client: RegisteredClient): Promise<void> {
    const supabase = getSupabaseClient();

    const { error } = await supabase.from("registered_clients").upsert({
      client_id: clientId,
      client_secret: client.clientSecret || null,
      redirect_uris: client.redirectUris,
      client_name: client.clientName || null,
      updated_at: new Date().toISOString(),
    }, {
      onConflict: "client_id",
    });

    if (error) {
      throw new Error(`Failed to register client: ${error.message}`);
    }
  }

  async getClient(clientId: string): Promise<RegisteredClient | null> {
    const supabase = getSupabaseClient();

    const { data, error } = await supabase
      .from("registered_clients")
      .select("*")
      .eq("client_id", clientId)
      .single();

    if (error || !data) {
      return null;
    }

    const row = data as RegisteredClientRow;

    return {
      clientId: row.client_id,
      clientSecret: row.client_secret || undefined,
      redirectUris: row.redirect_uris,
      clientName: row.client_name || undefined,
    };
  }
}

const oauthStore = new OAuthStore();

function base64URLEncode(str: Buffer): string {
  return str.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function sha256(buffer: string): Buffer {
  return crypto.createHash('sha256').update(buffer).digest();
}

function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

// Constant-time comparison of two equal-length hex digests.
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// A request is treated as secure (HTTPS) unless it is explicitly plain http or
// targets a loopback host. This matches getPublicBaseUrl's https-by-default
// stance, so a TLS-terminating proxy that omits x-forwarded-proto still yields a
// Secure binding cookie rather than silently downgrading it.
function isSecureRequest(c: {
  req: { header: (name: string) => string | undefined; url: string };
}): boolean {
  const host = (c.req.header("x-forwarded-host") || c.req.header("host") || "").toLowerCase();
  if (host.startsWith("localhost") || host.startsWith("127.0.0.1") || host.startsWith("[::1]")) {
    return false;
  }
  const proto = (c.req.header("x-forwarded-proto") || "").split(",")[0].trim();
  if (proto) return proto === "https";
  // No proxy scheme header and not a loopback host: default to secure, matching
  // getPublicBaseUrl's https-by-default stance.
  return true;
}

// Per-flow cookie name. The __Host- prefix (only valid over HTTPS) forbids a
// Domain attribute and requires Secure + Path=/, so a sibling subdomain cannot
// fixate this cookie. The internalState suffix gives each concurrent flow its
// own cookie instead of a single shared name that later flows would clobber.
function bindingCookieName(internalState: string, secure: boolean): string {
  const prefix = secure ? "__Host-" : "";
  return `${prefix}${BROWSER_BINDING_COOKIE}_${internalState}`;
}

// /authorize sets the binding cookie under a single name, decided once by its
// own locally-computed `secure`. The two read sites (/authorize/decision and
// /callback) are separate requests that may see inconsistent proxy headers
// (and therefore compute a different `secure`) than the request that set the
// cookie — recomputing the name there and looking up only that one name can
// miss a cookie the browser is actually presenting under the other name,
// failing a legitimate flow closed indistinguishably from an attack. Instead,
// try both possible names and use whichever one is actually set.
function readBindingCookie(
  c: Context,
  internalState: string
): { name: string; value: string } | null {
  const hostName = bindingCookieName(internalState, true);
  const plainName = bindingCookieName(internalState, false);

  const hostValue = getCookie(c, hostName);
  if (hostValue) {
    return { name: hostName, value: hostValue };
  }

  const plainValue = getCookie(c, plainName);
  if (plainValue) {
    return { name: plainName, value: plainValue };
  }

  return null;
}

// Reject redirect URIs that could execute script in the context that receives
// them. http(s) and custom application schemes (native MCP clients, per RFC
// 8252) are allowed — the browser binding on /callback, not this list, is what
// defeats open-redirect abuse of a registered https URI.
function isSafeRedirectUri(uri: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  const scheme = parsed.protocol.toLowerCase();
  return (
    scheme !== "javascript:" &&
    scheme !== "data:" &&
    scheme !== "vbscript:" &&
    scheme !== "file:"
  );
}

const WITHINGS_SCOPE = "user.metrics,user.activity,user.sleepevents,user.info";

function buildWithingsAuthUrl(config: OAuthConfig, internalState: string): string {
  const url = new URL(WITHINGS_AUTH_URL);
  url.searchParams.append("response_type", "code");
  url.searchParams.append("client_id", config.clientId);
  url.searchParams.append("redirect_uri", config.redirectUri);
  url.searchParams.append("scope", WITHINGS_SCOPE);
  url.searchParams.append("state", internalState);
  return url.toString();
}

function htmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// First-party consent interstitial, shown BEFORE the Withings hop. The browser
// binding proves the callback returns to the same browser; it cannot prove the
// user meant to authorize THIS client. Showing the requesting client and the
// destination the authorization will be sent to — and requiring an explicit
// click — is what stops an attacker phishing a victim to a crafted /authorize
// link (the code would otherwise be delivered to the attacker's redirect_uri
// with the victim never seeing where their data went).
function renderConsentPage(params: {
  internalState: string;
  clientId: string;
  redirectUri: string;
  clientName?: string;
}): string {
  let host: string;
  try {
    host = new URL(params.redirectUri).host;
  } catch {
    host = "";
  }
  // Custom application schemes (native clients, e.g. com.example.app:/cb) have an
  // empty URL host — fall back to the full URI so the destination is never blank,
  // which is the whole signal this screen exists to show.
  const headline = host || params.redirectUri;
  const flow = htmlEscape(params.internalState);
  const client = htmlEscape(params.clientId);
  const uriHost = htmlEscape(headline);
  const fullUri = htmlEscape(params.redirectUri);
  // client_name is optional per RFC 7591 — an unnamed client falls back to
  // today's behavior of identifying itself by its raw client_id.
  const clientName = params.clientName ? htmlEscape(params.clientName) : undefined;
  const intro = clientName
    ? `An application named &ldquo;<strong>${clientName}</strong>&rdquo; is requesting read access to your Withings data (weight, activity, sleep, and heart measurements).`
    : `An application is requesting read access to your Withings data (weight, activity, sleep, and heart measurements).`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize access to your Withings data</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 32rem; margin: 3rem auto; padding: 0 1.25rem; color: #1a1a1a; line-height: 1.5; }
  .card { border: 1px solid #e0e0e0; border-radius: 12px; padding: 1.5rem; }
  h1 { font-size: 1.2rem; margin: 0 0 1rem; }
  .dest { background: #f6f6f6; border-radius: 8px; padding: .75rem 1rem; margin: 1rem 0; word-break: break-all; }
  .dest strong { font-size: 1.05rem; }
  .muted { color: #666; font-size: .85rem; }
  .row { display: flex; gap: .75rem; margin-top: 1.5rem; }
  button { flex: 1; padding: .7rem 1rem; font-size: 1rem; border-radius: 8px; border: 0; cursor: pointer; }
  .allow { background: #0a7d34; color: #fff; }
  .deny { background: #eee; color: #1a1a1a; }
</style>
</head>
<body>
<div class="card">
<h1>Authorize access to your Withings health data</h1>
<p>${intro}</p>
<div class="dest">
  Your authorization will be sent to:<br><strong>${uriHost}</strong>
  <div class="muted">${fullUri}</div>
  <div class="muted">Client ID: ${client}</div>
</div>
<p class="muted">Only continue if you started this from an app you trust and you recognize the destination above.</p>
<form method="POST" action="/authorize/decision">
  <input type="hidden" name="flow" value="${flow}">
  <div class="row">
    <button class="deny" name="decision" value="deny">Cancel</button>
    <button class="allow" name="decision" value="allow">Allow</button>
  </div>
</form>
</div>
</body>
</html>`;
}

export async function initOAuthStore() {
  await oauthStore.init();
}

export function createOAuthRouter(config: OAuthConfig) {
  const oauth = new Hono();

  // Dynamic client registration (open for MCP compatibility, protected by rate limiting)
  // RFC 7591 — https://datatracker.ietf.org/doc/html/rfc7591
  oauth.post(
    "/register",
    rateLimit({ maxRequests: 5, windowMs: 300000 }), // 5 per 5 min (sliding)
    async (c) => {
      try {
        const body = await c.req.json().catch(() => ({} as Record<string, unknown>));
        const redirectUris = Array.isArray((body as { redirect_uris?: unknown }).redirect_uris)
          ? ((body as { redirect_uris: unknown[] }).redirect_uris.filter(
              (u): u is string => typeof u === "string"
            ))
          : [];
        const clientName =
          typeof (body as { client_name?: unknown }).client_name === "string"
            ? (body as { client_name: string }).client_name
            : undefined;

        // A client with no usable redirect_uri can never complete a flow
        // (/authorize rejects any redirect_uri not registered here), and
        // script-scheme URIs are never legitimate — reject both at registration.
        if (redirectUris.length === 0 || !redirectUris.every(isSafeRedirectUri)) {
          logger.warn("OAuth client registration rejected: invalid redirect_uris");
          return c.json(
            {
              error: "invalid_redirect_uri",
              error_description:
                "redirect_uris must be a non-empty list of URIs and may not use the javascript, data, vbscript, or file scheme",
            },
            400
          );
        }

        const clientId = crypto.randomUUID();
        const clientSecret = crypto.randomUUID();

        await oauthStore.registerClient(clientId, {
          clientId,
          clientSecret,
          redirectUris,
          clientName,
        });

        logger.info("OAuth client registered", { clientName });

        // Minimal RFC 7591 response, matching the working nutrition-mcp
        // reference exactly. Some OAuth orchestrators (including Claude's)
        // strict-parse the response and silently abort if they encounter
        // fields with values they don't like — keep the shape tiny.
        return c.json({
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uris: redirectUris,
        });
      } catch (error) {
        logger.error("OAuth client registration failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        return c.json(
          { error: "invalid_client_metadata", error_description: "Client registration failed" },
          400
        );
      }
    }
  );

  // Authorization endpoint - MCP client starts here
  oauth.get(
    "/authorize",
    rateLimit({ maxRequests: 15, windowMs: 300000 }), // 15 per 5 min (sliding)
    async (c) => {
    const responseType = c.req.query("response_type");
    const clientId = c.req.query("client_id");
    const redirectUri = c.req.query("redirect_uri");
    const state = c.req.query("state");
    const codeChallenge = c.req.query("code_challenge");
    const codeChallengeMethod = c.req.query("code_challenge_method");

    if (responseType !== "code") {
      logger.warn("OAuth authorization failed: unsupported response type");
      return c.json({ error: "unsupported_response_type" }, 400);
    }

    if (!redirectUri) {
      logger.warn("OAuth authorization failed: missing redirect_uri");
      return c.json({ error: "invalid_request", error_description: "redirect_uri is required" }, 400);
    }

    // Require state parameter for CSRF protection
    if (!state) {
      logger.warn("OAuth authorization failed: missing state parameter");
      return c.json({ error: "invalid_request", error_description: "state parameter is required for CSRF protection" }, 400);
    }

    // Validate redirect_uri against registered client
    if (!clientId) {
      logger.warn("OAuth authorization failed: missing client_id");
      return c.json({ error: "invalid_request", error_description: "client_id is required" }, 400);
    }

    const registeredClient = await oauthStore.getClient(clientId);
    if (!registeredClient) {
      logger.warn("OAuth authorization failed: unregistered client_id");
      return c.json({ error: "invalid_client", error_description: "client_id is not registered" }, 400);
    }

    if (!registeredClient.redirectUris.includes(redirectUri)) {
      logger.warn("OAuth authorization failed: redirect_uri not registered for client");
      return c.json({ error: "invalid_request", error_description: "redirect_uri is not registered for this client" }, 400);
    }

    // Require PKCE. The MCP authorization spec mandates it, and an authorization
    // code with no challenge is redeemable by anyone who intercepts it.
    if (!codeChallenge) {
      logger.warn("OAuth authorization failed: missing code_challenge (PKCE required)");
      return c.json({ error: "invalid_request", error_description: "code_challenge is required (PKCE)" }, 400);
    }
    // PKCE just became mandatory above; an RFC 7636 client that omits
    // code_challenge_method relies on the spec's "plain" default, which this
    // server has never implemented (/token only ever verifies S256). Reject
    // that here with a clear error instead of letting it sail through consent
    // and the whole Withings round trip only to fail confusingly at /token.
    if (codeChallengeMethod !== "S256") {
      logger.warn("OAuth authorization failed: unsupported code_challenge_method");
      return c.json({ error: "invalid_request", error_description: "code_challenge_method must be S256" }, 400);
    }

    logger.info("Starting OAuth authorization flow");

    // Generate internal state for Withings OAuth
    const internalState = crypto.randomUUID();

    // Bind this flow to the browser that started it. The Withings callback must
    // arrive carrying this cookie, so an attacker who initiates a flow
    // server-side cannot have a victim's browser complete it.
    const browserToken = base64URLEncode(crypto.randomBytes(32));

    // Store OAuth session
    await oauthStore.storeSession(internalState, {
      state,
      codeChallenge,
      codeChallengeMethod: "S256",
      redirectUri,
      clientId,
      browserTokenHash: sha256Hex(browserToken),
    });

    // Secure over HTTPS (default) so local http development still works.
    // SameSite=Lax is required: the callback is a top-level cross-site
    // navigation redirected from account.withings.com, which Strict would strip
    // the cookie from.
    const secure = isSecureRequest(c);
    setCookie(c, bindingCookieName(internalState, secure), browserToken, {
      httpOnly: true,
      secure,
      sameSite: "Lax",
      path: "/",
      maxAge: SESSION_TTL_MS / 1000,
    });

    // The response carries a secret cookie — never let a cache store it.
    c.header("Cache-Control", "no-store");

    // Show the first-party consent screen instead of bouncing straight to
    // Withings. The user must explicitly approve — and see the destination —
    // before the flow proceeds, which is what defeats a phished /authorize link.
    // No form-action directive: the consent POST is answered with a 302 to
    // account.withings.com, and some browsers apply form-action to that redirect
    // target — which would break the flow. The form's action is a hardcoded,
    // escaped, same-origin path and no script can run (default-src 'none'), so
    // form-action adds no protection here anyway.
    c.header(
      "Content-Security-Policy",
      "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
    );
    return c.html(
      renderConsentPage({
        internalState,
        clientId,
        redirectUri,
        clientName: registeredClient.clientName,
      })
    );
    }
  );

  // Consent decision — the user clicked Allow or Cancel on the interstitial.
  // Only from here does the flow proceed to Withings, so the consent screen
  // cannot be skipped.
  oauth.post(
    "/authorize/decision",
    rateLimit({ maxRequests: 15, windowMs: 300000 }),
    async (c) => {
      const body = (await c.req
        .parseBody()
        .catch(() => ({}))) as Record<string, unknown>;
      const internalState = typeof body.flow === "string" ? body.flow : "";
      const decision = typeof body.decision === "string" ? body.decision : "";

      c.header("Cache-Control", "no-store");

      if (!internalState) {
        return c.json({ error: "invalid_request", error_description: "flow is required" }, 400);
      }

      const session = await oauthStore.getSession(internalState);
      if (!session) {
        logger.warn("OAuth decision failed: invalid or expired flow");
        return c.json({ error: "invalid_state" }, 400);
      }

      // Same browser binding as /callback: the approval must come from the
      // browser that started the flow, not a cross-site forged POST. Look up
      // the cookie under either possible name (see readBindingCookie) rather
      // than only the one implied by this request's own recomputed `secure` —
      // a proxy that reports headers inconsistently across routes could
      // otherwise make a legitimate flow fail closed.
      const bound = readBindingCookie(c, internalState);
      const cookieName = bound?.name ?? bindingCookieName(internalState, isSecureRequest(c));
      const secure = cookieName.startsWith("__Host-");
      const browserToken = bound?.value;
      if (
        !session.browserTokenHash ||
        !browserToken ||
        !timingSafeEqualHex(sha256Hex(browserToken), session.browserTokenHash)
      ) {
        logger.warn("OAuth decision rejected: browser binding missing or mismatched");
        return c.json({ error: "invalid_state" }, 400);
      }

      if (decision !== "allow") {
        // User cancelled: return to the client with a standard error (RFC 6749
        // §4.1.2.1) so it can react instead of hanging. Build the redirect
        // before dropping the flow, so a malformed stored redirect_uri cannot
        // leave the session orphaned.
        const denied = new URL(session.redirectUri);
        denied.searchParams.append("error", "access_denied");
        denied.searchParams.append("state", session.state);
        await oauthStore.deleteSession(internalState);
        deleteCookie(c, cookieName, { path: "/", secure });
        return c.redirect(denied.toString());
      }

      // Record the approval so /callback issues a code only for a consented
      // flow, rather than any flow whose secret state was observed.
      await oauthStore.markConsented(internalState);
      logger.info("OAuth consent granted; redirecting to Withings");
      return c.redirect(buildWithingsAuthUrl(config, internalState));
    }
  );

  // Callback from Withings
  oauth.get(
    "/callback",
    rateLimit({ maxRequests: 15, windowMs: 300000 }), // matches /authorize's budget: callback volume tracks authorize volume 1:1
    async (c) => {
    const code = c.req.query("code");
    const internalState = c.req.query("state");

    if (!code || !internalState) {
      logger.warn("OAuth callback failed: missing code or state");
      return c.json({ error: "invalid_request" }, 400);
    }

    const session = await oauthStore.getSession(internalState);
    if (!session) {
      logger.warn("OAuth callback failed: invalid or expired state");
      return c.json({ error: "invalid_state" }, 400);
    }

    // Enforce the browser binding established at /authorize. Without a cookie
    // matching this flow, reject — this stops a third party from having a
    // victim's browser complete a flow the attacker initiated. The session is
    // left to expire on its own (10-minute TTL); consuming it here would let a
    // sibling flow's stray request cancel an unrelated in-flight login. Look up
    // the cookie under either possible name (see readBindingCookie) rather than
    // only the one implied by this request's own recomputed `secure`.
    const bound = readBindingCookie(c, internalState);
    const cookieName = bound?.name ?? bindingCookieName(internalState, isSecureRequest(c));
    const secure = cookieName.startsWith("__Host-");
    const browserToken = bound?.value;
    if (
      !session.browserTokenHash ||
      !browserToken ||
      !timingSafeEqualHex(sha256Hex(browserToken), session.browserTokenHash)
    ) {
      deleteCookie(c, cookieName, { path: "/", secure });
      logger.warn("OAuth callback rejected: browser binding missing or mismatched");
      return c.json(
        {
          error: "invalid_state",
          error_description:
            "authorization must be completed in the browser that started it",
        },
        400
      );
    }

    // The flow must have passed through the consent screen. This makes the
    // consent gate an explicit server-side invariant rather than one that holds
    // only because the internal state stayed secret.
    if (!session.consented) {
      logger.warn("OAuth callback rejected: flow was not consented");
      return c.json(
        { error: "invalid_state", error_description: "authorization was not consented" },
        400
      );
    }

    // Atomically consume the session now that both checks have passed. This
    // is the point past which a second concurrent request for the same flow
    // must not also succeed — otherwise two requests could each mint an
    // independently-redeemable auth code for the same underlying Withings
    // code. A null result means a concurrent request already consumed it.
    const consumedSession = await oauthStore.consumeSession(internalState);
    if (!consumedSession) {
      logger.warn("OAuth callback rejected: session already consumed by a concurrent/duplicate callback");
      return c.json({ error: "invalid_state" }, 400);
    }

    logger.info("Processing OAuth callback from Withings");

    // Generate authorization code for MCP client
    const authCode = crypto.randomUUID();

    // Store auth code with Withings code
    await oauthStore.storeAuthCode(authCode, {
      withingsCode: code,
      clientId: consumedSession.clientId,
      redirectUri: consumedSession.redirectUri,
      codeChallenge: consumedSession.codeChallenge,
    });

    // Redirect back to MCP client with state parameter (required for CSRF validation)
    const redirectUrl = new URL(consumedSession.redirectUri);
    redirectUrl.searchParams.append("code", authCode);
    redirectUrl.searchParams.append("state", consumedSession.state);

    logger.info("Redirecting to client callback", {
      host: redirectUrl.host,
      pathname: redirectUrl.pathname,
      hasCode: Boolean(redirectUrl.searchParams.get("code")),
      hasState: Boolean(redirectUrl.searchParams.get("state")),
      existingParams: Array.from(new URL(consumedSession.redirectUri).searchParams.keys()),
    });

    // Only clear the binding cookie once the flow has fully succeeded, so a
    // transient failure earlier (e.g. a Supabase error between here and
    // consumeSession) leaves the cookie intact for a legitimate retry instead
    // of stranding the client behind an orphaned, unredeemable auth code.
    deleteCookie(c, cookieName, { path: "/", secure });

    return c.redirect(redirectUrl.toString());
    }
  );

  // Token endpoint - MCP client exchanges code for token, or refreshes it
  oauth.post(
    "/token",
    rateLimit({
      maxRequests: 30,
      // 30 per 5 minutes, per grant type, on a sliding window. Short window is
      // deliberate: the limiter smooths capacity across two windows, so a long
      // one would take up to two hours to fully decay. A legitimate client
      // needs 1-3 calls per authorization, so 30 is ample headroom while a
      // stuck client recovers in minutes rather than the better part of a day.
      windowMs: 300000,
      // Budget per grant type, not per endpoint. A client stuck retrying a
      // dead refresh_token used to burn the shared budget and then get 429ed
      // on authorization_code — the one exchange that could have repaired it —
      // leaving the user unable to reconnect for the rest of the window.
      // Hono caches the parsed form body, so reading it here does not stop the
      // handler below from parsing it again.
      scope: async (c) => {
        const body = await c.req.parseBody();
        return typeof body.grant_type === "string" ? body.grant_type : "unknown";
      },
    }),
    async (c) => {
    const body = await c.req.parseBody();
    const grantType = body.grant_type;
    const code = body.code as string;
    const codeVerifier = body.code_verifier as string;
    const redirectUri = body.redirect_uri as string;

    // refresh_token grant (RFC 6749 §6). Rotate the MCP token value and
    // return the new pair. The Withings credentials stored alongside the
    // token are preserved — this only refreshes the opaque MCP-layer token.
    if (grantType === "refresh_token") {
      const refreshToken = body.refresh_token as string;
      if (!refreshToken) {
        logger.warn("Token refresh failed: refresh_token parameter missing");
        return c.json({
          error: "invalid_request",
          error_description: "refresh_token is required for this grant type",
        }, 400);
      }

      const resolved = await tokenStore.resolveRefreshToken(refreshToken);
      if (!resolved) {
        logger.warn(
          "Token refresh failed: refresh token is unknown, expired, or past the rotation grace window"
        );
        return c.json({
          error: "invalid_grant",
          error_description:
            "refresh_token is no longer valid; re-authorize to obtain a new one",
        }, 400);
      }

      // Rotation is idempotent within the grace window. A client that retried
      // because it never received (or never stored) the first response gets
      // handed the same token the winning request was issued, instead of a
      // terminal invalid_grant that would strand it permanently.
      let issuedToken = resolved.currentToken;

      if (!resolved.isReplay) {
        const candidate = crypto.randomUUID();
        const rotated = await tokenStore.rotateToken(refreshToken, candidate);

        if (rotated) {
          issuedToken = candidate;
        } else {
          // Lost a concurrent rotation race: `candidate` was never written, so
          // returning it would hand the client a token that authenticates
          // nothing. Re-resolve and return whatever the winner issued.
          const winner = await tokenStore.resolveRefreshToken(refreshToken);
          if (!winner) {
            logger.warn(
              "Token refresh failed: lost rotation race and the winning token is no longer resolvable"
            );
            return c.json({ error: "invalid_grant" }, 400);
          }
          issuedToken = winner.currentToken;
          logger.info("Token refresh resolved a concurrent rotation race");
        }
      } else {
        logger.info("Token refresh replayed within grace window");
      }

      const MCP_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      return c.json({
        access_token: issuedToken,
        token_type: "Bearer",
        expires_in: MCP_TOKEN_TTL_SECONDS,
        refresh_token: issuedToken,
      });
    }

    if (grantType !== "authorization_code") {
      logger.warn("Token exchange failed: unsupported grant type");
      return c.json({ error: "unsupported_grant_type" }, 400);
    }

    // Atomically consume the auth code (single-use per RFC 6749 Section 4.1.2)
    const authCodeData = await oauthStore.consumeAuthCode(code);
    if (!authCodeData) {
      logger.warn("Token exchange failed: invalid, expired, or already-used authorization code");
      return c.json({ error: "invalid_grant" }, 400);
    }

    logger.info("Processing token exchange request");

    // Validate redirect_uri matches the one from authorization request
    if (redirectUri !== authCodeData.redirectUri) {
      logger.warn("Token exchange failed: redirect_uri mismatch");
      return c.json({ error: "invalid_grant", error_description: "redirect_uri does not match authorization request" }, 400);
    }

    // Validate PKCE if code_challenge was provided
    if (authCodeData.codeChallenge) {
      if (!codeVerifier) {
        logger.warn("PKCE validation failed: missing code_verifier");
        return c.json({ error: "invalid_request", error_description: "code_verifier required" }, 400);
      }

      const hash = base64URLEncode(sha256(codeVerifier));
      if (hash !== authCodeData.codeChallenge) {
        logger.warn("PKCE validation failed: invalid code_verifier");
        return c.json({ error: "invalid_grant", error_description: "invalid code_verifier" }, 400);
      }
    }

    // Exchange Withings code for access token
    try {
      const tokenResponse = await fetch(WITHINGS_TOKEN_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          action: "requesttoken",
          grant_type: "authorization_code",
          client_id: config.clientId,
          client_secret: config.clientSecret,
          code: authCodeData.withingsCode,
          redirect_uri: config.redirectUri,
        }),
      });

      const tokenData = await tokenResponse.json() as {
        status: number;
        body: {
          access_token: string;
          refresh_token: string;
          userid: string;
          expires_in: number;
        };
      };

      if (tokenData.status !== 0) {
        logger.error("Withings token exchange failed");
        return c.json({ error: "server_error", error_description: "Failed to exchange Withings token" }, 500);
      }

      // Generate MCP access token
      const mcpToken = crypto.randomUUID();

      // Store token mapping
      await tokenStore.storeTokens(mcpToken, {
        withingsAccessToken: tokenData.body.access_token,
        withingsRefreshToken: tokenData.body.refresh_token,
        withingsUserId: tokenData.body.userid,
        expiresAt: Date.now() + tokenData.body.expires_in * 1000,
      });

      logger.info("Token exchange completed successfully");

      // MCP token is valid for 30 days (matches database TTL)
      // Server handles refreshing Withings tokens transparently
      const MCP_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

      // RFC 6749 §5.1: token endpoint responses MUST NOT be cached.
      // refresh_token intentionally shares the mcpToken value — this project
      // uses a single opaque MCP token that can be rotated via the
      // refresh_token grant (see rotateToken in token-store.ts).
      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      return c.json({
        access_token: mcpToken,
        token_type: "Bearer",
        expires_in: MCP_TOKEN_TTL_SECONDS,
        refresh_token: mcpToken,
      });
    } catch (error) {
      logger.error("Token exchange error", { error: String(error) });
      return c.json({ error: "server_error", error_description: "Failed to exchange authorization code" }, 500);
    }
    }
  );

  // Token revocation (RFC 7009). Possession of the token authorizes its
  // revocation: deleting the mcp_tokens row severs the Withings credential
  // mapping, so every subsequent /mcp request with that bearer fails auth. This
  // is the service-side kill switch an MCP client's "disconnect" can call.
  oauth.post(
    "/revoke",
    rateLimit({ maxRequests: 30, windowMs: 300000 }),
    async (c) => {
      const body = await c.req.parseBody();
      const token = typeof body.token === "string" ? body.token : "";

      if (token) {
        try {
          // A token rotated in the last 60s lives under previous_mcp_token,
          // not mcp_token — resolve it to the currently-live value first, so
          // revoking a recently-superseded token actually kills the live
          // token instead of silently no-op-ing while it stays usable at /mcp.
          const resolved = await tokenStore.resolveRefreshToken(token);
          await tokenStore.deleteToken(resolved ? resolved.currentToken : token);
          logger.info("Token revoked");
        } catch (error) {
          logger.warn("Token revocation failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }

      // RFC 7009 §2.2: respond 200 regardless of whether the token was valid, so
      // revocation cannot be used to probe token validity.
      c.header("Cache-Control", "no-store");
      return c.json({}, 200);
    }
  );

  return oauth;
}

/**
 * Refresh Withings access token using refresh token
 */
export async function refreshWithingsToken(
  refreshToken: string,
  config: OAuthConfig
): Promise<{
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  userId: string;
}> {
  logger.info("Refreshing Withings access token");

  const tokenResponse = await fetch(WITHINGS_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      action: "requesttoken",
      grant_type: "refresh_token",
      client_id: config.clientId,
      client_secret: config.clientSecret,
      refresh_token: refreshToken,
    }),
  });

  const tokenData = await tokenResponse.json() as {
    status: number;
    body: {
      access_token: string;
      refresh_token: string;
      userid: string;
      expires_in: number;
    };
  };

  if (tokenData.status !== 0) {
    logger.error("Withings token refresh failed");
    throw new Error(`Failed to refresh Withings token: ${tokenData.status}`);
  }

  logger.info("Token refresh completed successfully");

  return {
    accessToken: tokenData.body.access_token,
    refreshToken: tokenData.body.refresh_token,
    expiresIn: tokenData.body.expires_in,
    userId: tokenData.body.userid,
  };
}
