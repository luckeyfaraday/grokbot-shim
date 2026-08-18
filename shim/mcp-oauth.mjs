import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STATE_FILE = path.join(ROOT, "state", "mcp-oauth.json");
const DEFAULT_ACCOUNT_KEY = "default";
const PENDING_TTL_MS = 20 * 60 * 1000;
const EXPIRY_SKEW_MS = 60 * 1000;

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJsonAtomic(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const next = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(next, JSON.stringify(value, null, 2), { mode: 0o600 });
  fs.renameSync(next, file);
}

function loadState() {
  const state = readJson(STATE_FILE, { tokens: {}, pending: {} });
  if (!state.tokens || typeof state.tokens !== "object") state.tokens = {};
  if (!state.pending || typeof state.pending !== "object") state.pending = {};
  const cutoff = Date.now() - PENDING_TTL_MS;
  for (const [id, record] of Object.entries(state.pending)) {
    if (!record?.createdAt || record.createdAt < cutoff) delete state.pending[id];
  }
  return state;
}

function saveState(state) {
  writeJsonAtomic(STATE_FILE, state);
}

function accountKey(value) {
  return String(value ?? "").trim().toLocaleLowerCase() || DEFAULT_ACCOUNT_KEY;
}

function tokenKey(serverUrl, key) {
  return `${String(serverUrl).trim()}\n${accountKey(key)}`;
}

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function protectedResourceMetadataUrl(serverUrl) {
  const url = new URL(serverUrl);
  const suffix = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
  return `${url.origin}/.well-known/oauth-protected-resource${suffix}`;
}

function authorizationMetadataUrl(issuer) {
  const url = new URL(issuer);
  const suffix = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
  return `${url.origin}/.well-known/oauth-authorization-server${suffix}`;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(10_000) });
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`${new URL(url).hostname} returned non-JSON OAuth metadata`);
  }
  if (!response.ok) {
    throw new Error(`${new URL(url).hostname} returned OAuth HTTP ${response.status}`);
  }
  return body;
}

async function discoverOauth(serverUrl) {
  const resource = await fetchJson(protectedResourceMetadataUrl(serverUrl));
  const issuer = resource.authorization_servers?.[0];
  if (!issuer) throw new Error("the connector did not advertise an OAuth authorization server");
  let authorization;
  try {
    authorization = await fetchJson(authorizationMetadataUrl(issuer));
  } catch {
    const url = new URL(issuer);
    authorization = await fetchJson(`${url.origin}/.well-known/openid-configuration`);
  }
  if (!authorization.authorization_endpoint || !authorization.token_endpoint) {
    throw new Error("the connector's OAuth metadata is missing authorization or token endpoints");
  }
  return { resource, authorization, issuer };
}

function splitScopes(value) {
  return String(value ?? "")
    .split(/[\s,]+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
}

function oauthCredentials(serverUrl, issuer, resource, env = process.env) {
  const server = new URL(serverUrl);
  const auth = new URL(issuer);
  const google = auth.hostname === "accounts.google.com" || server.hostname.endsWith(".googleapis.com");
  const clientId = String(
    google ? env.MCP_GOOGLE_CLIENT_ID ?? env.MCP_OAUTH_CLIENT_ID ?? "" : env.MCP_OAUTH_CLIENT_ID ?? "",
  ).trim();
  const clientSecret = String(
    google
      ? env.MCP_GOOGLE_CLIENT_SECRET ?? env.MCP_OAUTH_CLIENT_SECRET ?? ""
      : env.MCP_OAUTH_CLIENT_SECRET ?? "",
  ).trim();
  const configuredScopes = splitScopes(
    google ? env.MCP_GOOGLE_SCOPES ?? env.MCP_OAUTH_SCOPES : env.MCP_OAUTH_SCOPES,
  );
  const supported = Array.isArray(resource.scopes_supported) ? resource.scopes_supported.map(String) : [];
  const scopes =
    configuredScopes.length > 0
      ? configuredScopes
      : google && server.hostname === "gmailmcp.googleapis.com"
        ? ["https://www.googleapis.com/auth/gmail.modify"]
        : supported;
  return { clientId, clientSecret, scopes, google };
}

async function tokenRequest(endpoint, params) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams(params),
    signal: AbortSignal.timeout(20_000),
  });
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = {};
  }
  if (!response.ok || !body.access_token) {
    const detail = String(body.error_description ?? body.error ?? `HTTP ${response.status}`).slice(0, 300);
    throw new Error(`OAuth token exchange failed: ${detail}`);
  }
  return body;
}

async function refreshRecord(serverUrl, key, record, env) {
  if (!record.refreshToken || !record.tokenEndpoint) return null;
  const credentials = oauthCredentials(serverUrl, record.issuer, { scopes_supported: record.scopes ?? [] }, env);
  if (!credentials.clientId) return null;
  const params = {
    grant_type: "refresh_token",
    refresh_token: record.refreshToken,
    client_id: credentials.clientId,
  };
  if (credentials.clientSecret) params.client_secret = credentials.clientSecret;
  try {
    const token = await tokenRequest(record.tokenEndpoint, params);
    return {
      ...record,
      accessToken: token.access_token,
      refreshToken: token.refresh_token ?? record.refreshToken,
      expiresAt: Date.now() + Number(token.expires_in ?? 3600) * 1000,
      scope: token.scope ?? record.scope,
      tokenType: token.token_type ?? record.tokenType ?? "Bearer",
      updatedAt: Date.now(),
    };
  } catch {
    return null;
  }
}

export async function mcpAccessToken(serverUrl, key = DEFAULT_ACCOUNT_KEY, env = process.env) {
  const state = loadState();
  const id = tokenKey(serverUrl, key);
  let record = state.tokens[id];
  if (!record) return null;
  if (record.accessToken && record.expiresAt > Date.now() + EXPIRY_SKEW_MS) return record.accessToken;
  record = await refreshRecord(serverUrl, key, record, env);
  if (!record) {
    delete state.tokens[id];
    saveState(state);
    return null;
  }
  state.tokens[id] = record;
  saveState(state);
  return record.accessToken;
}

export async function hasMcpAccessToken(serverUrl, key = DEFAULT_ACCOUNT_KEY, env = process.env) {
  return Boolean(await mcpAccessToken(serverUrl, key, env));
}

export function removeMcpAccessToken(serverUrl, key = DEFAULT_ACCOUNT_KEY) {
  const state = loadState();
  delete state.tokens[tokenKey(serverUrl, key)];
  saveState(state);
}

export async function beginMcpOauth(row, request, env = process.env) {
  const key = accountKey(request.accountKey);
  if (request.forceReauth) removeMcpAccessToken(row.config.url, key);
  const existing = await mcpAccessToken(row.config.url, key, env);
  if (existing && !request.forceReauth) {
    return { hasValidToken: true, isAvailable: true, requiresAuth: false };
  }

  let discovered;
  try {
    discovered = await discoverOauth(row.config.url);
  } catch (error) {
    return {
      hasValidToken: false,
      isAvailable: false,
      requiresAuth: false,
      error: `OAuth discovery failed: ${error?.message ?? error}`,
    };
  }
  const credentials = oauthCredentials(
    row.config.url,
    discovered.issuer,
    discovered.resource,
    env,
  );
  if (!credentials.clientId) {
    const variable = credentials.google ? "MCP_GOOGLE_CLIENT_ID" : "MCP_OAUTH_CLIENT_ID";
    return {
      hasValidToken: false,
      isAvailable: true,
      requiresAuth: true,
      error: `Set ${variable} in .env and restart the shim to enable this sign-in.`,
    };
  }
  if (!request.oauthRedirectUri) {
    return {
      hasValidToken: false,
      isAvailable: true,
      requiresAuth: true,
      error: "The desktop did not provide an OAuth callback URL.",
    };
  }

  const verifier = base64Url(crypto.randomBytes(48));
  const challenge = base64Url(crypto.createHash("sha256").update(verifier).digest());
  const stateId = crypto.randomUUID();
  const pending = {
    serverId: row.id,
    serverUrl: row.config.url,
    accountKey: key,
    redirectUri: request.oauthRedirectUri,
    postAuthReturnUrl: request.postAuthReturnUrl ?? "",
    codeVerifier: verifier,
    tokenEndpoint: discovered.authorization.token_endpoint,
    issuer: discovered.issuer,
    scopes: credentials.scopes,
    createdAt: Date.now(),
  };
  const state = loadState();
  state.pending[stateId] = pending;
  saveState(state);

  const authUrl = new URL(discovered.authorization.authorization_endpoint);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", credentials.clientId);
  authUrl.searchParams.set("redirect_uri", pending.redirectUri);
  authUrl.searchParams.set("state", stateId);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  if (credentials.scopes.length > 0) authUrl.searchParams.set("scope", credentials.scopes.join(" "));
  if (credentials.google) {
    authUrl.searchParams.set("access_type", "offline");
    authUrl.searchParams.set("prompt", "consent");
    authUrl.searchParams.set("include_granted_scopes", "true");
  } else {
    authUrl.searchParams.set("resource", discovered.resource.resource ?? row.config.url);
  }
  return {
    hasValidToken: false,
    isAvailable: true,
    requiresAuth: true,
    authUrl: authUrl.toString(),
  };
}

export async function completeMcpOauth(request, env = process.env) {
  const state = loadState();
  const pending = state.pending[request.stateId];
  if (!pending || Date.now() - pending.createdAt > PENDING_TTL_MS) {
    throw new Error("the MCP OAuth state is unknown or expired");
  }
  const credentials = oauthCredentials(
    pending.serverUrl,
    pending.issuer,
    { scopes_supported: pending.scopes },
    env,
  );
  if (!credentials.clientId) throw new Error("the configured MCP OAuth client id is missing");
  const params = {
    grant_type: "authorization_code",
    code: request.authorizationCode,
    redirect_uri: pending.redirectUri,
    client_id: credentials.clientId,
    code_verifier: pending.codeVerifier,
  };
  if (credentials.clientSecret) params.client_secret = credentials.clientSecret;
  const token = await tokenRequest(pending.tokenEndpoint, params);
  state.tokens[tokenKey(pending.serverUrl, pending.accountKey)] = {
    accessToken: token.access_token,
    refreshToken: token.refresh_token ?? "",
    expiresAt: Date.now() + Number(token.expires_in ?? 3600) * 1000,
    tokenType: token.token_type ?? "Bearer",
    scope: token.scope ?? pending.scopes.join(" "),
    tokenEndpoint: pending.tokenEndpoint,
    issuer: pending.issuer,
    scopes: pending.scopes,
    updatedAt: Date.now(),
  };
  delete state.pending[request.stateId];
  saveState(state);
  return { postAuthReturnUrl: pending.postAuthReturnUrl, accountKey: pending.accountKey };
}

async function remoteMcpRpc(serverUrl, method, params, accessToken) {
  const response = await fetch(serverUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: crypto.randomUUID(), method, params }),
    signal: AbortSignal.timeout(60_000),
  });
  const text = await response.text();
  if (response.status === 401 || response.status === 403) {
    const error = new Error("MCP authentication is required");
    error.code = "AUTH_REQUIRED";
    throw error;
  }
  if (!response.ok) throw new Error(`MCP server returned HTTP ${response.status}`);
  let message;
  try {
    message = JSON.parse(text);
  } catch {
    throw new Error("MCP server returned a non-JSON response");
  }
  if (message.error) throw new Error(String(message.error.message ?? "MCP request failed"));
  return message.result ?? {};
}

export async function listRemoteMcpTools(row, env = process.env) {
  const accessToken = await mcpAccessToken(row.config.url, DEFAULT_ACCOUNT_KEY, env);
  if (!accessToken) return { status: "needsAuth", tools: [] };
  try {
    const result = await remoteMcpRpc(row.config.url, "tools/list", {}, accessToken);
    return { status: "connected", tools: Array.isArray(result.tools) ? result.tools : [] };
  } catch (error) {
    if (error?.code === "AUTH_REQUIRED") {
      removeMcpAccessToken(row.config.url, DEFAULT_ACCOUNT_KEY);
      return { status: "needsAuth", tools: [] };
    }
    return { status: "error", tools: [], error: String(error?.message ?? error) };
  }
}

export async function executeRemoteMcpTool(row, toolName, args, env = process.env) {
  const accessToken = await mcpAccessToken(row.config.url, DEFAULT_ACCOUNT_KEY, env);
  if (!accessToken) throw new Error("MCP authentication is required");
  return remoteMcpRpc(row.config.url, "tools/call", { name: toolName, arguments: args }, accessToken);
}
