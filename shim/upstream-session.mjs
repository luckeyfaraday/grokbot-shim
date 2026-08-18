import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SESSION_HELPER = path.join(ROOT, "shim", "read-native-session.py");
const SESSION_VENV_PYTHON = path.join(ROOT, "state", "native-session-venv", "bin", "python");
const CURSOR_OAUTH_CLIENT_ID = "OzaBXLClY5CAGxNzUhQ2vlknpi07tGuE";
const SESSION_CACHE_MS = 5 * 60 * 1000;
const CHECKSUM_PREFIX_LENGTH = 8;

export const NATIVE_GROKBOT_UPSTREAM = "https://api2.cursor.sh";

let cachedSession;
let sessionRefresh;

export const NATIVE_PLUGIN_PATHS = new Set([
  "/aiserver.v1.DashboardService/GetEffectiveUserPlugins",
  "/aiserver.v1.DashboardService/ListUserPluginInstalls",
  "/aiserver.v1.DashboardService/InstallUserPlugin",
  "/aiserver.v1.DashboardService/UpdateUserPluginInstall",
  "/aiserver.v1.DashboardService/UninstallUserPlugin",
  "/aiserver.v1.DashboardService/GetAvailableMcpServers",
  "/aiserver.v1.DashboardService/GetMcpConfig",
  "/aiserver.v1.DashboardService/SetMcpConfig",
  "/aiserver.v1.DashboardService/GetPluginMcpConfig",
  "/aiserver.v1.DashboardService/ListSandMcpTools",
  "/aiserver.v1.DashboardService/ExecuteSandMcpTool",
  "/aiserver.v1.DashboardService/CheckHttpMcpStatus",
  "/aiserver.v1.DashboardService/CompleteMcpOAuth",
  "/aiserver.v1.DashboardService/ValidateMcpOAuthTokens",
  "/aiserver.v1.DashboardService/DeleteMcpOAuthToken",
  "/aiserver.v1.DashboardService/RenameMcpOAuthAccount",
  "/aiserver.v1.DashboardService/DeleteMcpOAuthAccount",
]);

export function shouldUseNativePluginBackend(pathname, env = process.env) {
  return env.PLUGIN_BACKEND !== "local" && NATIVE_PLUGIN_PATHS.has(pathname);
}

function nativeProfile(env) {
  return path.resolve(
    String(env.GROKBOT_PROFILE ?? path.join(os.homedir(), ".config", "Grok Bot")),
  );
}

async function readNativeSecrets(env) {
  let stdout;
  const python =
    env.GROKBOT_SESSION_PYTHON ??
    ((await fsExists(SESSION_VENV_PYTHON)) ? SESSION_VENV_PYTHON : "python3");
  try {
    ({ stdout } = await execFileAsync(python, [SESSION_HELPER, nativeProfile(env)], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024,
    }));
  } catch (error) {
    const detail = String(error?.stderr ?? error?.message ?? error).trim().slice(0, 300);
    throw new Error(`signed-in Grok Bot session unavailable${detail ? `: ${detail}` : ""}`);
  }
  const parsed = JSON.parse(stdout);
  if (!parsed.refreshToken || !parsed.machineId) {
    throw new Error("signed-in Grok Bot session is missing its refresh token or machine id");
  }
  return parsed;
}

async function fsExists(target) {
  try {
    await access(target);
    return true;
  } catch {
    return false;
  }
}

async function refreshNativeSession(env) {
  const native = await readNativeSecrets(env);
  const response = await fetch(`${NATIVE_GROKBOT_UPSTREAM}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      client_id: CURSOR_OAUTH_CLIENT_ID,
      grant_type: "refresh_token",
      refresh_token: native.refreshToken,
    }),
    signal: AbortSignal.timeout(20_000),
  });
  let body = {};
  try {
    body = await response.json();
  } catch {
    // The bounded status below is enough; never include an upstream body here.
  }
  if (!response.ok || typeof body.access_token !== "string" || !body.access_token) {
    throw new Error(`Grok Bot session refresh failed with HTTP ${response.status}`);
  }
  if (body.shouldLogout === true) throw new Error("Grok Bot's saved session has been signed out");
  return {
    accessToken: body.access_token,
    machineId: native.machineId,
    expiresAt: Date.now() + SESSION_CACHE_MS,
  };
}

export async function nativePluginSession(env = process.env) {
  if (cachedSession?.expiresAt > Date.now()) return cachedSession;
  if (!sessionRefresh) {
    sessionRefresh = refreshNativeSession(env).finally(() => {
      sessionRefresh = undefined;
    });
  }
  cachedSession = await sessionRefresh;
  return cachedSession;
}

export function nativeSessionChecksum(sentChecksum, machineId) {
  if (typeof sentChecksum !== "string" || sentChecksum.length < CHECKSUM_PREFIX_LENGTH) {
    return undefined;
  }
  return sentChecksum.slice(0, CHECKSUM_PREFIX_LENGTH) + machineId;
}

export function clearNativeSessionCache() {
  cachedSession = undefined;
}
