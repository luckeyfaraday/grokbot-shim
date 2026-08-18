import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import protobuf from "protobufjs";

import {
  beginMcpOauth,
  completeMcpOauth,
  executeRemoteMcpTool,
  hasMcpAccessToken,
  listRemoteMcpTools,
  removeMcpAccessToken,
} from "./mcp-oauth.mjs";
import { jsonToStruct, jsonToValue, structToJson } from "./struct.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STATE_DIR = path.join(ROOT, "state");
const CATALOG_CACHE_FILE = path.join(STATE_DIR, "marketplace-catalog.json");
const INSTALLS_FILE = path.join(STATE_DIR, "plugin-installs.json");
const PUBLIC_MARKETPLACE_URL = "https://cursor.com/marketplace";
const CATALOG_TTL_MS = 15 * 60 * 1000;

const protoRoot = protobuf.loadSync(path.join(ROOT, "shim", "marketplace.proto"));

const types = Object.fromEntries(
  [
    "ListMarketplacePluginsRequest",
    "ListMarketplacePluginsResponse",
    "ListMarketplacesResponse",
    "GetEffectiveUserPluginsResponse",
    "ListUserPluginInstallsResponse",
    "InstallUserPluginRequest",
    "InstallUserPluginResponse",
    "UpdateUserPluginInstallRequest",
    "UpdateUserPluginInstallResponse",
    "UninstallUserPluginRequest",
    "UninstallUserPluginResponse",
    "GetAvailableMcpServersResponse",
    "GetMcpConfigResponse",
    "GetPluginMcpConfigRequest",
    "GetPluginMcpConfigResponse",
    "ListSandMcpToolsRequest",
    "ListSandMcpToolsResponse",
    "ExecuteSandMcpToolRequest",
    "ExecuteSandMcpToolResponse",
    "CheckHttpMcpStatusRequest",
    "CheckHttpMcpStatusResponse",
    "CompleteMcpOAuthRequest",
    "CompleteMcpOAuthResponse",
    "ValidateMcpOAuthTokensRequest",
    "ValidateMcpOAuthTokensResponse",
    "DeleteMcpOAuthTokenRequest",
    "DeleteMcpOAuthTokenResponse",
  ].map((name) => [name, protoRoot.lookupType(`aiserver.v1.${name}`)]),
);

export const MARKETPLACE_READ_PATHS = new Set([
  "/aiserver.v1.DashboardService/ListMarketplaces",
  "/aiserver.v1.DashboardService/ListMarketplacePlugins",
  "/aiserver.v1.DashboardService/GetEffectiveUserPlugins",
]);

export const LOCAL_MARKETPLACE_PATHS = new Set([
  ...MARKETPLACE_READ_PATHS,
  "/aiserver.v1.DashboardService/ListUserPluginInstalls",
  "/aiserver.v1.DashboardService/InstallUserPlugin",
  "/aiserver.v1.DashboardService/UpdateUserPluginInstall",
  "/aiserver.v1.DashboardService/UninstallUserPlugin",
  "/aiserver.v1.DashboardService/GetAvailableMcpServers",
  "/aiserver.v1.DashboardService/GetMcpConfig",
  "/aiserver.v1.DashboardService/GetPluginMcpConfig",
  "/aiserver.v1.DashboardService/ListSandMcpTools",
  "/aiserver.v1.DashboardService/ExecuteSandMcpTool",
  "/aiserver.v1.DashboardService/CheckHttpMcpStatus",
  "/aiserver.v1.DashboardService/CompleteMcpOAuth",
  "/aiserver.v1.DashboardService/ValidateMcpOAuthTokens",
  "/aiserver.v1.DashboardService/DeleteMcpOAuthToken",
]);

// Backwards-compatible name used by the first proxy-only implementation.
export const MARKETPLACE_PATHS = MARKETPLACE_READ_PATHS;

export function marketplaceProxyEnabled(env = process.env) {
  return env.PLUGIN_PROXY === "1" && env.PLUGIN_MARKETPLACE === "private";
}

export function publicMarketplaceEnabled(env = process.env) {
  return !["off", "0", "private"].includes(env.PLUGIN_MARKETPLACE ?? "public");
}

export function shouldProxyMarketplace(pathname, env = process.env) {
  return marketplaceProxyEnabled(env) && MARKETPLACE_READ_PATHS.has(pathname);
}

export function shouldServePublicMarketplace(pathname, env = process.env) {
  return publicMarketplaceEnabled(env) && LOCAL_MARKETPLACE_PATHS.has(pathname);
}

// The app authenticates against the shim with a token the shim itself minted,
// which upstream has no reason to accept. UPSTREAM_TOKEN replaces it with a
// real session for forwarded private/team marketplace reads only.
export function marketplaceAuthOverride(env = process.env) {
  const token = (env.UPSTREAM_TOKEN ?? "").trim();
  if (!token) return undefined;
  return token.toLowerCase().startsWith("bearer ") ? token : `Bearer ${token}`;
}

// createCursorChecksum(machineId) builds `base64url(<6 obfuscated timestamp
// bytes>) + machineId`, and six bytes is exactly eight base64 characters.
const CHECKSUM_PREFIX_LENGTH = 8;

export function marketplaceChecksumOverride(checksum, env = process.env) {
  const machineId = (env.UPSTREAM_MACHINE_ID ?? "").trim();
  if (!machineId) return undefined;
  if (typeof checksum !== "string" || checksum.length < CHECKSUM_PREFIX_LENGTH) return undefined;
  return checksum.slice(0, CHECKSUM_PREFIX_LENGTH) + machineId;
}

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

function extractBalancedArray(text, start) {
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') quoted = false;
      continue;
    }
    if (char === '"') quoted = true;
    else if (char === "[") depth++;
    else if (char === "]" && --depth === 0) return text.slice(start, i + 1);
  }
  throw new Error("the public marketplace payload ended inside initialPlugins");
}

export function parsePublicMarketplaceHtml(html) {
  const scripts = html.matchAll(/<script>self\.__next_f\.push\((\[.*?\])\)<\/script>/gs);
  for (const match of scripts) {
    let packet;
    try {
      packet = JSON.parse(match[1]);
    } catch {
      continue;
    }
    const record = packet?.[1];
    if (typeof record !== "string") continue;
    const marker = '"initialPlugins":';
    const markerAt = record.indexOf(marker);
    if (markerAt === -1) continue;
    const arrayAt = record.indexOf("[", markerAt + marker.length);
    if (arrayAt === -1) continue;
    const plugins = JSON.parse(extractBalancedArray(record, arrayAt));
    if (!Array.isArray(plugins) || plugins.length === 0) continue;
    return plugins;
  }
  throw new Error("initialPlugins was not present in the public marketplace page");
}

let catalogMemory = readJson(CATALOG_CACHE_FILE, null);
let catalogRefresh;

async function fetchPublicCatalog(env = process.env) {
  const url = env.PUBLIC_MARKETPLACE_URL ?? PUBLIC_MARKETPLACE_URL;
  const response = await fetch(url, {
    headers: { "user-agent": "grokbot-shim/1.0 marketplace bridge" },
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`${url} returned ${response.status}`);
  const plugins = parsePublicMarketplaceHtml(await response.text());
  const next = { fetchedAt: Date.now(), source: url, plugins };
  writeJsonAtomic(CATALOG_CACHE_FILE, next);
  catalogMemory = next;
  return next;
}

export async function loadPublicCatalog(env = process.env) {
  const fresh = catalogMemory && Date.now() - Number(catalogMemory.fetchedAt ?? 0) < CATALOG_TTL_MS;
  if (fresh && Array.isArray(catalogMemory.plugins) && catalogMemory.plugins.length > 0) {
    return catalogMemory.plugins;
  }
  if (!catalogRefresh) {
    catalogRefresh = fetchPublicCatalog(env).finally(() => {
      catalogRefresh = undefined;
    });
  }
  try {
    return (await catalogRefresh).plugins;
  } catch (error) {
    if (Array.isArray(catalogMemory?.plugins) && catalogMemory.plugins.length > 0) {
      return catalogMemory.plugins;
    }
    throw error;
  }
}

function marketplaceKey(marketplace) {
  return String(marketplace?.id ?? marketplace?.name ?? "");
}

function marketplacesFrom(plugins) {
  const seen = new Map();
  for (const plugin of plugins) {
    if (!plugin.marketplace) continue;
    const key = marketplaceKey(plugin.marketplace);
    if (key && !seen.has(key)) seen.set(key, plugin.marketplace);
  }
  return [...seen.values()];
}

function pluginForWire(plugin) {
  return {
    ...plugin,
    variables: jsonToStruct(plugin.variables ?? {}),
  };
}

function encode(typeName, value) {
  const type = types[typeName];
  const message = type.fromObject(value);
  const error = type.verify(message);
  if (error) throw new Error(`invalid ${typeName}: ${error}`);
  return Buffer.from(type.encode(message).finish());
}

function decode(typeName, bytes) {
  return types[typeName].decode(bytes);
}

function longString(value) {
  return value == null ? "0" : String(value);
}

function loadInstalls() {
  const state = readJson(INSTALLS_FILE, { installs: {} });
  if (!state.installs || typeof state.installs !== "object") state.installs = {};
  return state;
}

function saveInstalls(state) {
  writeJsonAtomic(INSTALLS_FILE, state);
}

function installMessage(record, plugin) {
  return {
    userId: 1,
    pluginId: plugin.id,
    isEnabled: record.enabled !== false,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    plugin: pluginForWire(plugin),
    ...(record.pinnedGitRef ? { pinnedGitRef: record.pinnedGitRef } : {}),
  };
}

function effectiveMessage(record, plugin) {
  return {
    plugin: pluginForWire(plugin),
    isTeamRequired: false,
    isEnabled: record.enabled !== false,
    ...(record.pinnedGitRef ? { pinnedGitRef: record.pinnedGitRef } : {}),
    configuredVariables: jsonToStruct(record.variables ?? {}),
    hasTeamConfiguredVariables: false,
    installMode: "EFFECTIVE_PLUGIN_INSTALL_MODE_USER",
  };
}

function findPlugin(plugins, id) {
  return plugins.find((plugin) => String(plugin.id) === String(id));
}

function fieldPresent(message, name) {
  return Object.prototype.hasOwnProperty.call(message, name);
}

function searchPlugins(plugins, request) {
  const search = String(request.search ?? "").trim().toLocaleLowerCase();
  const tags = (request.tags ?? []).map((tag) => String(tag).toLocaleLowerCase());
  return plugins.filter((plugin) => {
    if (fieldPresent(request, "marketplaceId") && longString(request.marketplaceId) !== String(plugin.marketplaceId)) {
      return false;
    }
    if (fieldPresent(request, "publisherId") && longString(request.publisherId) !== String(plugin.publisherId)) {
      return false;
    }
    const pluginTags = (plugin.tags ?? []).map((tag) => String(tag).toLocaleLowerCase());
    if (tags.length > 0 && !tags.every((tag) => pluginTags.includes(tag))) return false;
    if (!search) return true;
    return [
      plugin.name,
      plugin.displayName,
      plugin.description,
      plugin.publisher?.name,
      plugin.publisher?.displayName,
      ...(plugin.tags ?? []),
      ...(plugin.curatedCategoryKeys ?? []),
    ].some((value) => String(value ?? "").toLocaleLowerCase().includes(search));
  });
}

function rawGithubUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.hostname !== "github.com") return null;
    const parts = parsed.pathname.split("/").filter(Boolean);
    if (parts.length < 5 || parts[2] !== "blob") return null;
    const [owner, repo, , ref, ...rest] = parts;
    return `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${rest.join("/")}`;
  } catch {
    return null;
  }
}

function rawPluginFileUrl(plugin, relativePath) {
  try {
    const parsed = new URL(plugin.gitUrl);
    if (parsed.hostname !== "github.com") return null;
    const [owner, repoWithSuffix] = parsed.pathname.split("/").filter(Boolean);
    if (!owner || !repoWithSuffix || !plugin.gitRef) return null;
    const repo = repoWithSuffix.replace(/\.git$/i, "");
    const gitPath = String(plugin.gitPath ?? "").replace(/^\.\/?|\/$/g, "");
    const sourcePath = String(relativePath).replace(/^\.\//, "");
    const alreadyRooted = gitPath && (sourcePath === gitPath || sourcePath.startsWith(`${gitPath}/`));
    const filePath = [alreadyRooted ? "" : gitPath, sourcePath].filter(Boolean).join("/");
    return `https://raw.githubusercontent.com/${owner}/${repo}/${plugin.gitRef}/${filePath}`;
  } catch {
    return null;
  }
}

const mcpConfigCache = new Map();

async function loadPluginMcpConfig(plugin) {
  const key = String(plugin.id);
  if (mcpConfigCache.has(key)) return mcpConfigCache.get(key);
  let config = { mcpServers: {} };
  const candidates = new Set();
  for (const descriptor of plugin.mcpServers ?? []) {
    const sourceUrl = rawGithubUrl(descriptor.sourceUrl ?? "");
    if (sourceUrl) candidates.add(sourceUrl);
    if (descriptor.sourcePath) {
      const pathUrl = rawPluginFileUrl(plugin, descriptor.sourcePath);
      if (pathUrl) candidates.add(pathUrl);
    }
  }
  // Some public rows omit source_path/source_url even though the pinned repo
  // carries the conventional plugin-level MCP manifest.
  for (const file of ["mcp.json", ".mcp.json"]) {
    const url = rawPluginFileUrl(plugin, file);
    if (url) candidates.add(url);
  }
  for (const url of candidates) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      if (!response.ok) continue;
      const parsed = JSON.parse(await response.text());
      const servers = parsed?.mcpServers ?? parsed;
      if (servers && typeof servers === "object" && !Array.isArray(servers)) {
        config = { mcpServers: servers };
        break;
      }
    } catch {
      // A catalog entry can still provide skills, rules, and agents when its
      // MCP source is unavailable, so keep the empty MCP portion.
    }
  }
  mcpConfigCache.set(key, config);
  return config;
}

function substituteVariables(value, variables) {
  if (typeof value === "string") {
    return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (whole, key) =>
      Object.prototype.hasOwnProperty.call(variables, key) ? String(variables[key]) : whole,
    );
  }
  if (Array.isArray(value)) return value.map((item) => substituteVariables(item, variables));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, substituteVariables(item, variables)]),
    );
  }
  return value;
}

function serverId(pluginId, name) {
  let hash = 2166136261;
  for (const char of `${pluginId}:${name}`) {
    hash ^= char.codePointAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 1) || 1;
}

async function installedMcpServers(plugins, state) {
  const rows = [];
  for (const [pluginId, record] of Object.entries(state.installs)) {
    const plugin = findPlugin(plugins, pluginId);
    if (!plugin || record.enabled === false) continue;
    const raw = await loadPluginMcpConfig(plugin);
    const config = substituteVariables(raw, record.variables ?? {});
    for (const [name, server] of Object.entries(config.mcpServers ?? {})) {
      if (!server || typeof server !== "object") continue;
      const id = serverId(pluginId, name);
      const type = String(server.type ?? server.transport ?? (server.command ? "stdio" : "http"));
      rows.push({ plugin, pluginId, name, id, type, config: server });
    }
  }
  return rows;
}

function remoteToolForWire(row, tool) {
  const toolName = String(tool?.name ?? "");
  return {
    name: `${row.name}-${toolName}`,
    providerIdentifier: `plugin:${row.pluginId}:${row.name}`,
    toolName,
    description: String(tool?.description ?? ""),
    inputSchema: jsonToValue(tool?.inputSchema ?? { type: "object" }),
  };
}

function remoteResultForWire(result) {
  const content = (Array.isArray(result?.content) ? result.content : []).map((item) => {
    if (item?.type === "text") return { text: { text: String(item.text ?? "") } };
    if (item?.type === "image") {
      return {
        image: {
          data: Buffer.from(String(item.data ?? ""), "base64"),
          mimeType: String(item.mimeType ?? "application/octet-stream"),
        },
      };
    }
    return { text: { text: JSON.stringify(item ?? null) } };
  });
  return {
    success: {
      content,
      isError: result?.isError === true,
      ...(result?.structuredContent && typeof result.structuredContent === "object"
        ? { structuredContent: jsonToStruct(result.structuredContent) }
        : {}),
    },
  };
}

function remoteErrorForWire(error) {
  return { error: { error: String(error?.message ?? error).slice(0, 1000) } };
}

export function availableMcpServerMessage(row, hasToken = false) {
  const { pluginId, name, id, type, config } = row;
  const identifier = `plugin:${pluginId}:${name}`;
  const http = type.toLocaleLowerCase() !== "stdio" && Boolean(config.url);
  return {
    id,
    name,
    isTeamServer: false,
    enabled: true,
    type,
    ...(config.command ? { command: config.command } : {}),
    ...(Array.isArray(config.args) ? { args: config.args.map(String) } : {}),
    ...(config.url ? { url: config.url } : {}),
    pluginId,
    isUnseen: false,
    ...(http ? { userHasAccessToken: hasToken } : {}),
    isRequired: false,
    managedByTeamPluginPolicy: false,
    disabledByTeamAdminPolicy: false,
    serverIdentifier: identifier,
    ...(http
      ? {
          accounts: [
            {
              accountKey: "default",
              serverIdentifier: identifier,
              userHasAccessToken: hasToken,
            },
          ],
        }
      : {}),
  };
}

export async function publicMarketplaceResponse(pathname, body, env = process.env) {
  const plugins = await loadPublicCatalog(env);
  const state = loadInstalls();
  const now = Date.now();

  switch (pathname) {
    case "/aiserver.v1.DashboardService/ListMarketplacePlugins": {
      const request = decode("ListMarketplacePluginsRequest", body);
      const matched = searchPlugins(plugins, request);
      const offset = Math.max(0, Number.parseInt(String(request.pageToken ?? "0"), 10) || 0);
      const size = request.pageSize > 0 ? Math.min(request.pageSize, 500) : 500;
      const page = matched.slice(offset, offset + size);
      const hasMore = offset + page.length < matched.length;
      return {
        bytes: encode("ListMarketplacePluginsResponse", {
          plugins: page.map(pluginForWire),
          ...(hasMore ? { nextPageToken: String(offset + page.length) } : {}),
          hasMore,
        }),
        label: `public marketplace ${page.length}/${matched.length} plugins`,
      };
    }
    case "/aiserver.v1.DashboardService/ListMarketplaces":
      return {
        bytes: encode("ListMarketplacesResponse", { marketplaces: marketplacesFrom(plugins) }),
        label: "public marketplaces",
      };
    case "/aiserver.v1.DashboardService/GetEffectiveUserPlugins": {
      const effective = Object.entries(state.installs).flatMap(([id, record]) => {
        const plugin = findPlugin(plugins, id);
        return plugin ? [effectiveMessage(record, plugin)] : [];
      });
      return {
        bytes: encode("GetEffectiveUserPluginsResponse", {
          plugins: effective,
          marketplaces: marketplacesFrom(plugins),
        }),
        label: `local effective plugins ${effective.length}`,
      };
    }
    case "/aiserver.v1.DashboardService/ListUserPluginInstalls": {
      const installs = Object.entries(state.installs).flatMap(([id, record]) => {
        const plugin = findPlugin(plugins, id);
        return plugin ? [installMessage(record, plugin)] : [];
      });
      return {
        bytes: encode("ListUserPluginInstallsResponse", { installs }),
        label: `local plugin installs ${installs.length}`,
      };
    }
    case "/aiserver.v1.DashboardService/InstallUserPlugin": {
      const request = decode("InstallUserPluginRequest", body);
      const id = longString(request.pluginId);
      const plugin = findPlugin(plugins, id);
      if (!plugin) throw new Error(`unknown public marketplace plugin ${id}`);
      const previous = state.installs[id];
      const record = {
        enabled: true,
        createdAt: previous?.createdAt ?? now,
        updatedAt: now,
        variables: structToJson(request.variables) ?? previous?.variables ?? {},
        ...(fieldPresent(request, "pinnedGitRef") ? { pinnedGitRef: request.pinnedGitRef } : {}),
      };
      state.installs[id] = record;
      saveInstalls(state);
      return {
        bytes: encode("InstallUserPluginResponse", { install: installMessage(record, plugin) }),
        label: `installed plugin ${plugin.name}`,
      };
    }
    case "/aiserver.v1.DashboardService/UpdateUserPluginInstall": {
      const request = decode("UpdateUserPluginInstallRequest", body);
      const id = longString(request.pluginId);
      const plugin = findPlugin(plugins, id);
      if (!plugin) throw new Error(`unknown public marketplace plugin ${id}`);
      const previous = state.installs[id] ?? { createdAt: now, variables: {} };
      const record = {
        ...previous,
        enabled: fieldPresent(request, "isEnabled") ? request.isEnabled : previous.enabled ?? true,
        updatedAt: now,
        variables: structToJson(request.variables) ?? previous.variables ?? {},
        ...(fieldPresent(request, "pinnedGitRef") ? { pinnedGitRef: request.pinnedGitRef } : {}),
      };
      state.installs[id] = record;
      saveInstalls(state);
      return {
        bytes: encode("UpdateUserPluginInstallResponse", { install: installMessage(record, plugin) }),
        label: `updated plugin ${plugin.name}`,
      };
    }
    case "/aiserver.v1.DashboardService/UninstallUserPlugin": {
      const request = decode("UninstallUserPluginRequest", body);
      const id = longString(request.pluginId);
      const success = Object.prototype.hasOwnProperty.call(state.installs, id);
      delete state.installs[id];
      saveInstalls(state);
      return {
        bytes: encode("UninstallUserPluginResponse", { success }),
        label: `uninstalled plugin ${id}`,
      };
    }
    case "/aiserver.v1.DashboardService/GetAvailableMcpServers": {
      const rows = await installedMcpServers(plugins, state);
      const servers = await Promise.all(
        rows.map(async (row) => {
          const http = row.type.toLocaleLowerCase() !== "stdio" && Boolean(row.config.url);
          const hasToken = http ? await hasMcpAccessToken(row.config.url, "default", env) : false;
          return availableMcpServerMessage(row, hasToken);
        }),
      );
      return {
        bytes: encode("GetAvailableMcpServersResponse", { servers }),
        label: `local MCP servers ${rows.length}`,
      };
    }
    case "/aiserver.v1.DashboardService/GetMcpConfig": {
      const rows = await installedMcpServers(plugins, state);
      const mcpServers = Object.fromEntries(rows.map((row) => [row.name, row.config]));
      const serverMetadataByName = Object.fromEntries(
        rows.map((row) => [row.name, { pluginId: row.pluginId, serverId: row.id }]),
      );
      return {
        bytes: encode("GetMcpConfigResponse", {
          configJson: JSON.stringify({ mcpServers }),
          serverMetadataByName,
        }),
        label: `local MCP config ${rows.length}`,
      };
    }
    case "/aiserver.v1.DashboardService/GetPluginMcpConfig": {
      const request = decode("GetPluginMcpConfigRequest", body);
      const plugin = findPlugin(plugins, longString(request.pluginId));
      const config = plugin ? await loadPluginMcpConfig(plugin) : { mcpServers: {} };
      return {
        bytes: encode("GetPluginMcpConfigResponse", {
          configJson: JSON.stringify(config),
          commitSha: plugin?.gitRef ?? "",
        }),
        label: `plugin MCP config ${plugin?.name ?? "unknown"}`,
      };
    }
    case "/aiserver.v1.DashboardService/ListSandMcpTools": {
      const request = decode("ListSandMcpToolsRequest", body);
      const requested = new Set(request.serverIdentifiers ?? []);
      const rows = (await installedMcpServers(plugins, state)).filter(
        (row) => row.config.url && (requested.size === 0 || requested.has(`plugin:${row.pluginId}:${row.name}`)),
      );
      const servers = await Promise.all(
        rows.map(async (row) => {
          const identifier = `plugin:${row.pluginId}:${row.name}`;
          const listed = await listRemoteMcpTools(row, env);
          return {
            serverIdentifier: identifier,
            status: listed.status,
            tools: listed.tools.map((tool) => remoteToolForWire(row, tool)),
            accountLabel: "default",
            rowServerIdentifier: identifier,
          };
        }),
      );
      return {
        bytes: encode("ListSandMcpToolsResponse", { servers }),
        label: `remote MCP tools ${servers.length}`,
      };
    }
    case "/aiserver.v1.DashboardService/ExecuteSandMcpTool": {
      const request = decode("ExecuteSandMcpToolRequest", body);
      const rows = await installedMcpServers(plugins, state);
      const row = rows.find(
        (candidate) => `plugin:${candidate.pluginId}:${candidate.name}` === request.serverIdentifier,
      );
      let result;
      if (!row?.config.url) {
        result = remoteErrorForWire(new Error("the requested remote MCP server is not installed"));
      } else {
        const prefix = `${row.name}-`;
        const toolName = request.toolName.startsWith(prefix)
          ? request.toolName.slice(prefix.length)
          : request.toolName;
        try {
          result = remoteResultForWire(
            await executeRemoteMcpTool(row, toolName, structToJson(request.args) ?? {}, env),
          );
        } catch (error) {
          result = remoteErrorForWire(error);
        }
      }
      return {
        bytes: encode("ExecuteSandMcpToolResponse", { result }),
        label: `remote MCP execute ${row?.name ?? "unknown"}`,
      };
    }
    case "/aiserver.v1.DashboardService/CheckHttpMcpStatus": {
      const request = decode("CheckHttpMcpStatusRequest", body);
      const rows = await installedMcpServers(plugins, state);
      const statuses = await Promise.all(
        (request.serverIds ?? []).map(async (id) => {
          const row = rows.find((candidate) => candidate.id === id);
          if (!row?.config.url) {
            return {
              id,
              isAvailable: false,
              requiresAuth: false,
              hasValidToken: false,
              error: "The remote MCP connector is not installed.",
            };
          }
          return { id, ...(await beginMcpOauth(row, request, env)) };
        }),
      );
      return {
        bytes: encode("CheckHttpMcpStatusResponse", { statuses }),
        label: `MCP OAuth status ${statuses.length}`,
      };
    }
    case "/aiserver.v1.DashboardService/CompleteMcpOAuth": {
      const request = decode("CompleteMcpOAuthRequest", body);
      const completed = await completeMcpOauth(request, env);
      return {
        bytes: encode("CompleteMcpOAuthResponse", completed),
        label: "completed MCP OAuth",
      };
    }
    case "/aiserver.v1.DashboardService/ValidateMcpOAuthTokens": {
      const request = decode("ValidateMcpOAuthTokensRequest", body);
      const targets = [
        ...(request.serverUrls ?? []).map((serverUrl) => ({ serverUrl, accountKey: "default" })),
        ...(request.targets ?? []),
      ];
      const results = await Promise.all(
        targets.map(async (target) => ({
          serverUrl: target.serverUrl,
          accountKey: String(target.accountKey || "default").toLocaleLowerCase(),
          hasValidToken: await hasMcpAccessToken(target.serverUrl, target.accountKey, env),
        })),
      );
      return {
        bytes: encode("ValidateMcpOAuthTokensResponse", { results }),
        label: `validated MCP OAuth ${results.length}`,
      };
    }
    case "/aiserver.v1.DashboardService/DeleteMcpOAuthToken": {
      const request = decode("DeleteMcpOAuthTokenRequest", body);
      removeMcpAccessToken(request.serverUrl, request.accountKey);
      return {
        bytes: encode("DeleteMcpOAuthTokenResponse", {}),
        label: "deleted MCP OAuth token",
      };
    }
    default:
      throw new Error(`unsupported local marketplace RPC ${pathname}`);
  }
}
