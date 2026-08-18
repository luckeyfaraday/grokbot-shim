import assert from "node:assert/strict";
import test from "node:test";

import {
  MARKETPLACE_PATHS,
  marketplaceAuthOverride,
  marketplaceChecksumOverride,
  marketplaceProxyEnabled,
  parsePublicMarketplaceHtml,
  publicMarketplaceEnabled,
  shouldServePublicMarketplace,
  shouldProxyMarketplace,
} from "../shim/marketplace.mjs";

test("the marketplace proxy stays off unless it is asked for", () => {
  assert.equal(marketplaceProxyEnabled({}), false);
  assert.equal(marketplaceProxyEnabled({ PLUGIN_PROXY: "0" }), false);
  assert.equal(marketplaceProxyEnabled({ PLUGIN_PROXY: "1" }), false);
  assert.equal(
    marketplaceProxyEnabled({ PLUGIN_PROXY: "1", PLUGIN_MARKETPLACE: "private" }),
    true,
  );
  for (const path of MARKETPLACE_PATHS) {
    assert.equal(shouldProxyMarketplace(path, {}), false);
  }
});

test("only the catalog reads are proxied", () => {
  const env = { PLUGIN_PROXY: "1", PLUGIN_MARKETPLACE: "private" };
  assert.equal(shouldProxyMarketplace("/aiserver.v1.DashboardService/ListMarketplaces", env), true);
  assert.equal(
    shouldProxyMarketplace("/aiserver.v1.DashboardService/ListMarketplacePlugins", env),
    true,
  );
  // Inference and auth must never leave the machine on the marketplace path.
  assert.equal(shouldProxyMarketplace("/aiserver.v1.InferenceService/Stream", env), false);
  assert.equal(shouldProxyMarketplace("/auth/cursor_dev_session_token", env), false);
  assert.equal(shouldProxyMarketplace("/aiserver.v1.AiService/AvailableModels", env), false);
});

test("the public bridge is on by default and includes install-state RPCs", () => {
  assert.equal(publicMarketplaceEnabled({}), true);
  assert.equal(publicMarketplaceEnabled({ PLUGIN_MARKETPLACE: "off" }), false);
  assert.equal(
    shouldServePublicMarketplace("/aiserver.v1.DashboardService/ListMarketplacePlugins", {}),
    true,
  );
  assert.equal(
    shouldServePublicMarketplace("/aiserver.v1.DashboardService/InstallUserPlugin", {}),
    true,
  );
  assert.equal(
    shouldServePublicMarketplace("/aiserver.v1.InferenceService/Stream", {}),
    false,
  );
});

test("the public Next.js payload parser extracts initialPlugins", () => {
  const plugins = [
    {
      id: "42",
      name: "real-plugin",
      displayName: "Real Plugin",
      description: "Contains brackets [like this] and a quote: \"yes\".",
    },
  ];
  const record = `1d:["$","component",null,{"initialPlugins":${JSON.stringify(plugins)}}]`;
  const html = `<script>self.__next_f.push(${JSON.stringify([1, record])})</script>`;
  assert.deepEqual(parsePublicMarketplaceHtml(html), plugins);
});

test("the upstream token is sent as a bearer credential exactly once", () => {
  assert.equal(marketplaceAuthOverride({}), undefined);
  assert.equal(marketplaceAuthOverride({ UPSTREAM_TOKEN: "   " }), undefined);
  assert.equal(marketplaceAuthOverride({ UPSTREAM_TOKEN: "abc" }), "Bearer abc");
  assert.equal(marketplaceAuthOverride({ UPSTREAM_TOKEN: "Bearer abc" }), "Bearer abc");
});

test("the checksum keeps the app's timestamp and takes the configured machine id", () => {
  // Shape observed on the wire: 8 base64url chars, then the machine id.
  const sent = "4bu9qfGv8bf719d2-d65b-4fe9-b1a6-df3b4397328d";
  const real = "11111111-2222-3333-4444-555555555555";
  assert.equal(marketplaceChecksumOverride(sent, { UPSTREAM_MACHINE_ID: real }), `4bu9qfGv${real}`);
  // Untouched without an override, or when there is nothing to rewrite.
  assert.equal(marketplaceChecksumOverride(sent, {}), undefined);
  assert.equal(marketplaceChecksumOverride(undefined, { UPSTREAM_MACHINE_ID: real }), undefined);
  assert.equal(marketplaceChecksumOverride("short", { UPSTREAM_MACHINE_ID: real }), undefined);
});
