import { describe, expect, test } from "bun:test";
import {
  buildCachedState,
  normalizeAgentConfig,
  normalizePluginsConfig,
  normalizeRoutePolicy,
  parseWafStatName,
  readJSONBody,
  redactMongoUri,
  serializeCachedResponses,
} from "./server";
import { normalizeSeedData } from "./scripts/seed-mongo";

describe("normalizeAgentConfig", () => {
  test("clamps numeric input and rejects unsafe headers", () => {
    const config = normalizeAgentConfig({
      cache: { enabled: true, ttl_seconds: -10, max_entries: "250" },
      rate_limit: { requests_per_minute: 2_000_000, key: "invalid" },
      metrics: { enabled: true, path: "https://example.com/metrics" },
      koda_waf: { threshold: 9, feature_header: "bad header" },
    });

    expect(config.cache.enabled).toBe(true);
    expect(config.cache.ttl_seconds).toBe(1);
    expect(config.cache.max_entries).toBe(250);
    expect(config.rate_limit.requests_per_minute).toBe(1_000_000);
    expect(config.rate_limit.key).toBe("ip");
    expect(config.metrics.path).toBe("/__netgoat/metrics");
    expect(config.koda_waf.threshold).toBe(1);
    expect(config.koda_waf.feature_header).toBe("X-KodaWaf-Features");
  });

  test("does not partially parse malformed numbers", () => {
    const config = normalizeAgentConfig({ cache: { max_entries: "250garbage" } });
    expect(config.cache.max_entries).toBe(1024);
  });

  test("rejects agent file paths that escape the agent directory", () => {
    const config = normalizeAgentConfig({
      koda_waf: {
        model_path: "../../../../etc/shadow",
        scaler_path: "/etc/passwd",
        python_script: "~/evil.py",
      },
      koda_2: {
        model_path: "C:\\Windows\\System32\\config\\SAM",
        python_script: "ai/../../escape.py",
      },
    });

    expect(config.koda_waf.model_path).toBe("ai/smart_waf_model.pkl");
    expect(config.koda_waf.scaler_path).toBe("ai/model_features.pkl");
    expect(config.koda_waf.python_script).toBe("ai/koda_waf_server.py");
    expect(config.koda_2.model_path).toBe("ai/koda2.keras");
    expect(config.koda_2.python_script).toBe("ai/koda2_server.py");
  });

  test("keeps legitimate relative agent file paths", () => {
    const config = normalizeAgentConfig({
      koda_waf: { model_path: "ai/custom/model.pkl" },
    });
    expect(config.koda_waf.model_path).toBe("ai/custom/model.pkl");
  });

  test("publishes bounded dynamic rules without unsafe source", () => {
    const config = normalizeAgentConfig({
      dynamic_rules: {
        enabled: true,
        max_rules: 2,
        max_execution_milliseconds: 9999,
        rules: [
          { name: "block-admin", language: "js", source: "module.exports = () => ({ action: 'block' });" },
          { name: "bad\u0000name", source: "module.exports = () => null" },
          { name: "second", language: "typescript", source: "export default () => null" },
          { name: "third", source: "module.exports = () => null" },
        ],
      },
    });

    expect(config.dynamic_rules.enabled).toBe(true);
    expect(config.dynamic_rules.max_rules).toBe(2);
    expect(config.dynamic_rules.max_execution_milliseconds).toBe(500);
    expect(config.dynamic_rules.rules).toEqual([
      { name: "block-admin", language: "javascript", source: "module.exports = () => ({ action: 'block' });" },
      { name: "second", language: "typescript", source: "export default () => null" },
    ]);
  });
});

describe("normalizePluginsConfig", () => {
  const sha256 = "A".repeat(64);

  test("publishes a bounded, canonical deployment plan", () => {
    const plugins = normalizePluginsConfig({
      installations: [
        {
          plugin_id: "zeta.audit",
          factory_id: "audit-gate",
          version: "1.2.3",
          sha256,
          api_version: "netgoat.dev/middleware/v1",
          granted_capabilities: ["response.write", "request.read", "request.read", "unknown"],
          config: { nested: { beta: true, alpha: 1 }, rules: ["one", "two"] },
        },
        {
          plugin_id: "alpha.guard",
          factory_id: "guard",
          version: "2.0.0-beta.1",
          sha256: "b".repeat(64),
          api_version: "netgoat.dev/middleware/v2",
          granted_capabilities: ["route.read"],
          config: {},
        },
      ],
    });

    expect(plugins).toEqual({
      installations: [
        {
          plugin_id: "alpha.guard",
          factory_id: "guard",
          version: "2.0.0-beta.1",
          sha256: "b".repeat(64),
          api_version: "netgoat.dev/middleware/v2",
          granted_capabilities: ["route.read"],
          config: {},
        },
        {
          plugin_id: "zeta.audit",
          factory_id: "audit-gate",
          version: "1.2.3",
          sha256: "a".repeat(64),
          api_version: "netgoat.dev/middleware/v1",
          granted_capabilities: ["request.read", "response.write"],
          config: { nested: { alpha: 1, beta: true }, rules: ["one", "two"] },
        },
      ],
    });
  });

  test("rejects unsafe or malformed installations and removes duplicates", () => {
    const plugins = normalizePluginsConfig({
      installations: [
        {
          plugin_id: "safe.plugin",
          factory_id: "safe-factory",
          version: "1.0.0",
          sha256: "c".repeat(64),
          api_version: "netgoat.dev/middleware/v1",
          granted_capabilities: [],
          config: { enabled: true },
        },
        {
          plugin_id: "safe.plugin",
          factory_id: "another-factory",
          version: "1.0.1",
          sha256: "d".repeat(64),
          api_version: "netgoat.dev/middleware/v1",
          granted_capabilities: [],
          config: {},
        },
        {
          plugin_id: "bad/hash",
          factory_id: "bad-factory",
          version: "1.0.0",
          sha256: "not-a-digest",
          api_version: "netgoat.dev/middleware/v1",
          granted_capabilities: [],
          config: {},
        },
        {
          plugin_id: "bad.config",
          factory_id: "bad-config",
          version: "1.0.0",
          sha256: "e".repeat(64),
          api_version: "netgoat.dev/middleware/v1",
          granted_capabilities: [],
          config: ["must be an object"],
        },
        {
          plugin_id: "unsafe..id",
          factory_id: "unsafe",
          version: "1.0.0",
          sha256: "f".repeat(64),
          api_version: "netgoat.dev/middleware/v1",
          granted_capabilities: [],
          config: {},
        },
      ],
    });

    expect(plugins.installations).toEqual([]);
  });

  test("caps the installation list and rejects over-sized config objects", () => {
    const installations = Array.from({ length: 66 }, (_, index) => ({
      plugin_id: `plugin-${index}`,
      factory_id: `factory-${index}`,
      version: "1.0.0",
      sha256: index === 65 ? "f".repeat(64) : "a".repeat(63) + (index % 10),
      api_version: "netgoat.dev/middleware/v1",
      granted_capabilities: [],
      config: index === 0 ? { source: "x".repeat(16 * 1024) } : {},
    }));

    const plugins = normalizePluginsConfig({ installations });
    expect(plugins.installations).toHaveLength(64);
    expect(plugins.installations.some((plugin) => plugin.plugin_id === "plugin-0")).toBe(false);
  });
});

describe("request parsing and secret redaction", () => {
  test("parses a bounded JSON request", async () => {
    const request = new Request("http://localhost/agent-config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ metrics: { enabled: true } }),
    });
    expect(await readJSONBody(request)).toEqual({ metrics: { enabled: true } });
  });

  test("rejects declared and streamed oversized bodies", async () => {
    const declared = new Request("http://localhost/agent-config", {
      method: "PUT",
      headers: { "Content-Length": "65537", "Content-Type": "application/json" },
      body: "{}",
    });
    await expect(readJSONBody(declared)).rejects.toThrow("request body too large");

    const streamed = new Request("http://localhost/agent-config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: `"${"x".repeat(65537)}"`,
    });
    await expect(readJSONBody(streamed)).rejects.toThrow("request body too large");
  });

  test("rejects unsupported media types and malformed JSON", async () => {
    const wrongType = new Request("http://localhost/agent-config", {
      method: "PUT",
      headers: { "Content-Type": "text/plain" },
      body: "{}",
    });
    await expect(readJSONBody(wrongType)).rejects.toThrow("content-type must be application/json");

    const malformed = new Request("http://localhost/agent-config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: "{",
    });
    await expect(readJSONBody(malformed)).rejects.toThrow("invalid JSON body");
  });

  test("redacts MongoDB credentials", () => {
    const redacted = redactMongoUri("mongodb+srv://alice:secret@cluster.example/netgoat");
    expect(redacted).not.toContain("alice");
    expect(redacted).not.toContain("secret");
    expect(redacted).toContain("cluster.example");
  });
});

describe("buildCachedState", () => {
  test("publishes only active routes, users, rules, and healthy upstreams", () => {
    const state = buildCachedState({
      domainDocs: [
        {
          _id: "domain-1",
          domain: "Example.COM",
          target_url: "https://primary.internal",
          active: true,
          subdomains: [
            {
              _id: "sub-1",
              subdomain: "API",
              full_domain: "api.example.com",
              target_url: "https://api-primary.internal",
              active: true,
            },
            { subdomain: "old", full_domain: "old.example.com", active: false },
          ],
          waf_rules: [
            { _id: "rule-1", name: "block bots", expression: "bot", priority: 10 },
            { name: "disabled", expression: "never", enabled: false },
          ],
        },
        { _id: "domain-2", domain: "disabled.example", active: false },
      ],
      proxyConfigDocs: [
        {
          domain_id: "domain-1",
          upstream_servers: [
            { url: "https://primary.internal" },
            { url: "https://secondary.internal" },
            { url: "https://down.internal", down: true },
          ],
        },
        {
          domain_id: "domain-1",
          subdomain: "api",
          upstream_servers: [{ url: "https://api-secondary.internal" }],
        },
      ],
      globalRuleDocs: [
        { _id: "global-1", name: "global", expression: "attack", action: "allow", priority: 20 },
      ],
      userDocs: [
        { _id: "user-1", name: "Alice", email: "ALICE@example.com" },
        { _id: "user-2", name: "Banned", banned: true },
      ],
      settingsDoc: {
        zeroTrustEnabled: true,
        casEnabled: true,
        agentConfig: { metrics: { enabled: true, path: "/metrics" } },
      },
    });

    expect(state.domains).toHaveLength(1);
    expect(state.domains[0]?.domain).toBe("example.com");
    expect(state.domains[0]?.target_urls).toEqual(["https://secondary.internal"]);
    expect(state.domains[0]?.subdomains).toHaveLength(1);
    expect(state.domains[0]?.subdomains[0]?.target_urls).toEqual(["https://api-secondary.internal"]);
    expect(state.waf_rules.map((rule) => rule.name)).toEqual(["global", "block bots"]);
    expect(state.waf_rules[0]?.action).toBe("ALLOW");
    expect(state.waf_rules.find((rule) => rule.name === "block bots")?.hosts).toEqual([
      "example.com",
      "api.example.com",
    ]);
    expect(state.users).toEqual([
      { id: "user-1", username: "Alice", email: "alice@example.com", role: "user" },
    ]);
    expect(state.zero_trust_enabled).toBe(true);
    expect(state.cas_enabled).toBe(true);
    expect(state.agent_config.metrics).toEqual({ enabled: true, path: "/metrics" });
    const published = JSON.parse(serializeCachedResponses(state).domains);
    expect(published.cas_enabled).toBe(true);
  });

  test("scopes proxy WAF rules to their resolved route host", () => {
    const state = buildCachedState({
      domainDocs: [{ _id: "domain-1", domain: "example.com", subdomains: [{ subdomain: "api" }] }],
      proxyConfigDocs: [{ _id: "proxy-1", domain_id: "domain-1", subdomain: "api" }],
      globalRuleDocs: [
        { _id: "scoped", name: "api only", expression: "Path == '/private'", proxy_config_id: "proxy-1" },
        { _id: "stale", name: "stale scope", expression: "true", proxy_config_id: "missing" },
      ],
      userDocs: [],
      settingsDoc: {},
    });
    expect(state.waf_rules).toHaveLength(1);
    expect(state.waf_rules[0]?.hosts).toEqual(["api.example.com"]);
  });

  test("reads the legacy zero-trust settings record", () => {
    const state = buildCachedState({
      domainDocs: [],
      proxyConfigDocs: [],
      globalRuleDocs: [],
      userDocs: [],
      settingsDoc: {},
      legacyZeroTrustDoc: { value: "true" },
    });

    expect(state.zero_trust_enabled).toBe(true);
  });

  test("only makes password-backed agent users authoritative on explicit opt-in", () => {
    const state = buildCachedState({
      domainDocs: [{
        _id: "domain-1",
        user_id: "user-1",
        domain: "example.com",
        target_url: "https://upstream.internal",
      }],
      proxyConfigDocs: [],
      globalRuleDocs: [],
      userDocs: [{
        _id: "user-1",
        name: "alice",
        email: "alice@example.com",
        password_hash: "$2b$12$credential-hash",
        zero_trust_enabled: false,
      }],
      settingsDoc: {
        agentUsersConfigured: true,
        agentUserDomainsConfigured: true,
      },
    });

    expect(state.users_configured).toBe(true);
    expect(state.user_domains_configured).toBe(true);
    expect(state.agent_users).toEqual([{
      id: "user-1",
      username: "alice",
      email: "alice@example.com",
      password_hash: "$2b$12$credential-hash",
      zero_trust_enabled: false,
    }]);
    expect(state.user_domains).toEqual([{
      id: "domain-1",
      user_id: "user-1",
      username: "alice",
      domain: "example.com",
      target_url: "https://upstream.internal",
      active: true,
    }]);
  });

  test("does not claim user ownership when a credential-backed source is incomplete", () => {
    const state = buildCachedState({
      domainDocs: [{ _id: "domain-1", user_id: "user-1", domain: "example.com" }],
      proxyConfigDocs: [],
      globalRuleDocs: [],
      userDocs: [{ _id: "user-1", name: "alice" }],
      settingsDoc: {
        agentUsersConfigured: true,
        agentUserDomainsConfigured: true,
      },
    });

    expect(state.agent_users).toEqual([]);
    expect(state.users_configured).toBe(false);
    expect(state.user_domains_configured).toBe(false);
  });

  test("can explicitly publish an intentionally empty user snapshot", () => {
    const state = buildCachedState({
      domainDocs: [],
      proxyConfigDocs: [],
      globalRuleDocs: [],
      userDocs: [],
      settingsDoc: {
        agentUsersConfigured: true,
        agentUserDomainsConfigured: true,
      },
    });

    expect(state.users_configured).toBe(true);
    expect(state.user_domains_configured).toBe(true);
    expect(state.agent_users).toEqual([]);
    expect(state.user_domains).toEqual([]);
  });

  test("publishes an explicit global plugin deployment plan", () => {
    const state = buildCachedState({
      domainDocs: [],
      proxyConfigDocs: [],
      globalRuleDocs: [],
      userDocs: [],
      settingsDoc: {
        pluginsConfigured: true,
        plugins: {
          installations: [{
            plugin_id: "acme.guard",
            factory_id: "acme-guard",
            version: "1.0.0",
            sha256: "a".repeat(64),
            api_version: "netgoat.dev/middleware/v1",
            granted_capabilities: ["route.read", "request.read"],
            config: { mode: "block" },
          }],
        },
      },
    });

    expect(state.plugins_configured).toBe(true);
    expect(state.plugins.installations).toEqual([{
      plugin_id: "acme.guard",
      factory_id: "acme-guard",
      version: "1.0.0",
      sha256: "a".repeat(64),
      api_version: "netgoat.dev/middleware/v1",
      granted_capabilities: ["request.read", "route.read"],
      config: { mode: "block" },
    }]);

    const published = JSON.parse(serializeCachedResponses(state).domains);
    expect(published.plugins_configured).toBe(true);
    expect(published.plugins).toEqual(state.plugins);
  });

  test("does not claim plugin ownership without the explicit replacement flag", () => {
    const state = buildCachedState({
      domainDocs: [],
      proxyConfigDocs: [],
      globalRuleDocs: [],
      userDocs: [],
      settingsDoc: {
        plugins: {
          installations: [{
            plugin_id: "acme.guard",
            factory_id: "acme-guard",
            version: "1.0.0",
            sha256: "a".repeat(64),
            api_version: "netgoat.dev/middleware/v1",
            granted_capabilities: [],
            config: {},
          }],
        },
      },
    });

    expect(state.plugins_configured).toBe(false);
    expect(state.plugins.installations).toHaveLength(1);
  });

  test("publishes bounded route policies without inventing an override", () => {
    const state = buildCachedState({
      domainDocs: [{
        _id: "domain-1",
        domain: "example.com",
        route_policy: {
          cache: { enabled: false, ttl_seconds: 30 },
          bandwidth: { enabled: true, bytes_per_second: 4096, burst_bytes: 8192, key: "ip" },
        },
        subdomains: [{
          subdomain: "api",
          route_policy: { cache: { enabled: true, max_entries: 12 } },
        }],
      }],
      proxyConfigDocs: [],
      globalRuleDocs: [],
      userDocs: [],
      settingsDoc: {},
    });

    expect(state.domains[0]?.policy).toEqual({
      cache: { enabled: false, ttl_seconds: 30, max_entries: undefined, max_body_bytes: undefined },
      bandwidth: { enabled: true, bytes_per_second: 4096, burst_bytes: 8192, key: "ip" },
    });
    expect(state.domains[0]?.subdomains[0]?.policy).toEqual({
      cache: { enabled: true, ttl_seconds: undefined, max_entries: 12, max_body_bytes: undefined },
    });
    expect(normalizeRoutePolicy({ cache: { ttl_seconds: 0 } })).toBeUndefined();
  });

  test("publishes subdomain certificates, scoped WAF rules, and resolved access", () => {
    const state = buildCachedState({
      domainDocs: [{
        _id: "domain-1",
        domain: "example.com",
        certificate_pem: "DOMAIN CERT",
        private_key_pem: "DOMAIN KEY",
        access_control: { mode: "allowlist", cidrs: ["10.0.0.0/8"] },
        waf_rules: [{ name: "zone", expression: "bot" }],
        subdomains: [{
          _id: "sub-1",
          subdomain: "api",
          full_domain: "api.example.com",
          target_url: "https://api.internal",
          certificate_pem: "API CERT",
          private_key_pem: "API KEY",
          access_control: { mode: "inherit" },
          waf_rules: [{ name: "api only", expression: "Path == '/admin'" }],
        }, {
          subdomain: "cdn",
          full_domain: "cdn.example.com",
          target_url: "https://cdn.internal",
          access_control: { mode: "off" },
        }, {
          subdomain: "office",
          full_domain: "office.example.com",
          target_url: "https://office.internal",
          access_control: { mode: "blocklist", cidrs: ["1.1.1.1"] },
        }],
      }],
      proxyConfigDocs: [],
      globalRuleDocs: [],
      userDocs: [],
      settingsDoc: {},
    });

    expect(state.domains[0]?.policy?.access).toEqual({ mode: "allowlist", cidrs: ["10.0.0.0/8"] });
    const api = state.domains[0]?.subdomains.find((entry) => entry.subdomain === "api");
    const cdn = state.domains[0]?.subdomains.find((entry) => entry.subdomain === "cdn");
    const office = state.domains[0]?.subdomains.find((entry) => entry.subdomain === "office");
    expect(api?.certificate_pem).toBe("API CERT");
    expect(api?.private_key_pem).toBe("API KEY");
    expect(api?.policy?.access).toEqual({ mode: "allowlist", cidrs: ["10.0.0.0/8"] });
    expect(cdn?.policy?.access).toBeUndefined();
    expect(office?.policy?.access).toEqual({ mode: "blocklist", cidrs: ["1.1.1.1/32"] });
    expect(state.waf_rules.find((rule) => rule.name === "api only")?.hosts).toEqual(["api.example.com"]);
    expect(state.waf_rules.find((rule) => rule.name === "zone")?.hosts).toEqual([
      "example.com",
      "api.example.com",
      "cdn.example.com",
      "office.example.com",
    ]);
  });
});

describe("normalizeSeedData", () => {
  test("keeps embedded route data and maps users to the frontend collection schema", () => {
    const seed = normalizeSeedData({
      domains: [{ domain: "example.com", subdomains: [{ subdomain: "api" }] }],
      waf_rules: [{ name: "global", expression: "attack" }],
      users: [{ username: "alice", email: "alice@example.com" }],
      users_configured: true,
      user_domains_configured: true,
      plugins: { installations: [] },
      plugins_configured: true,
      zero_trust_enabled: true,
    });

    expect(seed.domains[0]?.active).toBe(true);
    expect((seed.domains[0]?.subdomains as Array<Record<string, unknown>>)[0]?.active).toBe(true);
    expect(seed.waf_rules[0]?.enabled).toBe(true);
    expect(seed.users[0]?.name).toBe("alice");
    expect(seed.users[0]?.username).toBeUndefined();
    expect(seed.users_configured).toBe(true);
    expect(seed.user_domains_configured).toBe(true);
    expect(seed.plugins).toEqual({ installations: [] });
    expect(seed.plugins_configured).toBe(true);
    expect(seed.zero_trust_enabled).toBe(true);
  });
});

describe("parseWafStatName", () => {
  test("splits host-scoped agent rule names", () => {
    expect(parseWafStatName("block admin [api.example.com]")).toEqual({
      name: "block admin",
      hosts: ["api.example.com"],
    });
    expect(parseWafStatName("zone [example.com,api.example.com]")).toEqual({
      name: "zone",
      hosts: ["example.com", "api.example.com"],
    });
    expect(parseWafStatName("global")).toEqual({ name: "global", hosts: [] });
  });
});
