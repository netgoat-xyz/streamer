# NetGoat stream server

The stream server is NetGoat's small control plane. It reads domains, upstream
pools, WAF rules, users, zero-trust state, and agent runtime settings from
MongoDB, then exposes normalized snapshots for polling agents. If MongoDB is
unavailable, the last in-memory snapshot remains active and startup can fall
back to a local seed file.

## Run it

Requirements: Bun 1.3 or newer and, optionally, MongoDB.

```bash
cp .env.example .env
bun install
bun run start
```

The server retries an unavailable MongoDB connection; it does not need MongoDB
to start. Keep `seed-data.json`, `.env`, TLS private keys, and API keys out of
version control.

CAS is optional. Leave `casEnabled` unset or false in MongoDB and seed data to
run the stream server without exposing a central administrative service signal
to downstream consumers.

## Authentication

Set `API_KEY`, `DIAMOND_KEY`, or both. Clients may authenticate with
`X-API-Key`, `Authorization: Bearer`, `X-Diamond-Key`, or the legacy
`X-Zero-Trust-Key` header. When no read key is configured, requests are denied
unless `ALLOW_UNAUTHENTICATED=true` is explicitly set.

`CONFIG_WRITE_KEY` is optional but recommended. When present, only that key can
update `/agent-config`; send it in `X-Config-Write-Key` or a supported auth
header. Without it, write access falls back to the normal API authentication.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` or `/health` | Liveness, Mongo status, and cached counts |
| `GET` | `/domains` | Active routes, upstreams, WAF rules, zero-trust state, agent settings, opted-in user snapshots, and global plugin deployment plans |
| `GET` | `/users` | Active, non-banned control-plane users |
| `GET` | `/agent-config` | Current normalized agent runtime settings |
| `PUT` | `/agent-config` | Validate and update agent runtime settings |

`/health` and `/domains` both include a `cas_enabled` boolean so clients can
detect whether CAS should be surfaced in the UI or ignored entirely.

All JSON responses are marked `Cache-Control: no-store` because snapshots can
contain TLS private keys. Request bodies for configuration updates are limited
to 64 KiB.

WAF rules associated with a domain or proxy configuration include a normalized
`hosts` list in `/domains`. Agents combine that list with the rule expression,
so a route-specific rule cannot silently become global. Scoped rules whose
route no longer exists are omitted from the published snapshot.

## Seed data

`scripts/seed-mongo.ts` accepts the same top-level data shape served to agents:

```json
{
  "domains": [],
  "waf_rules": [],
  "users": [],
  "users_configured": false,
  "user_domains_configured": false,
  "plugins": { "installations": [] },
  "plugins_configured": false,
  "zero_trust_enabled": false,
  "cas_enabled": false,
  "agent_config": {}
}
```

Run `bun run scripts/seed-mongo.ts` to upsert records. Setting
`SEED_RESET=true` first clears only the replaceable `domains` and `waf_rules`
collections. It never drops unrelated collections or deletes application user
records.

## Agent user snapshots

The agent treats `users_configured` and `user_domains_configured` as explicit
full-replacement signals. The stream server emits either signal only when the
corresponding `Settings` flag (`agentUsersConfigured` or
`agentUserDomainsConfigured`) is true. User replacement also requires every
active source user to have a `password_hash`; this prevents dashboard-only
users from accidentally replacing an agent's local login accounts. A flagged,
empty list intentionally clears the matching agent collection. Without the
flag, agents may upsert supplied records but retain local/offline data.

## Global plugin deployments

`plugins_configured` has the same explicit full-replacement semantics as the
user snapshot flags. When true, the `plugins.installations` list is a complete
global deployment plan; a true flag with an empty list removes previous global
installs. Each installation is normalized and bounded before publication and
contains only `plugin_id`, `factory_id`, `version`, `sha256`, `api_version`,
`granted_capabilities`, and a JSON-object `config`. The stream server never
downloads, verifies, or executes plugin code. Agents must verify the pinned
digest and enforce their own runtime and capability policies.

## Verification

```bash
bun run test
bun run typecheck
```

The test suite covers snapshot filtering and upstream mapping, seed conversion,
request-size and media-type enforcement, secret redaction, model indexes,
session expiry, invite lookup isolation, and DNS validation.
