<img width="2968" height="841" alt="NetGoat" src="assets/netgoat-banner.png" />

# NetGoat stream server

The stream server is NetGoat's small control plane. It reads domains, upstream
pools, WAF rules, users, zero-trust state, and agent runtime settings from
MongoDB, then exposes normalized snapshots for polling agents. If MongoDB is
unavailable, the last in-memory snapshot remains active and startup can fall
back to a local seed file.

## Architecture

```text
dashboard / CAS ──writes──► MongoDB ◄──reads── stream server ──HTTP poll──► agents
                                                    │
                                                    └── seed-data.json (fallback)
```

Agents poll the stream server; the stream server never pushes to them. Every
snapshot is derived from MongoDB on an interval (`POLL_INTERVAL`), so a write to
MongoDB becomes visible to agents within one poll cycle. The service is
read-mostly and stateless apart from its in-memory cache, so it can be restarted
without losing data.

## Stack

| Layer | Choice |
| --- | --- |
| Runtime | Bun 1.3+ (compiled to a static binary for the image) |
| Language | TypeScript 7, strict mode |
| Database | MongoDB via Mongoose 8 |
| Container | Alpine 3.21, non-root UID 10001 |
| Tests | `bun test` |

## Prerequisites

- Bun 1.3 or newer
- MongoDB 6 or newer (optional — the server serves cached or seed state without it)

## Run it

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

## Scripts

| Command | Purpose |
| --- | --- |
| `bun run start` | Run the server |
| `bun run dev` | Run with `--watch` |
| `bun run test` | Run the test suite |
| `bun run typecheck` | `tsc --noEmit` |
| `bun run scripts/seed-mongo.ts` | Upsert seed data into MongoDB |

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Listen address |
| `PORT` | `8787` | Listen port |
| `MONGODB_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGODB_DB` | `netgoat` | Database name |
| `POLL_INTERVAL` | `5000` | Snapshot rebuild interval, ms |
| `MONGO_RETRY_INTERVAL` | `10000` | Reconnect backoff, ms |
| `API_KEY` | empty | Read key (`X-API-Key` / `Authorization: Bearer`) |
| `DIAMOND_KEY` | empty | Additional read key (`X-Diamond-Key`) |
| `CONFIG_WRITE_KEY` | empty | Required for `PUT /agent-config` when set |
| `DNS_READ_KEY` | empty | Dedicated key for the sanitized `/dns/zones` snapshot |
| `ALLOW_UNAUTHENTICATED` | `false` | Serve reads without a key |
| `CAS_ENABLED` | `false` | Advertise CAS to clients in snapshots |
| `SEED_FILE` | `./seed-data.json` | Local fallback snapshot |
| `LOG_LEVEL` | `info` | Log verbosity |

Set at least one read key. `ALLOW_UNAUTHENTICATED=true` is only appropriate on a
trusted loopback network.

## Authentication

Set `API_KEY`, `DIAMOND_KEY`, or both. Clients may authenticate with
`X-API-Key`, `Authorization: Bearer`, `X-Diamond-Key`, or the legacy
`X-Zero-Trust-Key` header. When no read key is configured, requests are denied
unless `ALLOW_UNAUTHENTICATED=true` is explicitly set.

The nameserver reads `/dns/zones` using `X-DNS-API-Key` and `DNS_READ_KEY`.
That endpoint exposes only active zone names and active DNS records, and does
not accept the broader agent snapshot credentials.

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
| `GET` | `/dns/zones` | Active DNS zones and records for the authoritative nameserver |
| `GET` | `/waf-stats` | Aggregated WAF counters |
| `GET` | `/__netgoat/metrics` | Prometheus-style metrics |

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

## Docker

```bash
docker build -t netgoat-streamer .
docker run --rm -p 8787:8787 --env-file .env netgoat-streamer
```

The image compiles the server to a single static binary with `bun build
--compile`, runs on Alpine 3.21 as UID 10001, and healthchecks `/health`.
Published images: `ghcr.io/netgoat-xyz/streamer`.

The healthcheck sends whichever read key is configured (`API_KEY`, falling
back to `DIAMOND_KEY`) and follows `PORT`, so a container with a custom port
or only the legacy key still reports healthy.

When MongoDB is unreachable the server serves `SEED_FILE` instead of live
state. The default path is baked in but the file is not — mount it read-only
if you rely on the fallback:

```bash
docker run --rm -p 8787:8787 --env-file .env \
  -v "$PWD/seed-data.json:/app/seed-data.json:ro" netgoat-streamer
```

## Deployment

Run one or more replicas behind a load balancer. Each replica keeps its own
in-memory cache and rebuilds it on `POLL_INTERVAL`, so scaling out is safe.
Restrict the listener to the agent network and terminate TLS in front of it —
the server speaks plain HTTP. Agents should send the read key on every request.

## Security

- Snapshots may contain TLS private keys; responses are `no-store` and must not
  be cached by an intermediary.
- Read keys and the config write key are compared without early exit.
- Request bodies are size- and media-type-limited.
- Report vulnerabilities per [SECURITY.md](SECURITY.md); do not open a public issue.

## Verification

```bash
bun install --frozen-lockfile
bun run typecheck
bun test
```

The test suite covers snapshot filtering and upstream mapping, seed conversion,
request-size and media-type enforcement, secret redaction, model indexes,
session expiry, invite lookup isolation, and DNS validation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[GNU Affero General Public License v3.0](LICENSE).
