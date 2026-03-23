# vault-gateway

A Go HTTP API server that wraps HashiCorp Vault for per-server secret management (RCON passwords).
Part of the [homelab-ai](https://github.com/lobo235/homelab-ai) platform.

## Module

`github.com/lobo235/vault-gateway`

## Quick Start

```bash
cp .env.example .env
# Fill in required values
go run ./cmd/server
```

## Build, Test, Run

> Go is installed at `~/bin/go/bin/go` (also on `$PATH` via `.bashrc`).

```bash
# Build
make build

# Run tests
make test

# Run tests with verbose output
go test -v ./...

# Run linter
make lint

# Coverage report (opens in browser)
make cover

# Run the server (requires .env or env vars)
make run

# Build binary
go build -o vault-gateway ./cmd/server
```

## Project Layout

```
vault-gateway/
├── Dockerfile
├── Makefile
├── go.mod / go.sum
├── .env.example              # dev template — never commit real values
├── .gitignore
├── .golangci.yml             # strict linter config
├── .githooks/pre-commit      # runs lint + tests; activate with `make hooks`
├── CLAUDE.md                 # this file
├── README.md
├── CHANGELOG.md
├── cmd/
│   └── server/
│       └── main.go           # entry point
├── deploy/
│   ├── vault-gateway.hcl         # Nomad job spec (placeholders only)
│   └── vault-gateway.policy.hcl  # Vault policy (least privilege)
└── internal/
    ├── config/
    │   ├── config.go          # ENV var loading & validation
    │   └── config_test.go
    ├── vault/
    │   ├── client.go          # Vault API wrapper (AppRole auth, KV v2 ops)
    │   └── client_test.go
    └── api/
        ├── server.go          # HTTP mux + Run()
        ├── middleware.go      # Bearer auth + request logging + X-Trace-ID
        ├── handlers.go        # all route handlers
        ├── errors.go          # writeError / writeJSON helpers
        ├── health.go          # GET /health (unauthenticated)
        └── server_test.go     # handler tests via httptest
```

## Configuration

All config via ENV vars. Loaded from `.env` in development (via `godotenv`; missing file silently ignored). In production, secrets are injected by Nomad Vault Workload Identity — the app never talks to Vault directly for its own secrets.

| Var | Required | Default | Purpose |
|-----|----------|---------|---------|
| `VAULT_ADDR` | yes | — | Vault server URL (e.g. `https://vault.example.com:8200`) |
| `VAULT_ROLE_ID` | yes | — | AppRole Role ID (injected via Nomad Workload Identity) |
| `VAULT_SECRET_ID` | yes | — | AppRole Secret ID (injected via Nomad Workload Identity) |
| `GATEWAY_API_KEY` | yes | — | Bearer token for callers of this API |
| `PORT` | no | `8080` | Listen port |
| `LOG_LEVEL` | no | `info` | Verbosity: `debug`, `info`, `warn`, `error` |

## Architecture

```
cmd/server/main.go           — entry point, wires deps, handles SIGINT/SIGTERM
internal/config/config.go    — ENV-based config with validation
internal/api/server.go       — HTTP server, route registration
internal/api/middleware.go   — bearerAuth + requestLogger + X-Trace-ID propagation
internal/api/handlers.go     — route handlers (create/read/update/delete secrets)
internal/api/errors.go       — writeError / writeJSON helpers
internal/api/health.go       — GET /health handler (unauthenticated)
internal/vault/client.go     — Vault API wrapper (AppRole auth, token renewal, KV v2 ops)
```

## API Routes

All routes except `/health` require `Authorization: Bearer <GATEWAY_API_KEY>`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Ping Vault; return `{"status":"ok","version":"..."}` |
| POST | `/secrets/minecraft/{serverName}` | Yes | Create secrets (auto-generates RCON password); 201 |
| GET | `/secrets/minecraft/{serverName}` | Yes | Read secrets (returns RCON password); 200 |
| PUT | `/secrets/minecraft/{serverName}` | Yes | Rotate RCON password; 200 |
| DELETE | `/secrets/minecraft/{serverName}` | Yes | Delete all secret versions; 200 |

### Server name validation

Server names must match `^[a-z0-9][a-z0-9-]{0,47}$`.

### Vault paths

- Read/write: `kv/data/nomad/default/{serverName}` (KV v2)
- Delete all versions: `kv/metadata/nomad/default/{serverName}` (KV v2)

All paths are validated to start with the expected prefix before any Vault call.

## Testing Approach

Tests live in `internal/vault/client_test.go` and `internal/api/server_test.go`.

Key patterns:
- API tests use a `mockVaultClient` that implements the `vaultClient` interface — no live Vault required
- Vault client tests cover password generation (length, alphabet, uniqueness) and path validation
- Config tests cover all required fields, defaults, and validation
- Table-driven tests for input validation (server names, log levels)
- Both success and error paths tested (upstream errors, not-found, conflict)

## Coding Conventions

- No external router, ORM, or framework — minimal dependency footprint
- Error responses always use `writeError(w, status, code, message)` with machine-readable `code`
- Route handlers return `http.HandlerFunc`
- All upstream errors wrapped with `fmt.Errorf("context: %w", err)`
- `X-Trace-ID` header propagated from request context to all log lines
- Structured JSON logging via `log/slog`; version logged on startup; every request access-logged
- Never log secret values (RCON passwords, Vault tokens, API keys)

## Security Rules

> **Claude must enforce all rules below on every commit and push without exception.**

1. **Never commit secrets:** No `.env`, tokens, API keys, passwords, or credentials of any kind.
2. **Never commit infrastructure identifiers:** No real hostnames, IP addresses, datacenter names, node pool names, Consul service names, Vault paths with real values, Traefik routing rules with real domains, or any value that reveals homelab architecture. Use generic placeholders (`dc1`, `default`, `example.com`, `your-node-pool`, `your-service`).
3. **Unknown files:** If `git status` shows a file Claude didn't create, ask the operator before staging it.
4. **Pre-commit checks (must all pass before committing):**
   - `go test ./...` — all tests must pass
   - `golangci-lint run` — no lint errors
5. **Docs accuracy:** Review all changed `.md` files before committing — documentation must reflect the current state of the code in the same commit.
6. **Version bump:** Before any `git commit`, review the changes and determine the appropriate SemVer bump (MAJOR/MINOR/PATCH). Present the rationale and proposed new version to the operator and wait for confirmation before tagging or referencing the new version.
7. **Push confirmation:** Before any `git push`, show the operator a summary of what will be pushed (commits, branch, remote) and wait for explicit confirmation.
8. **Commit messages:** Must not contain real hostnames, IPs, or infrastructure identifiers.

## Versioning & Releases

SemVer (`MAJOR.MINOR.PATCH`). Git tags are the source of truth.

```bash
git tag v1.2.3 && git push origin v1.2.3
```

This triggers the Docker workflow which publishes:
- `ghcr.io/lobo235/vault-gateway:v1.2.3`
- `ghcr.io/lobo235/vault-gateway:v1.2`
- `ghcr.io/lobo235/vault-gateway:latest`
- `ghcr.io/lobo235/vault-gateway:<short-sha>`

Version is embedded at build time: `-ldflags "-X main.version=v1.2.3"` — defaults to `"dev"` for local builds. Exposed in `GET /health` response and logged on startup.

## Docker

```bash
# Build (version defaults to "dev")
docker build -t vault-gateway .

# Build with explicit version
docker build --build-arg VERSION=v1.2.3 -t vault-gateway .

# Run
docker run --env-file .env -p 8080:8080 vault-gateway
```

Multi-stage build: `golang:1.24-alpine` → `alpine:3.21`. Statically compiled (`CGO_ENABLED=0`).

## Known Limitations

- **AppRole token renewal:** If Vault is unreachable during token renewal, the client falls back to full re-authentication. If re-auth also fails, subsequent Vault calls will fail until connectivity is restored.
- **No pagination:** The secrets API does not support listing all secrets — it operates on individual server names only.
- **Password not returned on create:** POST does not return the generated RCON password. Callers must use GET to retrieve it (by design — only minecraft-gateway should read passwords).
