# vault-gateway

A narrowly-scoped HTTP API that wraps HashiCorp Vault for secret management. Part of the [homelab-ai](https://github.com/lobo235/homelab-ai) platform.

## What it does

- Generates cryptographically random RCON passwords for Minecraft servers
- Stores/reads/rotates/deletes secrets in Vault KV v2
- Supports generic category-based secrets for non-Minecraft workloads
- Authenticates to Vault via AppRole with automatic token renewal
- Enforces strict path prefix validation (`kv/data/nomad/default/*`)

## Quick Start

```bash
cp .env.example .env
# Fill in VAULT_ADDR, VAULT_ROLE_ID, VAULT_SECRET_ID, GATEWAY_API_KEY
go run ./cmd/server
```

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (unauthenticated) |
| POST | `/secrets/minecraft/{serverName}` | Create Minecraft secrets (auto-generates RCON password) |
| GET | `/secrets/minecraft/{serverName}` | Read Minecraft secrets |
| PUT | `/secrets/minecraft/{serverName}` | Rotate RCON password |
| DELETE | `/secrets/minecraft/{serverName}` | Delete all Minecraft secret versions |
| POST | `/secrets/{category}/{name}` | Create generic secret (caller-supplied key-value data) |
| GET | `/secrets/{category}/{name}` | Read generic secret |
| PUT | `/secrets/{category}/{name}` | Update generic secret |
| DELETE | `/secrets/{category}/{name}` | Delete generic secret |

All endpoints except `/health` require `Authorization: Bearer <GATEWAY_API_KEY>`.

## Build

```bash
make build    # Build binary
make test     # Run tests
make lint     # Run linter
make cover    # Coverage report
```

## Docker

```bash
docker build -t vault-gateway .
docker run --env-file .env -p 8080:8080 vault-gateway
```

## License

Private — internal homelab use only.
