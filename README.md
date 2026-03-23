# vault-gateway

A narrowly-scoped HTTP API that wraps HashiCorp Vault for per-server secret management. Part of the [homelab-ai](https://github.com/lobo235/homelab-ai) platform.

## What it does

- Generates cryptographically random RCON passwords for Minecraft servers
- Stores/reads/rotates/deletes secrets in Vault KV v2
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
| POST | `/secrets/minecraft/{serverName}` | Create secrets (auto-generates RCON password) |
| GET | `/secrets/minecraft/{serverName}` | Read secrets |
| PUT | `/secrets/minecraft/{serverName}` | Rotate RCON password |
| DELETE | `/secrets/minecraft/{serverName}` | Delete all secret versions |

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
