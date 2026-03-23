# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial scaffold: project structure, go.mod, Makefile, Dockerfile, config, linter
- Vault client with AppRole authentication and automatic token renewal
- KV v2 read/write/delete operations with strict path prefix validation
- RCON password generation (32-char crypto/rand from [a-zA-Z0-9_.-])
- HTTP API endpoints: POST/GET/PUT/DELETE /secrets/minecraft/{serverName}
- Health endpoint with Vault reachability check
- Bearer token authentication middleware
- X-Trace-ID header propagation
- Server name validation (^[a-z0-9][a-z0-9-]{0,47}$)
- Structured JSON logging via log/slog
- Graceful shutdown on SIGINT/SIGTERM
- Full test suite for config, vault client, and API handlers
- Nomad job spec and Vault policy with placeholder values
