# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.0.1] - 2026-03-24

### Fixed
- Token TTL parsing handles `json.Number` type from Vault API — was always falling back to 60s renewal interval instead of using actual token TTL

### Changed
- Docker build workflow resolves version from git tags for non-tag builds

## [v1.0.0] - 2026-03-23

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
