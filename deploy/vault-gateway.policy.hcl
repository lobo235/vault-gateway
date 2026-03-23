# vault-gateway Vault policy — least privilege for KV v2 secret management
# Apply with: vault policy write vault-gateway deploy/vault-gateway.policy.hcl

# KV v2: read/write data lives under kv/data/...
path "kv/data/nomad/default/*" {
  capabilities = ["create", "read", "update", "delete"]
}

# KV v2: metadata/list/delete lives under kv/metadata/...
path "kv/metadata/nomad/default/*" {
  capabilities = ["read", "delete", "list"]
}
