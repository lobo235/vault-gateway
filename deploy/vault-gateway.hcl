job "vault-gateway" {
  node_pool   = "default"
  datacenters = ["dc1"]
  type        = "service"

  group "vault-gateway" {
    count = 1

    network {
      port "http" {
        to = 8080
      }
    }

    service {
      name     = "vault-gateway"
      port     = "http"
      provider = "consul"
      tags = [
        "traefik.enable=true",
        "traefik.http.routers.vault-gateway.rule=Host(`vault-gateway.example.com`)",
        "traefik.http.routers.vault-gateway.entrypoints=websecure",
        "traefik.http.routers.vault-gateway.tls=true",
      ]

      check {
        type     = "http"
        path     = "/health"
        port     = "http"
        interval = "30s"
        timeout  = "5s"

        check_restart {
          limit = 3
          grace = "30s"
        }
      }
    }

    restart {
      attempts = 3
      interval = "2m"
      delay    = "15s"
      mode     = "fail"
    }

    vault {
      cluster     = "default"
      change_mode = "restart"
    }

    task "vault-gateway" {
      driver = "docker"

      config {
        image = "ghcr.io/lobo235/vault-gateway:latest"
        ports = ["http"]
      }

      template {
        data = <<EOF
{{ with secret "kv/data/nomad/default/vault-gateway" }}
VAULT_ROLE_ID={{ .Data.data.vault_role_id }}
VAULT_SECRET_ID={{ .Data.data.vault_secret_id }}
GATEWAY_API_KEY={{ .Data.data.gateway_api_key }}
{{ end }}
EOF
        destination = "secrets/vault-gateway.env"
        env         = true
      }

      env {
        PORT       = "8080"
        LOG_LEVEL  = "info"
        VAULT_ADDR = "https://vault.example.com:8200"
      }

      resources {
        cpu    = 100
        memory = 64
      }

      kill_timeout = "35s"
    }
  }
}
