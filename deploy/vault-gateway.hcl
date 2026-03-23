job "vault-gateway" {
  datacenters = ["dc1"]
  type        = "service"
  node_pool   = "default"

  group "vault-gateway" {
    count = 1

    network {
      port "http" {
        static = 8080
      }
    }

    task "vault-gateway" {
      driver = "docker"

      config {
        image = "ghcr.io/lobo235/vault-gateway:latest"
        ports = ["http"]
        volumes = ["/path/to/data:/data"]
      }

      env {
        PORT      = "${NOMAD_PORT_http}"
        LOG_LEVEL = "info"
      }

      template {
        data        = <<-EOF
          VAULT_ADDR={{ with nomadVar "nomad/jobs/vault-gateway" }}{{ .vault_addr }}{{ end }}
          VAULT_ROLE_ID={{ with nomadVar "nomad/jobs/vault-gateway" }}{{ .vault_role_id }}{{ end }}
          VAULT_SECRET_ID={{ with nomadVar "nomad/jobs/vault-gateway" }}{{ .vault_secret_id }}{{ end }}
          GATEWAY_API_KEY={{ with nomadVar "nomad/jobs/vault-gateway" }}{{ .gateway_api_key }}{{ end }}
        EOF
        destination = "secrets/env.env"
        env         = true
      }

      resources {
        cpu    = 100
        memory = 64
      }

      service {
        name = "vault-gateway"
        port = "http"
        tags = ["http"]

        check {
          type     = "http"
          path     = "/health"
          interval = "15s"
          timeout  = "5s"
        }
      }
    }
  }
}
