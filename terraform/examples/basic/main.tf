terraform {
  required_providers {
    restapi = {
      source  = "Mastercard/restapi"
      version = "~> 1.18"
    }
  }
}

# -----------------------------------------------------------------------------
# Provider
# -----------------------------------------------------------------------------

provider "restapi" {
  uri                  = var.seki_url
  write_returns_object = true
  headers = {
    Authorization = "Bearer ${var.seki_api_key}"
    Content-Type  = "application/json"
  }
}

# -----------------------------------------------------------------------------
# OAuth Client
# -----------------------------------------------------------------------------

resource "restapi_object" "app_client" {
  path         = "/api/v1/clients"
  id_attribute = "id"
  data = jsonencode({
    id            = "my-web-app"
    name          = "My Web Application"
    redirect_uris = ["https://app.example.com/callback"]
    grant_types   = ["authorization_code"]
    scopes        = ["openid", "profile", "email"]
    pkce_required = true
  })
}

# -----------------------------------------------------------------------------
# Organization
# -----------------------------------------------------------------------------

resource "restapi_object" "acme_org" {
  path         = "/api/v1/orgs"
  id_attribute = "slug"
  data = jsonencode({
    slug    = "acme"
    name    = "Acme Corp"
    domains = ["acme.com"]
  })
}
