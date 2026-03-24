# Terraform Integration for seki

seki does not ship a native Terraform provider (the HashiCorp provider SDK is
out of scope for v0.3). Instead you can manage seki resources with Terraform
today using the generic **restapi** provider or the built-in **http** data
source.

This guide covers:

1. Provider configuration
2. Managing OAuth clients
3. Managing organizations
4. Managing users

---

## Prerequisites

- Terraform >= 1.0
- A running seki instance with an admin API key

## Provider Setup

The [`Mastercard/restapi`](https://registry.terraform.io/providers/Mastercard/restapi/latest)
provider lets you CRUD any JSON-based REST resource:

```hcl
terraform {
  required_providers {
    restapi = {
      source  = "Mastercard/restapi"
      version = "~> 1.18"
    }
  }
}

provider "restapi" {
  uri                  = var.seki_url
  write_returns_object = true
  headers = {
    Authorization = "Bearer ${var.seki_api_key}"
    Content-Type  = "application/json"
  }
}
```

## Managing OAuth Clients

```hcl
resource "restapi_object" "app_client" {
  path         = "/api/v1/clients"
  id_attribute = "id"
  data = jsonencode({
    id            = "my-app"
    name          = "My Application"
    redirect_uris = ["https://app.example.com/callback"]
    grant_types   = ["authorization_code"]
    scopes        = ["openid", "profile", "email"]
    pkce_required = true
  })
}
```

## Managing Organizations

```hcl
resource "restapi_object" "acme_org" {
  path         = "/api/v1/orgs"
  id_attribute = "slug"
  data = jsonencode({
    slug    = "acme"
    name    = "Acme Corp"
    domains = ["acme.com"]
  })
}
```

## Managing Users

```hcl
resource "restapi_object" "alice" {
  path         = "/api/v1/users"
  id_attribute = "id"
  data = jsonencode({
    email        = "alice@acme.com"
    display_name = "Alice"
    metadata     = {}
  })
}
```

## Reading Resources with the http Data Source

If you only need to read seki data (no create/update/delete), you can use the
built-in `http` data source without any extra providers:

```hcl
data "http" "clients" {
  url = "${var.seki_url}/api/v1/clients"
  request_headers = {
    Authorization = "Bearer ${var.seki_api_key}"
  }
}

locals {
  clients = jsondecode(data.http.clients.response_body).data
}
```

## Examples

See the [`examples/basic/`](examples/basic/) directory for a complete working
configuration that provisions an OAuth client and an organization.

## Go Client Library

seki also ships a Go client library at `pkg/client` that can be used from
custom tooling or a future native Terraform provider. See the package
documentation for details:

```go
import "github.com/Monet/seki/pkg/client"

c := client.New("http://localhost:8080", "my-api-key")
oc, err := c.CreateClient(ctx, client.CreateClientInput{
    ID:   "my-app",
    Name: "My Application",
    RedirectURIs: []string{"https://app.example.com/callback"},
    GrantTypes:   []string{"authorization_code"},
    Scopes:       []string{"openid", "profile"},
})
```
