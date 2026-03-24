# Migration Guide: Importing Users from Auth0 and Keycloak

seki includes `seki-migrate`, a CLI tool that imports users, clients, and roles
from Auth0 or Keycloak export files into a running seki instance.

## Prerequisites

- A running seki server with an API key configured
- An export file from your source identity provider (JSON)
- Go 1.22+ (to build from source)

Build the tool:

```bash
go build -o seki-migrate ./cmd/seki-migrate
```

## Exporting from Auth0

### Users

Use the Auth0 Management API to export users:

```bash
curl -H "Authorization: Bearer $AUTH0_TOKEN" \
  "https://YOUR_DOMAIN.auth0.com/api/v2/users" \
  > auth0-users.json
```

For large tenants, use the [Export Users job](https://auth0.com/docs/manage-users/user-migration/bulk-user-exports):

```bash
curl -X POST -H "Authorization: Bearer $AUTH0_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format": "json"}' \
  "https://YOUR_DOMAIN.auth0.com/api/v2/jobs/users-exports"
```

### Clients (optional)

Export your Auth0 applications:

```bash
curl -H "Authorization: Bearer $AUTH0_TOKEN" \
  "https://YOUR_DOMAIN.auth0.com/api/v2/clients" \
  > auth0-clients.json
```

Combine both into a single file:

```json
{
  "users": [...],
  "clients": [...]
}
```

Or pass a bare array of users — both formats are accepted.

### Running the import

```bash
# Dry run first
./seki-migrate auth0 --file auth0-users.json --api-url http://localhost:8080 --api-key YOUR_KEY --dry-run

# Actual import
./seki-migrate auth0 --file auth0-users.json --api-url http://localhost:8080 --api-key YOUR_KEY --verbose
```

## Exporting from Keycloak

### Realm export

Use the Keycloak Admin Console:

1. Go to **Realm Settings** → **Action** → **Partial Export**
2. Toggle **Include clients** and **Include groups and roles**
3. Click **Export** to download the JSON file

Alternatively, use `kc.sh`:

```bash
bin/kc.sh export --dir /tmp/export --realm my-realm
```

The resulting JSON file contains users, clients, roles, and groups.

### Running the import

```bash
# Dry run first
./seki-migrate keycloak --file realm-export.json --api-url http://localhost:8080 --api-key YOUR_KEY --dry-run

# Actual import
./seki-migrate keycloak --file realm-export.json --api-url http://localhost:8080 --api-key YOUR_KEY --verbose
```

## Dry run workflow

Always run with `--dry-run` first. The output shows exactly what will happen:

```
DRY RUN — no changes will be made

Users:
  + CREATE user@example.com (Auth0 ID: auth0|123)
  + CREATE admin@example.com (Auth0 ID: auth0|456)
  ~ SKIP   existing@example.com (Auth0 ID: auth0|789, already exists)

Clients:
  + CREATE my-spa-app (Auth0 Client ID: spa-123)

Summary: 2 users to create, 1 to skip, 1 clients to create, 0 to skip
```

Review the output, then re-run without `--dry-run` to apply changes.

## Password hash compatibility

### Auth0

Auth0 stores passwords as bcrypt hashes. seki also uses bcrypt, so password
hashes are directly compatible. Users can log in with their existing passwords
after migration.

> **Note:** The current version of `seki-migrate` does not automatically import
> password hashes into seki credentials. Use `--skip-passwords` if you want to
> require users to reset their passwords after migration.

### Keycloak

Keycloak supports multiple credential formats:

- **bcrypt** — Directly compatible with seki
- **pbkdf2-sha256** — Requires conversion or password reset

Credential hashes are preserved in user metadata for reference. Automatic
credential import may be added in a future release.

## What gets migrated

| Source entity           | seki entity      | Notes                                    |
|-------------------------|------------------|------------------------------------------|
| Auth0 user              | User             | user_id stored in metadata               |
| Auth0 client            | OAuth client     | client_id and callbacks preserved         |
| Keycloak user           | User             | firstName + lastName → display_name      |
| Keycloak client         | OAuth client     | Only enabled openid-connect clients      |
| Keycloak realm role     | Role             | Built-in roles (offline_access) skipped  |
| Keycloak group          | Organization     | Group name → org name, path → slug       |

## Post-migration verification

After running the migration:

1. **Check the summary output** for any errors
2. **Verify user counts** match expectations:
   ```bash
   seki-cli user list --api-url http://localhost:8080 --api-key YOUR_KEY
   ```
3. **Test login** with a migrated user account
4. **Check client configurations** are correct:
   ```bash
   seki-cli client list
   ```
5. **Review metadata** on imported users to confirm source IDs are preserved

## Environment variables

| Variable       | Description                                      |
|----------------|--------------------------------------------------|
| `SEKI_API_URL` | seki API base URL (default: http://localhost:8080)|
| `SEKI_API_KEY` | API key for authentication                       |

These can be used instead of `--api-url` and `--api-key` flags.
