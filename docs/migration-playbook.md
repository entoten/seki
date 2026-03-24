# Migration Playbook

## Overview

This playbook covers end-to-end migration from an existing identity provider to seki. Choose the right tool for the job:

| Approach | Best for | Notes |
|----------|----------|-------|
| `seki-migrate` CLI | Auth0, Keycloak, Okta, Clerk exports | Handles provider-specific JSON formats automatically |
| Admin API (bulk import) | Custom/self-built auth systems | POST CSV or JSON to `/api/v1/import/users` |
| SCIM provisioning | Ongoing sync from an upstream IdP | Real-time user lifecycle management |

### Decision flowchart

```
Migrating from a supported provider (Auth0/Keycloak/Okta/Clerk)?
  YES -> Use seki-migrate CLI with the provider's export file
  NO  -> Do you have users in CSV or JSON?
           YES -> Use the Admin API bulk import endpoint
           NO  -> Do you need ongoing sync with an upstream IdP?
                    YES -> Configure SCIM provisioning
                    NO  -> Export users manually, then use Admin API
```

## Pre-Migration Checklist

- [ ] Inventory current users, organizations, roles, and OAuth clients
- [ ] Identify password hash format used by the source system (see matrix below)
- [ ] Plan DNS cutover strategy (instant vs. gradual)
- [ ] Set up seki in parallel (do not replace the existing system yet)
- [ ] Test with a subset of users first (10-50 users)
- [ ] Confirm OIDC client configuration is ready in `seki.yaml`
- [ ] Back up the source identity provider data
- [ ] Notify stakeholders about the planned migration window
- [ ] Prepare rollback procedure (see below)

## Password Hash Compatibility Matrix

| Source | Hash Format | seki Compatible | Notes |
|--------|-------------|-----------------|-------|
| Auth0 | bcrypt | Yes | Direct import |
| Keycloak | bcrypt / pbkdf2 | Partial | bcrypt = direct import, pbkdf2 = require password reset |
| Okta | bcrypt | Yes | Direct import |
| Clerk | bcrypt | Yes | Direct import |
| Custom (bcrypt) | `$2a$` / `$2b$` | Yes | Direct import |
| Custom (argon2id) | `$argon2id$` | Yes | Direct import |
| Custom (scrypt) | scrypt | No | Users must reset password |
| Custom (pbkdf2) | pbkdf2 | No | Users must reset password |
| Custom (MD5/SHA) | varies | No | Users must reset password |

## Source-Specific Guides

### Auth0 to seki

1. **Export users** via the Auth0 Management API:
   ```bash
   curl -H "Authorization: Bearer $AUTH0_TOKEN" \
     "https://YOUR_DOMAIN.auth0.com/api/v2/users" > auth0-users.json
   ```
   For large tenants, use the [bulk user export job](https://auth0.com/docs/manage-users/user-migration/bulk-user-exports).

2. **Dry run** to preview what will happen:
   ```bash
   ./seki-migrate auth0 --file auth0-users.json --dry-run
   ```

3. **Review the report.** Verify user counts and check for any warnings about unsupported fields.

4. **Run the actual import:**
   ```bash
   ./seki-migrate auth0 \
     --file auth0-users.json \
     --api-url http://localhost:8080 \
     --api-key YOUR_API_KEY
   ```

5. **Configure OIDC clients** in `seki.yaml` to match your Auth0 application settings (client IDs, redirect URIs, allowed origins).

6. **Test the login flow** with a migrated user account.

7. **Update DNS or application config** to point to seki.

8. **Monitor audit logs** for failed logins or errors during the grace period.

9. **Decommission Auth0** after the grace period (typically 2-4 weeks).

### Keycloak to seki

1. **Export the realm** from Keycloak Admin Console:
   - Go to Realm Settings > Action > Partial Export
   - Enable "Include clients" and "Include groups and roles"
   - Download the JSON file

   Or use the CLI:
   ```bash
   bin/kc.sh export --dir /tmp/export --realm my-realm
   ```

2. **Dry run:**
   ```bash
   ./seki-migrate keycloak --file realm-export.json --dry-run
   ```

3. **Review the report.** Pay special attention to users with pbkdf2 password hashes -- they will need to reset their passwords.

4. **Run the actual import:**
   ```bash
   ./seki-migrate keycloak \
     --file realm-export.json \
     --api-url http://localhost:8080 \
     --api-key YOUR_API_KEY
   ```

5. **Configure OIDC clients** in `seki.yaml` to match your Keycloak client settings.

6. **Test the login flow** with a migrated user account.

7. **Update DNS or application config** to point to seki.

8. **Monitor audit logs** for the grace period.

9. **Decommission Keycloak** after confirming all users have migrated successfully.

### Okta to seki

1. **Export users** via the Okta Users API:
   ```bash
   curl -H "Authorization: SSWS $OKTA_TOKEN" \
     "https://YOUR_DOMAIN.okta.com/api/v1/users" > okta-users.json
   ```

2. **Dry run:**
   ```bash
   ./seki-migrate okta --file okta-users.json --dry-run
   ```

3. **Review the report.**

4. **Run the actual import:**
   ```bash
   ./seki-migrate okta \
     --file okta-users.json \
     --api-url http://localhost:8080 \
     --api-key YOUR_API_KEY
   ```

5. **Configure OIDC clients** in `seki.yaml`.

6. **Test the login flow.**

7. **Update DNS or application config** to point to seki.

8. **Monitor audit logs.**

9. **Decommission Okta** after the grace period.

### Clerk to seki

1. **Export users** via the Clerk Backend API:
   ```bash
   curl -H "Authorization: Bearer $CLERK_SECRET_KEY" \
     "https://api.clerk.com/v1/users?limit=500" > clerk-users.json
   ```
   Paginate as needed for larger user bases.

2. **Dry run:**
   ```bash
   ./seki-migrate clerk --file clerk-users.json --dry-run
   ```

3. **Review the report.**

4. **Run the actual import:**
   ```bash
   ./seki-migrate clerk \
     --file clerk-users.json \
     --api-url http://localhost:8080 \
     --api-key YOUR_API_KEY
   ```

5. **Configure OIDC clients** in `seki.yaml`.

6. **Test the login flow.**

7. **Update DNS or application config** to point to seki.

8. **Monitor audit logs.**

9. **Decommission Clerk** after the grace period.

### Custom / Self-built to seki

1. **Export users** to CSV or JSON from your database. Example CSV:
   ```csv
   email,display_name,password_hash
   alice@example.com,Alice,$2a$10$N9qo8uLOickgx2ZMRZoMye...
   bob@example.com,Bob,$2b$12$WApznUPhDubN0oeveSXHp....
   ```

   Example JSON:
   ```json
   [
     {"email": "alice@example.com", "display_name": "Alice", "password_hash": "$2a$10$..."},
     {"email": "bob@example.com", "display_name": "Bob"}
   ]
   ```

2. **Preview the import** with a dry run:
   ```bash
   curl -X POST http://localhost:8080/api/v1/import/users \
     -H "Authorization: Bearer YOUR_API_KEY" \
     -H "Content-Type: application/json" \
     -H "X-Dry-Run: true" \
     -d @users.json
   ```
   Or for CSV:
   ```bash
   curl -X POST http://localhost:8080/api/v1/import/users/csv \
     -H "Authorization: Bearer YOUR_API_KEY" \
     -H "X-Dry-Run: true" \
     --data-binary @users.csv
   ```

3. **Run the actual import** (remove the `X-Dry-Run` header):
   ```bash
   curl -X POST http://localhost:8080/api/v1/import/users \
     -H "Authorization: Bearer YOUR_API_KEY" \
     -H "Content-Type: application/json" \
     -d @users.json
   ```

4. **Configure OIDC** in your application to use seki as the identity provider.

5. **Test login** with imported accounts.

6. **Cut over** DNS or application config to seki.

## Zero-Downtime Migration Pattern

For production systems that cannot tolerate downtime:

1. **Run seki in parallel** with the existing auth system. Both systems should be operational.

2. **Import all users** into seki using `seki-migrate` or the bulk import API.

3. **Update your application** to try seki first, then fall back to the old auth system:
   ```
   Login request
     -> Try seki authentication
       -> Success: proceed
       -> Failure: try old auth system
         -> Success: create/update user in seki, proceed
         -> Failure: reject
   ```

4. **Monitor for 1-2 weeks.** Check audit logs in both systems. Verify that:
   - All active users can log in via seki
   - No users are only authenticating via the old system
   - Error rates are stable

5. **Remove the old auth fallback** once you are confident all users have transitioned.

6. **Decommission the old auth system** after a final grace period.

## Rollback Procedure

If issues arise during or after migration:

1. **Immediate rollback (DNS-based):**
   - Point DNS back to the old auth system
   - seki data is preserved for retry later

2. **Application-level rollback:**
   - Revert the application configuration to use the old auth system
   - No data loss in either system

3. **Partial rollback:**
   - Keep seki running for users who have already migrated
   - Route remaining users to the old system
   - Investigate and fix the issue before continuing

4. **Data cleanup (if needed):**
   - Use the Admin API to delete users that were imported:
     ```bash
     DELETE /api/v1/users/{id}
     ```
   - Or reset and re-import from scratch

## Post-Migration Verification

Run through this checklist after completing the migration:

- [ ] Users can log in with their existing passwords
- [ ] MFA (TOTP / passkeys) works for enrolled users
- [ ] Social login (Google, GitHub, etc.) works if configured
- [ ] API tokens and personal access tokens work
- [ ] Audit logs show login activity
- [ ] Session management works (login, logout, session listing)
- [ ] OAuth2/OIDC flows work (authorization code, refresh tokens)
- [ ] User profile updates work
- [ ] Password reset flow works
- [ ] Email verification flow works
- [ ] Organization membership is correct
- [ ] Role assignments are correct
- [ ] Rate limiting is functioning
- [ ] Monitoring and alerting are connected

## Common Issues and Solutions

### Users cannot log in after migration

**Cause:** Password hashes are in an unsupported format (e.g., pbkdf2, scrypt).

**Solution:** Trigger a password reset for affected users. Use the Admin API to identify users without password credentials and send them reset emails.

### Duplicate email errors during import

**Cause:** The user already exists in seki (from a previous import attempt or manual creation).

**Solution:** The bulk import API automatically skips existing emails and reports them as "skipped" in the response. No action needed.

### Import is slow for large user sets

**Cause:** Individual user creation with duplicate checking takes time at scale.

**Solution:** Split the import into batches of 5,000-10,000 users. Run batches sequentially. Monitor seki's resource usage during import.

### OAuth clients not working after migration

**Cause:** Client IDs, secrets, or redirect URIs do not match between the old system and seki.

**Solution:** Double-check `seki.yaml` client configuration. Ensure redirect URIs exactly match what the application sends (including trailing slashes).

### MFA not working after migration

**Cause:** TOTP secrets or passkey credentials were not migrated.

**Solution:** Users will need to re-enroll in MFA after migration. Communicate this to users before the cutover. Consider disabling MFA enforcement temporarily during the transition.

### Sessions are lost after migration

**Cause:** Sessions from the old auth system are not transferred to seki.

**Solution:** This is expected. Users will need to log in again after the cutover. Plan the migration during a low-traffic window to minimize impact.
