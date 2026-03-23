# Authentication Platform Failures, Pain Points & Anti-Patterns

> Research report for the Seki project -- compiled March 2026.
> Focus: what went **wrong** with existing open-source auth/identity platforms, not feature lists.

---

## Table of Contents

1. [Keycloak](#1-keycloak)
2. [Zitadel](#2-zitadel)
3. [Authentik](#3-authentik)
4. [Dex](#4-dex)
5. [Casdoor](#5-casdoor)
6. [Ory (Hydra / Kratos)](#6-ory-hydra--kratos)
7. [General Auth Server Anti-Patterns](#7-general-auth-server-anti-patterns)
8. [OIDC Implementation Gotchas](#8-oidc-implementation-gotchas)
9. [WebAuthn / Passkey Implementation Lessons](#9-webauthn--passkey-implementation-lessons)
10. [Session Management Pitfalls](#10-session-management-pitfalls)
11. [Key Takeaways for Seki](#11-key-takeaways-for-seki)

---

## 1. Keycloak

### Top Pain Points

**1. Resource overhead and JVM tax**
Keycloak requires a minimum of ~1,250 MB RAM per pod (70% heap + 300 MB non-heap). Users report constantly increasing memory usage over time without proper garbage collection, suggesting memory leaks (GitHub issue #28211). Startup memory consumption has regressed in recent versions -- users had to increase max heap from 256 MB to 512 MB just to avoid OOM during boot (issue #45662). This makes Keycloak impractical for lightweight or edge deployments.

**2. Session loss on restarts**
One of the most reported pain points: Keycloak loses all user sessions on restart when using default in-memory storage. Persistent user sessions were not scheduled until Keycloak 26 (GitHub Discussion #28271). Countless workarounds exist, all unsupported and with trade-offs. This is a fundamental architectural flaw -- an auth server that logs out all users on deploy is operationally unacceptable.

**3. Migration is a minefield**
- Migrating from version 11.0 to 24.0.4 fails outright with duplicate insertion errors (issue #30497).
- Migration gets stuck if versions are incompatible, with no clear error messages (issue #30449).
- The WildFly-to-Quarkus migration was a mass breaking change: custom providers needed rebuilding, configurations changed, endpoints moved.
- The project actively "discourages jumping multiple major releases," effectively requiring serial upgrades.
- A real-world migration of 20M+ users hit severe bottlenecks: requests piled up in event loops, DB connections saturated, Keycloak accumulated tens of thousands of stuck active requests.

**4. Customization requires deep Java expertise**
Extending Keycloak means writing Java JARs, understanding Service Provider Interfaces (SPIs), and deploying them into the runtime. Developers describe this as "not fun." Modifying authentication flows requires "advanced Java programming knowledge." This creates a hard lock-in to the Java ecosystem and makes the platform inaccessible to teams without JVM specialists.

**5. Multi-tenant scaling breaks down**
Keycloak struggles beyond 100-200 realms due to inefficient JPA entity loading. Recursive role traversal algorithms degrade with large role hierarchies. The embedded Infinispan cache is not optimized for multi-zone deployments. Users describe large multi-tenant deployments as "practically unusable."

### Architectural Decisions That Caused Problems

- **Java/Quarkus runtime**: Heavy memory footprint, slow startup, requires JVM tuning expertise
- **Infinispan for caching/sessions**: Complex to operate, not designed for geo-distributed deployments
- **JPA/Hibernate ORM**: Inefficient queries at scale, especially for multi-realm configurations
- **SPI extensibility model**: Powerful but requires building and deploying JAR files -- extremely high friction
- **In-memory default sessions**: Data loss on restart; external session store was an afterthought

### What Users Wish Was Different

- Lightweight runtime that doesn't need 1+ GB RAM
- Sessions persisted by default, not as an opt-in afterthought
- Configuration possible without the admin UI (infrastructure-as-code friendly)
- Extension model that doesn't require Java
- Smooth major-version upgrades with automated migration tooling
- Documentation that covers real-world scenarios, not just happy paths

### Security Incidents / Concerns

Continuous stream of CVEs: CVE-2024-8698 (SAML validation bypass), CVE-2024-7260 (open redirect), CVE-2023-6787 (session fixation), CVE-2023-6563 (DoS via resource exhaustion). The system's complexity itself is a security risk -- misconfiguration causes SSO loops, improper SAML validation, and unintended token exposure.

---

## 2. Zitadel

### Top Pain Points

**1. Event sourcing / CQRS complexity for self-hosters**
Zitadel's entire architecture is built on event sourcing with CQRS. The command side writes events; a spooler polls every 100ms for new events and projects read models. While elegant for audit trails, this introduces operational complexity that most self-hosters aren't prepared for. Users on HN explicitly cite event sourcing as their primary concern, preferring "regular state saving with audit log" approaches.

**2. CockroachDB dependency (now deprecated)**
Zitadel originally required CockroachDB, an unusual choice that added significant operational burden for self-hosters. They have since deprecated CockroachDB support in v3 and moved to PostgreSQL-only, but the migration path is broken:
- Mirroring from CockroachDB to Postgres fails with missing `instance_id` columns (issue #8558)
- Migration errors on constraint violations (issue #9042)
- DB migration verification fails with timeouts post-v2.69 (issue #9741)
- Users who adopted Zitadel early with CockroachDB now face a painful forced migration.

**3. Silent failures and brittle self-hosting**
The Zitadel service can become unhealthy without any visible error or log output (issue #11651). Users describe self-hosting as "brittle" -- configuration complexity punishes self-hosters, silent failures waste debugging time, and API instability erodes trust. One detailed blog post ("Brittle ZITADEL!") documents these frustrations extensively.

**4. Breaking changes on upgrades**
Upgrading from v3.x to v4.x immediately invalidated all tokens (issue #10673). The Actions V1 to V2 migration replaced inline JavaScript execution with an external webhook model, introducing network round-trip latency and new failure modes from webhook unavailability. These are not graceful transitions.

**5. Account linking and authentication flow bugs**
Multiple issues with the account linking flow: usernames aren't in readable format, forms allow linking to accounts that shouldn't be linkable, SAML IdP linking fails with validation errors. Users can get stuck on 2FA setup screens with no exit path except clearing cookies.

### Architectural Decisions That Caused Problems

- **Event sourcing as the core model**: Overkill for most self-hosted deployments; adds latency (100ms polling), complexity, and debugging difficulty
- **CockroachDB as initial database**: Forced an unusual operational dependency that was later abandoned, leaving early adopters stranded
- **Internal pub/sub instead of external message queue**: Tight coupling that limits scaling options
- **Actions V2 webhook model**: Replaced simple inline JS with network-dependent webhooks, adding failure modes

### What Users Wish Was Different

- Simpler self-hosted setup that doesn't require CQRS expertise
- Stable API contracts across major versions
- Visible error reporting instead of silent failures
- Smoother CockroachDB-to-Postgres migration tooling
- Less "enterprisy" UI -- some users find it requires too much configuration

---

## 3. Authentik

### Top Pain Points

**1. Python/Django performance penalty**
Authentik's own team acknowledges it is "500% slower to run" than compiled alternatives due to Python/Django. The baseline memory footprint is ~512 MB for the auth server alone, compared to <150 MB for Go-based alternatives like Zitadel or Authelia. Customers have complained about performance issues when new features are added.

**2. High idle resource consumption**
Even when inactive, Authentik server and worker containers consume surprising amounts of resources (GitHub issue #2159). This is a fundamental characteristic of the Django runtime and Celery worker model, not something easily optimized away.

**3. Task queue flooding (post-Redis removal)**
Since the 2025.10.0 release, which removed the Redis dependency and moved to PostgreSQL for job queuing, users report "enormous numbers of system tasks unable to be processed in time" -- pending tasks piling up to 500+ even with 2 workers at 8 cores each on NVMe storage (issue #18368). This is a classic case of an architectural change (removing Redis) causing a regression in a critical subsystem.

**4. No native high availability**
Users requesting HA capabilities (load balancing, secondary synchronized servers) found this unsupported (issue #2460). For a system that sits in the critical authentication path, lack of HA is a serious operational risk.

**5. Complex initial setup**
Multiple sources describe Authentik as "one of the most difficult services I ever set up." The flow-based configuration system, while powerful, has a steep learning curve. Users report multiple failed installation attempts before succeeding.

### Architectural Decisions That Caused Problems

- **Python/Django runtime**: 5x slower than compiled languages; high memory baseline; limits deployment on resource-constrained environments
- **Celery worker model**: Adds operational complexity (separate worker processes, task queue management)
- **Redis removal without adequate replacement**: Moving job queuing to Postgres caused task flooding
- **No HA design from the start**: Retrofitting HA into a system not designed for it is extremely difficult

### What Users Wish Was Different

- Lower resource footprint (the 512 MB minimum is a non-starter for many self-hosters)
- Built-in high availability
- Simpler initial setup experience
- Better performance under load without requiring dedicated optimization work

---

## 4. Dex

### Top Pain Points

**1. Not a complete identity system -- just a shim**
Dex explicitly does not manage users. It is a "shim between a client app and the upstream identity provider." This means you always need another system (LDAP, GitHub, etc.) for actual user storage. Teams that need user management, password resets, or self-service registration must bolt on additional systems.

**2. No admin UI or management interface**
Dex is entirely configuration-file driven with no graphical management. While this appeals to infrastructure-as-code practitioners, it makes Dex inaccessible to teams that need operational visibility or non-engineer administrators.

**3. Refresh token limitations by connector**
Groups claims in the OIDC connector only refresh when the ID token itself is refreshed. SAML connectors cannot issue refresh tokens at all because SAML lacks non-interactive assertion refresh. This means clients requiring `offline_access` (like kubectl) cannot work with SAML-backed Dex. These are protocol-level limitations that Dex surfaces but cannot solve.

**4. Minimal feature set limits adoption**
Dex provides OIDC federation and little else. No MFA, no user self-service, no consent management, no admin API beyond basic configuration. Projects that start with Dex for its simplicity often outgrow it and must migrate to a more complete solution.

**5. Small community, niche use case**
Dex is primarily used in the Kubernetes ecosystem (ArgoCD, Kubernetes OIDC). Outside that niche, adoption is limited, which means fewer integrations, less documentation, and slower bug fixes.

### Architectural Decisions That Caused Problems

- **Shim-only design**: Forces dependency on external user stores for any real-world deployment
- **Static configuration**: No runtime API for managing clients or connectors (config file reloads required)
- **Connector abstraction leaks protocol limitations**: SAML's inability to refresh assertions bleeds through to end users

### What Users Wish Was Different

- Optional built-in user store for simple deployments
- Runtime API for client and connector management
- MFA support
- Better group claim handling across connector types

---

## 5. Casdoor

### Top Pain Points

**1. Serious security vulnerabilities**
- **CVE-2022-24124**: Unauthenticated SQL injection in the query API (CVSS 7.5). The `field` parameter was inserted directly into raw SQL. Proof-of-concept exploits are publicly available. This is a basic input sanitization failure that should never exist in an auth server.
- **Arbitrary file deletion vulnerability** (pre-v1.126.1) via the `uploadFile` function.
- **Cross-organizational access bypass** (pre-v2.63.0): Administrators of any organization could bypass permission checks by URL manipulation to edit other organizations' applications and settings.

**2. Code quality concerns**
The SQL injection vulnerability (inserting user input directly into raw SQL) indicates fundamental code quality issues. An auth server that fails basic input sanitization cannot be trusted with security-critical workloads.

**3. Unclear security posture**
The project requests that security issues be reported via email rather than public GitHub issues, which is standard practice -- but combined with the severity and nature of past vulnerabilities, it raises questions about internal security review processes.

**4. "AI-first" marketing vs. security focus**
Casdoor's current branding emphasizes "AI-first Identity and Access Management" with MCP gateway support. This marketing-driven feature expansion contrasts with the fundamental security issues that have been discovered, suggesting priorities may not be aligned with the core mission of an auth server: being secure.

### Architectural Decisions That Caused Problems

- **Insufficient input sanitization**: Raw SQL construction from user input
- **Weak authorization model**: Organization admins could access other orgs via URL manipulation
- **Broad feature surface without security depth**: Many protocols supported (OAuth, OIDC, SAML, CAS, LDAP, SCIM, WebAuthn, TOTP, MFA, Face ID) but with shallow security implementation

---

## 6. Ory (Hydra / Kratos)

### Top Pain Points

**1. Split-service architecture creates integration hell**
Ory splits identity (Kratos), OAuth/OIDC (Hydra), permissions (Keto), and API gateway (Oathkeeper) into separate services. Users report that configuring Kratos to work with Hydra is poorly documented and confusing:
- "While Hydra 2.0 release notes state that Kratos can be used as the IdP, guidance on what configuration is meant is lacking"
- Integration branches in documentation are "outdated and not compatible with current versions"
- Calling `updateLoginFlow` to Kratos does not trigger the expected Hydra callback
- Users describe the combined flow as "fairly complicated" and say the complexity pushes them back to Keycloak

**2. "Bring Your Own UI" becomes "Build Your Own UI from Scratch"**
Kratos is headless -- no login UI provided. The self-service UI rendering is described as "becoming kind of absurdly complicated." Specific complaints:
- Implicit, undocumented rules for rendering UI nodes ("usually but not always the default group should be included")
- Rendering a password form requires pulling the "identifier" node from a different node group -- only discoverable by reading `@ory/elements` source code
- The backend knows user state and enabled auth methods but still returns unnecessary nodes, forcing the frontend to re-implement backend logic
- No 1:1 mapping between form groups and UI elements, requiring custom filtering logic
- "The combinatorial explosion of options was just too much, leaving them changing values without really understanding the consequences"

**3. Documentation gaps between services**
Each Ory service has its own documentation, but the integration points between them are poorly covered. The critical question "how do I set up Kratos + Hydra together?" has no clear, maintained answer. One developer converting Kratos session cookies into Hydra access tokens had to figure it out from scratch.

**4. Ory Network vs. open-source divergence**
Ory increasingly pushes users toward their hosted Ory Network product. The open-source self-hosted path receives less attention and documentation, creating a two-tier experience that frustrates open-source users.

**5. Operational complexity of running 4 services**
Running Kratos + Hydra + Oathkeeper + Keto means managing 4 separate services, each with its own database, configuration, and health monitoring. Users note this makes them "look again at Keycloak since it would probably be simpler."

### Architectural Decisions That Caused Problems

- **Microservice decomposition of auth**: Splitting auth into 4 services adds deployment, networking, and debugging complexity without proportional benefit for most use cases
- **Headless UI philosophy**: Maximum flexibility at the cost of massive implementation burden on every consumer
- **Implicit UI node rendering rules**: API responses require undocumented client-side logic to render correctly
- **Separate databases per service**: Multiplies operational burden

### What Users Wish Was Different

- A single-binary deployment option that bundles core auth functionality
- Reference UI that works out of the box (not just a "reference" that requires deep customization)
- Clear, maintained documentation for multi-service integration
- UI API responses that are self-describing (no implicit rendering rules)

---

## 7. General Auth Server Anti-Patterns

### Token Storage Mistakes

1. **Storing tokens in localStorage**: Vulnerable to XSS attacks. Any JavaScript running on the page can read tokens. This is the single most common auth implementation mistake.

2. **Storing tokens in non-HttpOnly cookies**: Same XSS risk as localStorage but with additional CSRF exposure.

3. **Not using the Backend-for-Frontend (BFF) pattern for SPAs**: The recommended approach is to keep tokens server-side and use session cookies between the SPA and its backend. Most auth servers don't make this easy.

4. **Long-lived access tokens**: Issuing access tokens with hours-long or day-long lifetimes instead of 15-60 minutes. Longer tokens mean longer windows of exploitation after compromise.

5. **Not rotating refresh tokens**: OAuth 2.1 recommends rotating refresh tokens after every use and automatically invalidating reused tokens (detecting token theft). Many implementations skip this.

6. **Hardcoding IdP public keys**: Fails on key rotation. Must dynamically fetch from `.well-known/jwks_uri` with appropriate caching.

### Architecture Anti-Patterns

1. **In-memory session storage as default**: Sessions lost on restart/deploy (Keycloak's original sin).

2. **Monolithic database schema**: Auth systems that store everything in one massive relational schema become migration nightmares at scale.

3. **Tight coupling to a specific database**: CockroachDB (Zitadel) or specific PostgreSQL features create operational lock-in.

4. **Extension via compiled plugins**: Requiring JAR files (Keycloak) or Go plugins creates a prohibitively high barrier to customization.

5. **Event sourcing for auth state**: Adds complexity without proportional benefit for most deployments. Simple state + audit log achieves similar goals with far less operational overhead.

---

## 8. OIDC Implementation Gotchas

### Critical Implementation Errors

1. **Decoding JWTs without validating**: `jwt.decode()` is NOT validation. Must verify: signature (against JWKS), `iss` (issuer), `aud` (audience matches your client_id), `exp` (expiration), `nbf` (not-before). Skipping any of these enables token forgery or confused-deputy attacks.

2. **Not restricting accepted algorithms**: Accepting any algorithm the token claims to use enables algorithm confusion attacks. Explicitly allowlist `ES256` or `RS256`. Never accept `none`.

3. **Wildcard redirect URIs**: `https://*.example.com/*` combined with any open redirect on a subdomain allows authorization code theft. Always use exact string matching for redirect URIs.

4. **Using access tokens for authentication**: Access tokens authorize API access; they do not identify users. Use ID tokens for authentication. This is the fundamental OAuth vs. OIDC distinction that most developers get wrong.

5. **Client secrets in frontend code**: SPAs and native apps must use PKCE, not client secrets. Client secrets in JavaScript bundles are visible to anyone who views source.

6. **Overly broad `sub` claims in CI/CD OIDC**: Wildcards like `repo:my-org/*` in trust policies grant cloud credentials to any workflow in the org.

7. **Not validating `at_hash` in ID tokens**: When an ID token is issued alongside an access token in the authorization code flow, the `at_hash` claim binds them. Not verifying this allows token substitution.

### Provider-Side Gotchas

1. **Discovery document caching**: The `.well-known/openid-configuration` endpoint should be cacheable but must update when keys rotate. Getting cache TTLs wrong causes either stale keys (auth failures) or excessive fetching (performance hit).

2. **PKCE storage**: The code challenge must be stored server-side and verified on token exchange. Stateless implementations that encode challenges in the authorization code itself must ensure tamper-proof encoding.

3. **Consent screen state management**: The consent flow is a multi-step redirect chain. Losing state between steps (e.g., across load-balanced servers without shared state) breaks the flow silently.

---

## 9. WebAuthn / Passkey Implementation Lessons

### The Complexity is Severely Underestimated

Passkey implementation is described as "100x harder than you think" by practitioners who have shipped it. Key reasons:

### Technical Pitfalls

1. **Two-round-trip registration**: Registration requires: (a) backend generates challenge -> (b) browser calls `navigator.credentials.create()` -> (c) backend verifies and stores credential. Each step has encoding requirements (Base64URL for challenges, COSE for public keys, CBOR for authenticator data). Most WebAuthn server libraries do NOT provide credential storage -- you must design the schema yourself.

2. **Passkey availability is undetectable**: Privacy-by-design prevents browsers from revealing whether a passkey exists on a device before authentication. You can only check if the browser *supports* WebAuthn, not if the user *has* a passkey. This makes conditional UI logic extremely fragile.

3. **Cross-device authentication (CDA) is unreliable**: QR code flows trigger when `allowCredentials` entries aren't found locally. But 40+ combinations of OS versions, browser versions, and credential options produce different behaviors. Windows 10 without Bluetooth cannot do CDA at all but may show confusing dialogs.

4. **Client-side deletion creates orphaned server credentials**: When a user deletes a passkey from their device/password manager, the server receives no notification. The credential still exists server-side but will never work again. Must implement "passkey intelligence" to detect and clean up inactive credentials.

5. **User.id changes break everything**: If `user.id` changes (common during email changes or account migrations), passkey lookups fail even though the credential is still valid on the device.

### UX Pitfalls

6. **Fallback strategy is not optional**: Must support fallback auth (email OTP, passwords, social login) for devices that don't support passkeys, users who lose devices, and users who cancel passkey flows. The most dangerous gap is a weak recovery strategy.

7. **Conditional UI varies wildly by platform**: Safari shows a modal for the last used passkey; Chrome shows a dropdown with multiple options (iCloud Keychain, stored devices, CDA). These cannot be customized or controlled.

8. **User agent parsing is dying**: Browser fingerprinting for device recognition is breaking as Chromium reduces User-Agent detail and Firefox follows suit. Must use Client Hints API, but Safari doesn't support it.

### Testing Pitfalls

9. **HTTPS required everywhere**: WebAuthn only works in secure contexts. `localhost` gets an exception, but testing across real devices requires proper TLS. Local IP addresses are invalid for Relying Party IDs.

10. **Performance degrades at scale**: Authenticators with 200+ stored passkeys (especially Windows Hello) show degraded performance.

### Key Lesson for Seki

Passkey support must be treated as a first-class subsystem, not a bolt-on. It requires: credential lifecycle management, device-credential relationship tracking, fallback authentication strategies, and cross-platform testing infrastructure. "Passkeys kill passwords, not session hijacking" -- session security remains independently critical.

---

## 10. Session Management Pitfalls

### Common Mistakes

1. **Client-side-only logout**: Only clearing the cookie without invalidating the server-side session. An attacker who captured the session cookie can continue using it after the user "logs out."

2. **Session fixation on login**: Not generating a new session ID after successful authentication. If the session ID was set before login (e.g., for CSRF tracking), an attacker who knows the pre-auth session ID inherits the authenticated session.

3. **No absolute timeout**: Relying solely on idle timeout means active sessions live forever. Applications that reset the expiry on every request keep sessions alive indefinitely. Must implement both idle timeout AND absolute maximum session lifetime.

4. **Extending token lifetime for "remember me"**: Using long-lived primary session tokens for persistent login. Correct approach: issue a separate long-lived token in a secure HttpOnly cookie that triggers re-authentication, not a longer primary session.

5. **Multiple cookies without cross-verification**: When multiple cookies are set for a session, all must be verified together. Attackers can exploit pre-authentication cookies to access authenticated sessions if relationships aren't enforced.

### Recent Breaches Highlighting These Issues (2024-2025)

- Microsoft's OAuth exploitation
- Oracle Cloud's 6 million record breach
- Multiple JWT implementation flaws enabling unauthorized access (CVEs highlighting algorithm confusion attacks)

These demonstrate that SSO implementations create single points of failure when session management is weak.

---

## 11. Key Takeaways for Seki

### What to Avoid

| Anti-Pattern | Seen In | Impact |
|---|---|---|
| JVM/Python runtime for auth server | Keycloak, Authentik | 500MB-1.2GB RAM baseline; slow startup |
| In-memory sessions as default | Keycloak | Session loss on deploy |
| Event sourcing for core state | Zitadel | Operational complexity disproportionate to benefit |
| Microservice decomposition of auth | Ory | Integration hell, documentation debt |
| Headless-only (no UI) | Ory Kratos, Dex | Massive implementation burden on every consumer |
| Extension via compiled plugins | Keycloak (JARs) | High friction customization |
| Raw SQL from user input | Casdoor | Instant critical vulnerability |
| Tight coupling to exotic databases | Zitadel (CockroachDB) | Forced painful migration when strategy changed |
| Removing infrastructure dependencies without adequate replacement | Authentik (Redis removal) | Task queue flooding regression |

### What to Do Instead

1. **Single binary, low resource footprint**: Go binary targeting <100 MB RAM baseline. No JVM, no Python runtime.

2. **Persistent sessions by default**: Never store sessions only in memory. Use the primary database with optional caching layer.

3. **Simple state + audit log, not event sourcing**: Store current state directly. Maintain a separate append-only audit log for compliance. Same outcome, 10x simpler operations.

4. **Single service with clear module boundaries**: One binary, one database, one configuration. Internal modularity without operational microservice overhead.

5. **Ship a usable default UI with headless API**: Provide a working login/consent UI out of the box. Allow full replacement via API for teams that need custom UI. Never force everyone to build UI from scratch.

6. **Extension via configuration and webhooks, not compiled plugins**: Webhook-based extensibility for custom logic. Configuration-driven policy engine for common cases. Never require users to compile and deploy binary plugins.

7. **PostgreSQL as the primary (and initially only) database**: Most widely deployed, best understood, excellent tooling ecosystem. Don't fragment attention across database backends early.

8. **Automated, tested migration paths**: Every schema change gets a migration. Every migration gets tested against real-world data volumes. Never require serial major-version upgrades.

9. **Strict input validation and parameterized queries only**: No string concatenation for SQL. No raw user input in queries. Security is not a feature; it's a constraint on every line of code.

10. **Passkeys as a first-class subsystem**: Purpose-built credential lifecycle management, device tracking, fallback strategies, and cross-platform testing from day one.

---

## Sources

### Keycloak
- [Problems with Keycloak: Unpacking the Challenges](https://www.siriusopensource.com/en-us/blog/problems-keycloak-unpacking-challenges)
- [Improve migration performance - Issue #38649](https://github.com/keycloak/keycloak/issues/38649)
- [Migration from Version 11.0 to 24.0.4 Fails - Issue #30497](https://github.com/keycloak/keycloak/issues/30497)
- [Persistent user sessions - Discussion #28271](https://github.com/keycloak/keycloak/discussions/28271)
- [Constantly increasing memory usage - Issue #28211](https://github.com/keycloak/keycloak/issues/28211)
- [Increase in startup memory consumption - Issue #45662](https://github.com/keycloak/keycloak/issues/45662)
- [Memory consumption escalates - Issue #28264](https://github.com/keycloak/keycloak/issues/28264)
- [Massive Identity Migration to Keycloak](https://keymate.io/blog/tuning_keycloak_migration)
- [Enhanced migration story - Issue #37356](https://github.com/keycloak/keycloak/issues/37356)

### Zitadel
- [Brittle ZITADEL! Why Self Hosting Feels Brittle](https://medium.com/@nirajkvinit/brittle-zitadel-why-self-hosting-feels-brittle-and-what-to-do-next-70566cfc43a1)
- [Invalid tokens after upgrade to v4.x - Issue #10673](https://github.com/zitadel/zitadel/issues/10673)
- [Service silently fails (unhealthy) - Issue #11651](https://github.com/zitadel/zitadel/issues/11651)
- [Mirroring from CockroachDB to Postgres not working - Issue #8558](https://github.com/zitadel/zitadel/issues/8558)
- [Error migrating from Cockroach to Postgres - Issue #9042](https://github.com/zitadel/zitadel/issues/9042)
- [DB migration fails - Issue #9741](https://github.com/zitadel/zitadel/issues/9741)
- [CockroachDB deprecation PR #9480](https://github.com/zitadel/zitadel/pull/9480)

### Authentik
- [Authentik on Django: 500% slower to run](https://goauthentik.io/blog/2023-03-16-authentik-on-django-500-slower-to-run-but-200-faster-to-build/)
- [High idle resource load - Issue #2159](https://github.com/goauthentik/authentik/issues/2159)
- [High Availability - Issue #2460](https://github.com/goauthentik/authentik/issues/2460)
- [Flooding of Queued System Tasks - Issue #18368](https://github.com/goauthentik/authentik/issues/18368)
- [Resource consumption - Discussion #9569](https://github.com/goauthentik/authentik/discussions/9569)

### Dex
- [Dex GitHub - Connector Limitations](https://github.com/dexidp/dex)
- [Dex Connectors Documentation](https://dexidp.io/docs/connectors/)
- [Comparison of open-source SSO implementations](https://gist.github.com/bmaupin/6878fae9abcb63ef43f8ac9b9de8fafd)

### Casdoor
- [Casdoor SQL Injection CVE-2022-24124](https://blog.qualys.com/vulnerabilities-threat-research/2022/03/09/casdoor-sql-injection-cve-2022-24124)
- [Casdoor CVE List](https://vulners.com/search/vendors/casbin/products/casdoor)
- [Cross-Organizational Access Vulnerability](https://www.devhjz.com/en-us/archives/24/)

### Ory
- [UI rendering is extremely convoluted - Discussion #4152](https://github.com/ory/kratos/discussions/4152)
- [How to configure Kratos with Hydra - Discussion #2976](https://github.com/ory/kratos/discussions/2976)
- [Hydra+Kratos integration - Discussion #2855](https://github.com/ory/hydra/discussions/2855)
- [Pixie Labs: Open Source Auth](https://blog.px.dev/open-source-auth/)

### Auth Anti-Patterns and OIDC
- [OIDC for Developers: Reasons Your Auth Integration Could Be Broken](https://blog.gitguardian.com/oidc-for-developers-auth-integration/)
- [OAuth Patterns and Anti-Patterns](https://dzone.com/refcardz/oauth-patterns-and-anti-patterns)
- [OAuth 2.1 and Modern Authentication Patterns](https://www.javacodegeeks.com/2025/12/oauth-2-1-and-modern-authentication-patterns-whats-deprecated-and-whats-recommended.html)

### WebAuthn / Passkeys
- [Why Passkey Implementation is 100x Harder Than You Think](https://www.corbado.com/blog/passkey-implementation-pitfalls-misconceptions-unknowns)
- [Passkeys Failed: How to Avoid the Most Common Pitfalls](https://medium.com/@corbado_tech/passkeys-failed-how-to-avoid-the-most-common-pitfalls-217ab3a1d056)
- [Passkey Day 2 Problems: 5 Risks in Production](https://dev.to/corbado/passkey-day-2-problems-5-risks-in-production-deployments-2hcl)

### Session Management
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Session Management Vulnerabilities: What Developers Get Wrong](https://onsecurity.io/article/session-management-vulnerabilities-what-developers-get-wrong-and-how-to-fix-them/)
- [SSO Best Practices for Secure, Scalable Logins 2025](https://clerk.com/articles/sso-best-practices-for-secure-scalable-logins)
