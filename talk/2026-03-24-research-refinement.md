---
created: "2026-03-24"
topic: "seki v2.0 Evolution Research — DID/VC, Developer Features, B2B, Competitive Landscape"
status: completed
tags: [auth, did, verifiable-credentials, b2b, developer-experience, competitive-analysis, roadmap]
---

# 調査: seki v2.0 Evolution Research

## 目的

seki v1.0 が production-ready になった今、次の進化を設計するために、DID/Verifiable Credentials、個人開発者向け機能、B2B SaaS 機能、競合動向を包括的に調査する。調査結果を基に seki v2.0 の機能ロードマップを策定する。

---

# Part 1: DID / Decentralized Identity

## 1.1 W3C DID (Decentralized Identifiers)

**What it is:** A new type of globally unique identifier (URI) that enables verifiable, decentralized digital identity. Unlike traditional identifiers, DIDs do not require a centralized registry and can be cryptographically verified.

**Current spec status:**
- DID v1.0 became a W3C Recommendation in July 2022
- DID v1.1 entered Candidate Recommendation on March 5, 2026, with a public comment window until April 5, 2026
- v1.1 consolidates media types, adds JSON-LD Context, and separates DID Resolution into its own spec (v0.3, published February 2026)
- v1.1 is layered on top of the Controlled Identifiers v1.0 spec (W3C Recommendation since May 2025)

**Adoption reality:** Steady but unspectacular. Microsoft Entra Verified ID is the largest production deployment. The decentralized identity market was valued at $2.56-4.89 billion in 2025, projected to reach $7.4 billion in 2026. Large enterprises captured 67% of revenue. The dominant pattern is weaving DIDs into existing IAM stacks, not replacing them.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Early production for enterprise, experimental for most |
| Relevance for seki | **Low-Medium** |
| Implementation complexity | High |
| Recommendation | **Wait** -- monitor v1.1 finalization, revisit in 2027 |

## 1.2 Verifiable Credentials (VC)

**What it is:** A tamper-evident credential with cryptographic proof of authorship. The digital equivalent of physical credentials (diplomas, licenses, ID cards) that can be verified without contacting the issuer.

**Current status:**
- W3C Verifiable Credentials 2.0 published as a W3C Standard on May 15, 2025 -- a major milestone
- VC 2.0 refines terminology, improves extensibility, and aligns with modern security mechanisms
- A VC Working Group Charter for 2026 is already in progress

**Real-world adoption:**
- Government: EU eIDAS 2.0, mDL (21+ US states)
- Education: University diplomas as VCs (EU EUDI Wallet early use case)
- Healthcare: Digital health certificates
- Sustainability: Product credential vocabularies for EU Business Wallet
- Citizen adoption in pilots: 70-85% when wallets were pre-installed

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Production in government/education, growing in enterprise |
| Relevance for seki | **Medium** |
| Implementation complexity | High |
| Recommendation | **Wait** -- but build architecture that doesn't preclude VC support |

## 1.3 did:web

**What it is:** The simplest DID method -- resolves DIDs via HTTPS to a well-known URL on a domain. E.g., `did:web:auth.example.com` resolves to `https://auth.example.com/.well-known/did.json`. DNS-based, no blockchain needed.

**Practical assessment:** The most pragmatic DID method for web services. Low barrier to entry since it leverages existing DNS/TLS infrastructure. However, it inherits DNS trust model (not truly decentralized) and is vulnerable to domain hijacking.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Most widely adopted DID method in enterprise pilots |
| Relevance for seki | **Medium** -- if seki ever does DID, this is the method |
| Implementation complexity | Low-Medium (just serve a JSON document) |
| Recommendation | **Wait** -- trivial to add later, near-zero value without VC ecosystem |

## 1.4 did:key

**What it is:** A self-sovereign DID method that encodes a public key directly in the identifier. No registry, no resolution infrastructure needed. E.g., `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`.

**Practical assessment:** Useful for ephemeral identities, testing, and scenarios where no persistent identity infrastructure exists. Very simple to implement.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Used in testing and dev tooling, limited production use |
| Relevance for seki | **Low** |
| Implementation complexity | Low |
| Recommendation | **Skip** for now -- no practical value for an auth server |

## 1.5 OIDC4VC (OpenID for Verifiable Credentials)

**What it is:** A suite of three specs bridging OIDC and Verifiable Credentials:
- **OID4VCI** (Verifiable Credential Issuance) -- how to issue VCs using OAuth flows
- **OID4VP** (Verifiable Presentations) -- how to present VCs during authentication
- **SIOPv2** (Self-Issued OpenID Provider v2) -- users as their own OIDC provider

**Current status:**
- OID4VCI 1.0 finalized September 2025
- OID4VP finalized ~September 2025
- OpenID Foundation launched self-certification program in February 2026
- 30+ jurisdictions have selected and are deploying OID4VCI
- Interoperability proven: 7 issuers and 5 wallets tested pairwise

**Assessment:** This is the most relevant DID/VC spec for seki because it bridges the OIDC world (where seki already lives) with the VC world. If seki ever supports VC, it would be through OID4VP (accepting VC presentations as login credentials).

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Specs finalized, self-certification starting, government adoption strong |
| Relevance for seki | **Medium-High** -- the natural bridge from OIDC to VC |
| Implementation complexity | High |
| Recommendation | **Wait with intent** -- plan for OID4VP support in v3.0 timeline (2027+) |

## 1.6 EU eIDAS 2.0 / EUDI Wallet

**What it is:** EU regulation requiring all 27 member states to provide certified digital identity wallets by December 2026. The wallets use Verifiable Credentials and support both in-person and online identity verification.

**Current status:**
- Regulation entered into force May 2024
- Technical specs finalized November 2024
- Beta versions launching in early 2026 (Italy, Germany, Sweden)
- Austria's "Valera" wallet already deployed
- All member states must have wallets by September-December 2026
- From November 2027, organizations must accept EUDI wallets for identity verification
- Target: 80% citizen usage by 2030

**Assessment:** This is the single biggest driver of VC adoption globally. It creates a massive ecosystem of VC issuers/verifiers. However, seki's primary market (B2B SaaS auth) is not directly affected -- EUDI wallets are about citizen identity, not enterprise SSO.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Active implementation, hard regulatory deadlines |
| Relevance for seki | **Low-Medium** -- indirect relevance via ecosystem growth |
| Implementation complexity | N/A (seki wouldn't implement a wallet) |
| Recommendation | **Monitor** -- if EU customers need EUDI wallet login, implement OID4VP |

## 1.7 mDL (Mobile Driver's License) / ISO 18013-5

**What it is:** A mobile-phone-based driver's license standardized by ISO 18013-5 (proximity) and ISO/IEC TS 18013-7:2025 (online). Uses mdoc format (a VC-adjacent credential format).

**Current status:**
- 21 US states + Puerto Rico have mDLs accepted by TSA
- California: 2.65 million mDLs issued
- Arizona: ~23% of drivers using mDL
- Florida relaunching its program (March 2026)
- ISO/IEC DIS 18013-5 revision in progress

**Assessment:** mDLs prove that digital credentials work at scale. However, mDL verification is primarily a relying-party concern (age verification, identity proofing), not a core auth server function.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Production at scale in US, growing globally |
| Relevance for seki | **Low** -- identity proofing, not authentication |
| Implementation complexity | Medium |
| Recommendation | **Skip** -- out of scope for auth server |

## 1.8 Should seki support DID?

**Short answer: Not yet. Plan for it architecturally.**

**Reasoning:**
1. No major auth provider (Auth0, Clerk, Zitadel, Authentik) has shipped DID support as a core feature
2. The VC ecosystem is being driven by government mandates (EUDI, mDL), not by B2B SaaS needs
3. The dominant enterprise pattern is adding VC capabilities to existing IAM, not replacing IAM with VC
4. OIDC4VC (specifically OID4VP) is the natural bridge -- when the time comes, seki can accept VC presentations through its existing OIDC infrastructure
5. The specs are now stable (VC 2.0 is a Recommendation, OID4VCI/OID4VP finalized), so the risk of spec churn is diminishing

**Recommended approach:**
- v2.0: No DID/VC implementation. Ensure architecture is extensible.
- v2.x: Consider `did:web` support as a lightweight identity feature (serve DID documents for seki-managed identities)
- v3.0: Evaluate OID4VP support for accepting VC-based login (if demand materializes)

## 1.9 Who's implementing DID in auth?

| Vendor | Status | Notes |
|--------|--------|-------|
| **Microsoft Entra Verified ID** | Production | Most mature. Issues and verifies VCs. Integrated with Azure AD. |
| **Walt.id** | Production | Open-source VC toolkit. Supports OID4VCI, OID4VP, did:web, did:key. EUDI wallet reference implementation. |
| **Sphereon** | Production | VC wallet and verifier. Supports Entra integration. |
| **Spruce ID** | Active | SpruceID/DIDKit open-source toolkit. did:web, did:key support. |
| **Auth0** | Experimental | Published blog posts with MATTR integration. Not a core feature. |
| **Clerk** | None | No DID/VC support. Focus remains on traditional auth + DX. |
| **Zitadel** | None | No DID/VC on roadmap. Focus on multi-tenancy and performance. |
| **Authentik** | None | No DID/VC support. Focus on SAML/OIDC/SCIM. |

**Key insight:** DID/VC is being implemented by specialized identity platforms (Walt.id, Sphereon, Microsoft), not by general auth servers. This validates the "wait" strategy for seki.

## 1.10 Risks of DID

| Risk | Severity | Mitigation |
|------|----------|------------|
| Over-engineering | High | Only implement when clear demand exists |
| Spec complexity | Medium | Stick to did:web and OID4VP (simplest paths) |
| Limited adoption in B2B SaaS | High | Monitor EUDI wallet rollout and enterprise demand |
| Ecosystem fragmentation | Medium | Follow OpenID Foundation certification program |
| Maintenance burden | Medium | Treat as optional module, not core |
| User confusion | Medium | DID adds no UX value unless part of a VC flow |

---

# Part 2: Features for Individual Developers / Geeks

## 2.1 Single Sign-On for Personal Infrastructure

**What it is:** Using seki as a unified login for self-hosted services (Gitea, Grafana, Nextcloud, Miniflux, etc.) -- the "homelab SSO" use case.

**Current adoption:** Authelia and Authentik dominate this space. Developers often use LLDAP + Authelia or Authentik as their homelab identity stack. Most self-hosted apps support OIDC, making any OIDC provider viable.

**seki's position:** seki already works here via OIDC. The gap is documentation and pre-built integration guides. seki's lightweight footprint (Go binary, SQLite mode) is a significant advantage over Authentik (Python/Django) and Keycloak (Java).

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Mature use case, strong community demand |
| Relevance for seki | **High** -- expands addressable market beyond B2B |
| Implementation complexity | Low (mostly docs + config examples) |
| Recommendation | **Do it** -- publish integration guides for top 10 self-hosted apps |

## 2.2 Magic Link / Email OTP

**What it is:** Passwordless authentication via a one-time link or code sent to email. No device dependency (unlike passkeys).

**Current adoption:** Widely adopted. Recommended 2026 architecture: passkeys for returning users, magic links for new/unenrolled users, social login as optional. FBI/CISA issued guidance against SMS-only auth in 2025. UAE and Philippines setting deadlines to eliminate SMS OTP from financial services.

**Assessment:** seki currently has passkey + TOTP + password + social login. Magic link / email OTP fills the gap for users who don't have a passkey-capable device or haven't enrolled yet. This is the #1 missing authentication method.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Production standard, recommended as passkey fallback |
| Relevance for seki | **High** -- fills the "first login on new device" gap |
| Implementation complexity | Medium (requires email delivery integration via webhook) |
| Recommendation | **Do it** -- priority feature for v2.0 |

## 2.3 Device Authorization Grant (RFC 8628)

**What it is:** OAuth flow for devices without a browser -- CLI tools, smart TVs, IoT devices. User enters a code on a separate device to authorize.

**Current adoption:** Zitadel supports it. Auth0 supports it. Standard flow for CLI authentication (GitHub CLI, Azure CLI, gcloud all use this pattern).

**Assessment:** Essential for developer tooling. If seki powers an API and developers use CLI tools, device flow is how they authenticate. Also needed for the `seki-cli` tool itself.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Production standard, widely implemented |
| Relevance for seki | **High** -- essential for CLI/IoT use cases |
| Implementation complexity | Medium |
| Recommendation | **Do it** -- priority feature for v2.0 |

## 2.4 OAuth2 Token Exchange (RFC 8693)

**What it is:** A protocol for exchanging one security token for another -- enabling impersonation, delegation, and service-to-service token flow. E.g., Service A has a user token and needs to call Service B on behalf of that user.

**Current adoption:** Zitadel supports it (impersonation and delegation). Used in microservice architectures. Growing adoption with service mesh and zero-trust patterns.

**Assessment:** Important for advanced architectures. Less critical for seki's primary audience (small-to-mid B2B SaaS teams) but valuable for larger deployments and the "geek" audience.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Production, growing with microservice adoption |
| Relevance for seki | **Medium** |
| Implementation complexity | Medium-High |
| Recommendation | **Do it** -- v2.x (not first priority) |

## 2.5 Personal Access Tokens (PAT)

**What it is:** Long-lived, user-generated tokens for API access. Like GitHub PATs -- scoped, revocable, with expiration dates. An alternative to OAuth flows for developer tooling and automation.

**Current adoption:** Universal. GitHub, GitLab, Azure DevOps, Docker, Atlassian all support PATs. Zitadel has PATs for service users. GitLab 17.10 added DPoP (Demonstrating Proof of Possession) for PAT security.

**Assessment:** This is a must-have for developer adoption. Developers expect to be able to generate API tokens from a dashboard. seki currently has admin API keys but no user-scoped PATs.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Universal standard |
| Relevance for seki | **High** -- developers expect this |
| Implementation complexity | Low-Medium |
| Recommendation | **Do it** -- priority feature for v2.0 |

## 2.6 API Token Management UI

**What it is:** A self-service interface where developers can create, view, rotate, and revoke their own API tokens/PATs. Shows scopes, roles, expiration dates, and last-used timestamps.

**Current adoption:** Standard feature in all developer-facing platforms (GitHub, GitLab, Stripe, etc.).

**Assessment:** Directly tied to PAT support. If seki has PATs, it needs a management UI. This aligns with seki's philosophy of "admin UI as API viewer."

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Universal |
| Relevance for seki | **High** -- paired with PAT feature |
| Implementation complexity | Low-Medium |
| Recommendation | **Do it** -- ship with PATs |

## 2.7 Headless / API-Only Mode

**What it is:** Running seki without the built-in login UI -- all authentication flows driven entirely through APIs. For teams that want to build their own custom login experience.

**Current adoption:** Clerk offers headless APIs. Auth0 has always been API-first. The trend toward headless architectures is strong: 73% of organizations already use headless patterns (2024 WP Engine survey). Machine IAM and AI agent authentication are driving demand for API-only auth.

**Assessment:** seki is already API-first. The gap is formalizing headless mode: ensuring every auth flow (passkey, TOTP, social, magic link) is fully completable via API without requiring seki's built-in HTML pages.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Growing rapidly, driven by AI/agent authentication |
| Relevance for seki | **High** -- aligns with seki's API-first philosophy |
| Implementation complexity | Medium (audit all flows for API completeness) |
| Recommendation | **Do it** -- formalize and document headless mode in v2.0 |

## 2.8 Multi-Factor Step-Up Authentication

**What it is:** Requiring additional authentication factors only for sensitive operations (e.g., changing email, accessing billing, admin actions) rather than at every login.

**Current adoption:** Auth0 supports step-up auth via `acr_values`. OAuth/OIDC specs support it natively. Push notifications (29%) and TOTP (14%) are the most common second factors.

**Implementation patterns:**
- Include MFA completion status/level in JWT tokens (`acr` claim)
- Use `acr_values` in authorization requests to request specific assurance levels
- Scope-based triggers for sensitive resources

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Production standard |
| Relevance for seki | **Medium-High** |
| Implementation complexity | Medium |
| Recommendation | **Do it** -- v2.x, after core v2.0 features |

## 2.9 Webhook Templates

**What it is:** Pre-built webhook configurations for common services (Slack notifications on login failure, Discord alerts for new user signup, email via SendGrid/Mailgun).

**Current adoption:** Auth0 has webhook extensions. Most platforms leave this to the user. Supabase has "auth hooks" for custom logic.

**Assessment:** seki already has webhooks with HMAC-SHA256. Templates would reduce integration friction but are not core functionality.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Partial -- most platforms have webhooks but not templates |
| Relevance for seki | **Low-Medium** |
| Implementation complexity | Low |
| Recommendation | **Wait** -- publish example webhook handlers in docs instead |

## 2.10 Plugin / Extension System

**What it is:** A mechanism for users to inject custom logic into auth flows without forking seki. E.g., custom claim enrichment, conditional MFA, custom identity verification.

**Current adoption:**
- Auth0: Actions (JavaScript functions triggered at specific points)
- Microsoft Entra: Custom authentication extensions (HTTP callouts to REST APIs)
- Supabase: Auth hooks (Postgres functions or HTTP endpoints)
- Zitadel: Actions (external auth flow hooks)

**Assessment:** High value but high complexity. An HTTP-callout model (like Entra's custom extensions) is the most pragmatic approach -- seki calls an external URL at defined points in the auth flow. Avoids embedding a scripting runtime.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Mature in major platforms, expected by enterprise |
| Relevance for seki | **Medium-High** |
| Implementation complexity | High (must define extension points carefully) |
| Recommendation | **Do it** -- v2.x, HTTP-callout model at key auth flow points |

---

# Part 3: B2B Features for v2.0

## 3.1 Just-in-Time (JIT) Provisioning

**What it is:** Automatically creating user accounts on first login via SSO (SAML/OIDC federation). No pre-registration needed -- the user's identity provider assertion creates the account.

**Current adoption:** Industry standard for B2B SaaS. JIT provisioning creates users automatically during SSO login. Ideal for fast SSO integration with minimal setup. Most enterprise customers expect this.

**Assessment:** seki has social login (Google, GitHub) which already does implicit JIT. Formalizing JIT for enterprise OIDC/SAML federation is important if seki adds SAML support.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Universal in B2B SaaS |
| Relevance for seki | **High** |
| Implementation complexity | Low-Medium |
| Recommendation | **Do it** -- v2.0, for OIDC federation. SAML JIT when SAML lands. |

## 3.2 Directory Sync (Beyond SCIM)

**What it is:** Continuous synchronization of user/group data from enterprise directories (Google Workspace, Azure AD/Entra, Okta). SCIM is the protocol standard, but direct API sync with major providers reduces friction.

**Current adoption:** SCIM has become an industry standard for B2B SaaS. Authentik 2026.2 shipped major SCIM improvements (policy-based user filtering, group imports). Enterprise customers expect SCIM for lifecycle management.

**Assessment:** SCIM was planned for seki v1.0 but deferred. It's now a critical gap for enterprise adoption. Direct API sync with Google/Azure/Okta is a nice-to-have on top of SCIM.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Enterprise standard, growing requirement |
| Relevance for seki | **High** |
| Implementation complexity | High (SCIM spec is broad) |
| Recommendation | **Do it** -- SCIM in v2.0. Direct directory sync in v2.x. |

## 3.3 Custom Branding per Tenant

**What it is:** Allowing each organization/tenant to customize the login page with their logo, colors, and messaging. White-label login experiences.

**Current adoption:** Standard in Auth0, Clerk, Zitadel. Expected by B2B SaaS customers.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Standard B2B feature |
| Relevance for seki | **Medium-High** |
| Implementation complexity | Medium |
| Recommendation | **Do it** -- v2.0, per-org branding configuration in YAML/API |

## 3.4 Impersonation

**What it is:** Admin users acting as another user for support/debugging purposes, with full audit trail. The admin sees exactly what the user sees.

**Current adoption:** Zitadel supports impersonation via token exchange (RFC 8693). Auth0 has impersonation. Standard for customer support teams.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Common in enterprise platforms |
| Relevance for seki | **Medium** |
| Implementation complexity | Medium (requires token exchange + audit trail) |
| Recommendation | **Do it** -- v2.x, implement alongside RFC 8693 token exchange |

## 3.5 Session Sharing Across Subdomains

**What it is:** Maintaining a user's authenticated session across multiple subdomains (app.example.com, admin.example.com, api.example.com) without re-authentication.

**Current adoption:** Standard requirement for SaaS with multiple frontend apps. Typically implemented via cookie domain settings or a centralized session service.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Standard |
| Relevance for seki | **Medium** |
| Implementation complexity | Low-Medium (cookie domain config + docs) |
| Recommendation | **Do it** -- v2.0, configurable session cookie domain |

## 3.6 Consent Management

**What it is:** GDPR-compliant tracking and management of user consent for data processing. Recording when, how, and what users consented to with audit trails.

**Current adoption:** GDPR enforcement has intensified in 2025 (CNIL record fines, AEPD targeting pre-consent cookie loading). Auth0 has basic consent tracking. Curity has comprehensive privacy/GDPR support with the Phantom Token Pattern.

**Assessment:** seki's audit log provides a foundation. Consent management is a distinct concern from authentication -- often handled by dedicated consent management platforms (OneTrust, Cookiebot). seki should provide consent events in its audit log and webhook system, but not try to be a full consent management platform.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Required for EU-facing services |
| Relevance for seki | **Medium** |
| Implementation complexity | Medium |
| Recommendation | **Do it partially** -- v2.0, consent event logging + API. Leave CMP to dedicated tools. |

## 3.7 Multi-Region Data Residency

**What it is:** Controlling where user data is physically stored to comply with data sovereignty regulations (GDPR, CCPA, etc.).

**Current adoption:** Growing requirement. WorkOS advocates for a "selective residency" pattern: authentication can be centralized while sensitive data stays in-region. Self-hosted solutions like seki inherently give users full control over data location.

**Assessment:** seki's self-hosted nature already provides data sovereignty. The feature gap is documentation and tooling for multi-region deployment (e.g., per-tenant database routing, cross-region session sync).

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Growing enterprise requirement |
| Relevance for seki | **Low-Medium** -- self-hosting already solves this |
| Implementation complexity | Very High |
| Recommendation | **Wait** -- publish multi-region deployment guide. Actual multi-region support is v3.0. |

## 3.8 Usage-Based Billing Hooks

**What it is:** MAU (Monthly Active User) tracking and billing event emission for SaaS platforms that charge based on usage. Auth0 charges per MAU. Clerk charges ~$0.07/MAU.

**Current adoption:** MAU is the dominant pricing axis for auth platforms. SaaS customers need MAU data for their own billing. Metering data should be published from auth to a centralized billing system.

**Assessment:** seki should emit MAU metrics (via webhooks and Prometheus) so that SaaS operators can integrate with their billing systems. Not seki's job to handle billing itself.

| Attribute | Assessment |
|-----------|------------|
| Adoption status | Standard for SaaS billing integration |
| Relevance for seki | **Medium** |
| Implementation complexity | Low-Medium |
| Recommendation | **Do it** -- v2.0, MAU counter + Prometheus metrics + webhook events |

---

# Part 4: Competitive Landscape Update (2025-2026)

## 4.1 Auth0

**Recent moves:**
- Fine Grained Authorization (FGA) -- going beyond RBAC into relationship-based access control (ReBAC)
- Verifiable Credentials integration via MATTR partnership (blog posts, not core product)
- Actions ecosystem continues to grow (custom auth flow logic)

**Implication for seki:** FGA/ReBAC is a differentiator for complex authorization. seki should monitor but not chase -- RBAC covers most B2B cases. Auth0's VC integration is experimental, validating seki's "wait" approach.

## 4.2 Clerk

**Recent moves:**
- Continues to dominate developer experience for React/Next.js
- Headless API mode for custom UIs
- Focus on traditional auth (no DID/VC)
- Open-source alternatives gaining ground (10+ listed on OpenAlternative)

**Implication for seki:** Clerk's success proves DX matters. seki should invest in integration guides, SDK-like examples, and developer-friendly documentation. Clerk's SaaS-only model is its weakness -- seki's self-hosted advantage is real.

## 4.3 Zitadel

**Recent moves:**
- Login V2 (TypeScript-based, customizable) reached GA as default
- Repository Pattern refactoring for PostgreSQL performance
- Token Exchange (RFC 8693) support
- Device Authorization (RFC 8628) support
- Personal Access Tokens for service users
- Redis caching infrastructure (beta)
- Focus on multi-tenancy simplification and API standardization for 2026

**Implication for seki:** Zitadel is the closest competitor. They're ahead on RFC 8693, RFC 8628, and PATs. seki should prioritize these to achieve feature parity. Zitadel's complexity (event sourcing, CQRS) remains a weakness -- seki's simplicity is a genuine differentiator.

## 4.4 Authentik

**Recent moves:**
- 2026.2: Object Lifecycle Management, WS-Federation support, major SCIM improvements (policy-based filtering, group imports)
- 2025.12: Additional security enhancements
- 2025.10: Single Logout (SLO) for SAML and OIDC, enterprise SCIM with OAuth
- Three CVEs in February 2026 (including one critical)

**Implication for seki:** Authentik is investing heavily in enterprise features (SCIM, WS-Federation, SLO). Their SCIM improvements show this is table stakes for enterprise. seki should match SCIM and SLO. Authentik's security issues reinforce the value of seki's "honest scope" -- smaller attack surface.

## 4.5 Auth Trends Summary

| Trend | Status | seki Relevance |
|-------|--------|----------------|
| DID/VC in auth servers | None of the 4 competitors have shipped it | Low -- validates "wait" |
| Machine/Agent IAM | Emerging 2026 trend | High -- headless mode + PATs + device flow |
| Passkeys mainstream | Google reports 120% increase | High -- seki's core differentiator holds |
| SCIM as table stakes | Authentik shipped major improvements | High -- must implement |
| Step-up / adaptive MFA | Auth0 leads, Zitadel catching up | Medium -- important for enterprise |
| Fine-grained authz (FGA/ReBAC) | Auth0 leading, others following | Low -- RBAC sufficient for now |
| Headless/API-first auth | Clerk and Auth0 pushing hard | High -- formalize seki's headless mode |
| SMS OTP deprecation | FBI/CISA guidance against it | High -- seki already doesn't depend on SMS |

---

# Prioritized Feature Roadmap for seki v2.0

## Tier 1: v2.0 Core (High impact, do first)

These features address the most critical gaps and provide the highest value for both B2B and individual developer audiences.

| # | Feature | B2B Value | Geek Value | Complexity | Notes |
|---|---------|-----------|------------|------------|-------|
| 1 | **Magic Link / Email OTP** | High | High | Medium | #1 missing auth method. Webhook-based delivery. |
| 2 | **Personal Access Tokens (PAT)** | Medium | High | Low-Medium | Developer expectation. Scoped, expirable, revocable. |
| 3 | **Device Authorization Grant (RFC 8628)** | Medium | High | Medium | CLI auth, IoT. Essential for seki-cli. |
| 4 | **SCIM Provisioning** | High | Low | High | Enterprise table stakes. Start with user lifecycle. |
| 5 | **JIT Provisioning** | High | Medium | Low-Medium | Auto-create users on first OIDC login. |
| 6 | **Headless / API-Only Mode** | Medium | High | Medium | Formalize all flows as API-completable. |
| 7 | **Custom Branding per Tenant** | High | Low | Medium | Per-org login page customization. |
| 8 | **MAU Metrics + Prometheus** | High | Medium | Low-Medium | Usage tracking for SaaS operators. |

## Tier 2: v2.x Follow-up (Important, builds on Tier 1)

| # | Feature | B2B Value | Geek Value | Complexity | Notes |
|---|---------|-----------|------------|------------|-------|
| 9 | **Token Exchange (RFC 8693)** | Medium | Medium | Medium-High | Impersonation + delegation. |
| 10 | **Step-Up Authentication** | High | Medium | Medium | `acr_values` support, MFA for sensitive ops. |
| 11 | **Plugin/Extension System** | High | High | High | HTTP callouts at auth flow points. Start with 3-4 hooks. |
| 12 | **Impersonation** | High | Low | Medium | Admin-as-user for support. Requires RFC 8693. |
| 13 | **Single Logout (SLO)** | Medium | Medium | Medium | Authentik shipped this. OIDC front-channel SLO. |
| 14 | **Session Sharing (Subdomain)** | Medium | Medium | Low-Medium | Configurable session cookie domain. |
| 15 | **Consent Event Logging** | Medium | Low | Medium | GDPR audit trail for consent decisions. |
| 16 | **Homelab Integration Guides** | Low | High | Low | Docs for Gitea, Grafana, Nextcloud, etc. |

## Tier 3: v3.0 Future (Monitor and plan)

| # | Feature | B2B Value | Geek Value | Complexity | Notes |
|---|---------|-----------|------------|------------|-------|
| 17 | **SAML IdP** | High | Low | Very High | Enterprise federation. Was v1.0 plan. |
| 18 | **OID4VP (VC Login)** | Medium | Medium | High | Accept Verifiable Credential presentations. |
| 19 | **did:web Support** | Low | Medium | Low-Medium | Serve DID documents for seki identities. |
| 20 | **Directory Sync (Google/Azure/Okta)** | High | Low | High | Direct API sync beyond SCIM. |
| 21 | **Multi-Region Deployment** | Medium | Low | Very High | Per-tenant data routing. |
| 22 | **FGA / ReBAC** | Medium | Medium | Very High | Beyond RBAC. Only if demand proves out. |

## Skip (Not recommended for seki)

| Feature | Reason |
|---------|--------|
| did:key support | No practical value for auth server |
| mDL verification | Identity proofing, not authentication |
| Full Consent Management Platform | Dedicated tools (OneTrust etc.) do this better |
| Embedded scripting runtime | Too complex; HTTP callouts are simpler and safer |
| SMS OTP | Deprecated by security guidance. Email OTP is sufficient. |
| WS-Federation | Legacy protocol. Only Authentik added it. Not worth the investment. |

---

## 結論

1. **DID/VC is not yet ready for general auth servers.** No competitor has shipped it. The specs are stable but adoption is government-driven, not B2B SaaS-driven. seki should architect for future OID4VP support but not implement it in v2.0.

2. **The biggest wins for v2.0 are developer experience features:** magic links, PATs, device flow, headless mode. These make seki appealing to individual developers and geeks who want a lightweight, hackable auth server for personal infrastructure.

3. **SCIM and JIT provisioning are the critical B2B gaps.** Enterprise customers expect automated user lifecycle management. Without SCIM, seki cannot compete for enterprise deals.

4. **seki's core differentiators remain strong:** lightweight Go binary, passkey-first, API-first, honest scope. The competitive landscape has not eroded these advantages.

5. **The "machine IAM" trend (AI agents, CLI tools, headless services) is the emerging opportunity.** seki's API-first architecture and planned PAT/device-flow support position it well for this wave.

## ネクストアクション

- [ ] v2.0 scope finalization based on Tier 1 features
- [ ] Architecture review to ensure DID/VC extensibility without implementation
- [ ] SCIM implementation planning (start with /Users endpoint)
- [ ] Magic link / email OTP design (webhook-based delivery)
- [ ] PAT data model and API design
- [ ] RFC 8628 device flow implementation
- [ ] Headless mode audit (which flows require built-in UI today?)
- [ ] Integration guide planning (top 10 self-hosted apps)

## 参考リンク

### DID / Verifiable Credentials
- [W3C DID v1.0 Recommendation](https://www.w3.org/TR/did-1.0/)
- [W3C DID v1.1 Candidate Recommendation](https://www.w3.org/news/2026/w3c-invites-implementations-of-decentralized-identifiers-dids-v1-1/)
- [W3C Verifiable Credentials 2.0 Standard](https://www.w3.org/press-releases/2025/verifiable-credentials-2-0/)
- [OpenID for Verifiable Credentials](https://openid.net/sg/openid4vc/)
- [OID4VCI Developer Guide (Walt.id)](https://docs.walt.id/concepts/data-exchange-protocols/openid4vci)
- [OID4VP Developer Guide (Walt.id)](https://docs.walt.id/concepts/data-exchange-protocols/openid4vp)
- [OpenID Foundation Self-Certification Program](https://www.biometricupdate.com/202512/openid-foundation-launching-self-certification-program-for-3-specs-in-feb-2026)
- [EU eIDAS 2.0 Digital Identity Regulation](https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/915931811/The+European+Digital+Identity+Regulation)
- [EUDI Wallet 2026 Complete Guide](https://www.visasupdate.com/post/eu-digital-identity-wallet-eudi-wallet-2026-complete-guide-features-rollout)
- [mDL Global Status 2026](https://regulaforensics.com/blog/mobile-drivers-license-verification/)
- [mDL US State Adoption (Trinsic)](https://trinsic.id/state-of-mobile-drivers-licenses-in-the-u-s/)
- [Microsoft Entra Verified ID](https://learn.microsoft.com/en-us/entra/verified-id/decentralized-identifier-overview)
- [Walt.id Verifier API](https://docs.walt.id/community-stack/verifier/api/integrations/entra/overview)
- [Decentralized Identity Enterprise Playbook 2026](https://securityboulevard.com/2026/03/decentralized-identity-and-verifiable-credentials-the-enterprise-playbook-2026/)
- [2025 State of Verifiable Credential Report](https://everycred.com/blog/2025-state-of-verifiable-credential-report/)

### Developer Experience / Auth Patterns
- [Passwordless Authentication Practical Guide 2026](https://mojoauth.com/blog/the-developers-practical-guide-to-passwordless-authentication-in-2026)
- [Magic Links vs Passkeys vs OTP](https://mojoauth.com/blog/magic-links-passkeys-otp-and-social-login-which-passwordless-method-fits-your-application)
- [RFC 8628 - Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [Zitadel Device Flow Guide](https://zitadel.com/docs/guides/integrate/login/oidc/device-authorization)
- [RFC 8693 - Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Zitadel Token Exchange Guide](https://zitadel.com/docs/guides/integrate/token-exchange)
- [Zitadel Personal Access Tokens](https://zitadel.com/blog/new-personal-access-token)
- [Step-Up Authentication with OAuth/OIDC](https://www.scottbrady.io/oauth/step-up-authentication)
- [Auth0 Step-Up Auth](https://auth0.com/docs/secure/multi-factor-authentication/step-up-authentication)
- [Supabase Auth Hooks](https://supabase.com/docs/guides/auth/auth-hooks)
- [Self-Hosted IAM for Home Lab](https://dev.to/patimapoochai/building-a-self-hosted-iam-platform-to-add-sso-to-my-home-lab-5a2n)
- [5 Authentication Trends for 2026](https://www.authsignal.com/blog/articles/5-authentication-trends-that-will-define-2026-our-founders-perspective)

### B2B / Enterprise Auth
- [JIT Provisioning with SSO and SCIM](https://securityboulevard.com/2026/03/how-to-implement-just-in-time-jit-user-provisioning-with-sso-and-scim/)
- [SCIM: Transforming B2B User Identity Management](https://www.scalekit.com/blog/the-scim-imperative-transforming-b2b-user-identity-management)
- [OIDC Implementation in B2B SaaS](https://www.scalekit.com/blog/oidc-implementation-in-b2b-saas-a-step-by-step-guide-for-developers-atjte)
- [GDPR Consent Management 2026](https://secureprivacy.ai/blog/gdpr-consent-management)
- [Privacy and GDPR with OAuth (Curity)](https://curity.io/resources/learn/privacy-and-gdpr/)
- [Data Residency for Enterprise SaaS (WorkOS)](https://workos.com/blog/data-residency-for-enterprise-saas)
- [MAU-Based Pricing for Auth Platforms](https://www.getmonetizely.com/articles/why-authentication-platforms-use-mau-based-pricing-and-when-it-works-for-saas)

### Competitive Landscape
- [Zitadel Roadmap 2026](https://zitadel.com/blog/the-road-to-2026)
- [Zitadel Changelog](https://zitadel.com/changelog)
- [Authentik 2026.2 Release](https://goauthentik.io/blog/2026-02-27-authentik-version-2026-2/)
- [Authentik 2025.10 Release](https://docs.goauthentik.io/releases/2025.10/)
- [Top Auth Providers 2026 (Logto)](https://blog.logto.io/top-7-auth-providers-2026)
- [Open Source Auth0 Alternatives 2026](https://openalternative.co/alternatives/auth0)
- [API Security Trends 2026 (Curity)](https://curity.io/blog/api-security-trends-2026/)
