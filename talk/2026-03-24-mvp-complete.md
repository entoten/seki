# 2026-03-24 seki v0.1 MVP 完了レポート

## 全マイルストーン完了

| マイルストーン | Issue数 | 状態 |
|-------------|--------|------|
| M0 プロジェクト基盤 | 7 | 全完了 |
| M1 OIDC Core | 5 | 全完了 |
| M2 認証フロー | 5 | 全完了 |
| M3 Identity管理 | 3 | 全完了 |
| M4 運用基盤 | 3 | 全完了 |
| M5 デプロイ・UI | 2 | 全完了 |
| M6 品質・ドキュメント | 2 | 全完了 |
| **合計** | **27** | **全完了** |

## 実装済み機能

### OIDC Provider
- Discovery (/.well-known/openid-configuration)
- JWKS (/.well-known/jwks.json)
- Authorization Code + PKCE (S256のみ)
- Token endpoint (authorization_code, client_credentials, refresh_token)
- UserInfo endpoint
- Refresh Token ローテーション + 盗難検知（family tracking）

### 認証
- Passkey (WebAuthn) — 登録・認証・Discoverable Login・ライフサイクル管理
- TOTP — シークレット生成・リカバリーコード（8個、bcryptハッシュ）
- Password — opt-in, argon2id, min 8 chars
- Social Login — Google, GitHub OAuth2

### Identity管理
- User CRUD + search + metadata
- Organization / Tenant（slug, domains, members）
- Role / Permission (RBAC)

### 運用
- Admin REST API (18 endpoints, API Key認証, RFC 7807エラー)
- Audit Log (DB + stdout JSON)
- Webhook emitter (HMAC-SHA256, リトライ, イベントフィルタ)

### インフラ
- Go単一バイナリ
- PostgreSQL / SQLite切り替え
- Docker + docker-compose (prod + dev)
- Ed25519 JWT署名
- DBセッション永続化（idle + absolute timeout）
- CI/CD (Gitea Actions: build + lint + security)

## テスト
- 約100テスト全パス
- config, crypto, oidc, session, storage, admin, audit, webhook, passkey, totp, password, social

## ドキュメント
- README.md (Quick Start, API Reference, Architecture)
- CHANGELOG.md
- OpenAPI spec (api/openapi.yaml)
- LICENSE (Apache 2.0)
- seki.yaml.example

## リサーチから適用した教訓
1. DB永続セッションがデフォルト（Keycloakの失敗を回避）
2. シンプルなstate + audit log（Zitadelのevent sourcing複雑性を回避）
3. 単一バイナリ（Oryのマイクロサービス地獄を回避）
4. デフォルトUI同梱（Ory/Dexの「自分でUI作れ」問題を回避）
5. PostgreSQL一本（Zitadelの CockroachDB依存を回避）
6. パラメタライズドクエリ徹底（CasdoorのSQLi恥を回避）
7. Passkey第一級サブシステム（各社の甘い実装を回避）
8. Refresh Tokenローテーション + 盗難検知（OAuth 2.1推奨）

## 次のステップ (v0.2)
- Rate limiting / brute-force protection
- Session management強化
- Prometheus metrics
- 管理UI (SPA)
- テストカバレッジ 80%+
- セキュリティ監査
