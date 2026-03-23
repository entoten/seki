# 2026-03-23 プロジェクトキックオフ

## 議論の概要

seki（関）の開発を正式に開始。concept.md をベースにMVPのロードマップを策定した。

## 決定事項

### プロジェクト名
- **seki**（関）— 関所。通すか通さないかを判断する場所。

### ポジショニング
- Auth0/Clerk の依存リスク vs Keycloak の重さ、その間を埋める
- OIDC first / Passkey first / API first

### MVP マイルストーン（M0〜M6）

| # | マイルストーン | 内容 |
|---|-------------|------|
| M0 | プロジェクト基盤 | Go module, ディレクトリ構造, Docker, Config loader |
| M1 | OIDC Core | Discovery, Authorization, Token, UserInfo |
| M2 | 認証フロー | Passkey, TOTP, Password, Social Login |
| M3 | Identity管理 | User, Org/Tenant, RBAC |
| M4 | 運用基盤 | Admin API, Audit Log, Webhook |
| M5 | デプロイ・UI | Docker image, 管理UI |
| M6 | 品質・ドキュメント | テスト, セキュリティレビュー, README |

### アーキテクチャ方針
- **言語**: Go
- **DB**: PostgreSQL（本番）/ SQLite（dev）
- **HTTP**: net/http (Go 1.22+) or chi
- **WebAuthn**: go-webauthn/webauthn
- **JWT**: golang-jwt/jwt/v5
- **署名**: Ed25519 デフォルト
- **Config**: YAML + 環境変数
- **API**: RESTful, OpenAPI spec first, RFC 7807 エラー

### プロジェクト構造
```
seki/
├── cmd/seki/          # エントリーポイント
├── internal/
│   ├── config/        # YAML設定ローダー
│   ├── server/        # HTTPサーバー
│   ├── oidc/          # OIDCプロバイダー
│   ├── authn/         # 認証フロー（passkey/totp/password/social）
│   ├── identity/      # User/Org/RBAC
│   ├── admin/         # Admin REST API
│   ├── audit/         # 監査ログ
│   ├── storage/       # DB抽象化（postgres/sqlite）
│   ├── crypto/        # 署名・ハッシュ
│   └── webhook/       # Webhook emitter
├── migrations/        # DBマイグレーション
├── web/               # 管理UI + ログイン画面
├── api/               # OpenAPI spec
├── docker/            # Dockerfile + compose
└── talk/              # 議論・意思決定ログ
```

### やらないこと（v0.1 スコープ外）
- SAML, SCIM, LDAP
- ABAC/ReBAC
- HA クラスタ
- メール/SMS 配信エンジン
- モバイル SDK
- Self-service ユーザーポータル

## 次のアクション
- M0 タスクを Issue 化して着手
- Go module 初期化 → ディレクトリ構造 → Config loader → Docker 基盤
