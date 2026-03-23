# seki — Concept Document v0.1

## One-line Concept

“5分で立ち上がって、ちゃんと安全で、APIが気持ちいい” 現代的B2B SaaS向け認証コア

## Tagline

## Name Origin

seki（関）— 関所。通すか、通さないかを判断する場所。認証の本質を一文字で表す。
囲碁用語の「セキ」（双方生き）の意味も持ち、Go言語で書くプロジェクトとしての縁もある。
Authentication infrastructure that respects your time.

-----

## 誰の何を解決するか

### Target

自社SaaS / 自社Webアプリを持つ、小〜中規模の開発チーム（1〜30人）

### Pain

1. Auth0/Clerk は便利だが、プロダクトの首根っこを SaaS に握られる
- 料金の不透明さ、データ所在の不安、カスタマイズ限界、outage 時の無力感
1. Keycloak は強いが、“導入した瞬間に運用責任者になる”
- 重い、概念が多い、UI が広すぎる、小さく始められない
1. OSS 認証基盤は “できる” が “設計の芯” が弱い
- パスキーが主役じゃない、API/config が第一級じゃない、テナント/権限/監査が継ぎ足し

### Solution

OIDC first / Passkey first / API first の認証サーバー。
Docker 1発で起動し、設定は YAML/API で完結。
B2B SaaS に必要な Org・テナント・監査ログを最初から持つ。

-----

## Philosophy — 5つの設計原則

### 1. Start in 5 minutes

`docker compose up` で起動。初期設定は 1つの YAML ファイル。
チュートリアルなしで最初の OIDC クライアントを登録できること。

### 2. OIDC native, Passkey native

OIDC Provider として正しく振る舞うことが最優先。
パスワードレス（Passkey + TOTP）をデフォルトの認証フローにする。
パスワード認証はオプトインで提供するが推奨しない。

### 3. API/Config as Code first

管理画面は “APIのビューア” であり、真実の源泉は API と設定ファイル。
すべての操作は API 経由で可能。Terraform provider も視野に入れる。
管理UIは便利だが、UIでしかできない操作は作らない。

### 4. Audit by default

すべての認証イベント・管理操作は構造化ログとして記録。
ログは外部転送可能（stdout JSON / webhook）。
「後から監査ログを足す」は認証基盤の設計ミス。

### 5. Honest scope

やらないことを明言する。
“将来対応” を匂わせて中途半端な抽象化を入れない。
SAML が要るなら Keycloak を使え、と README に書く。

-----

## 絶対にやること（MVP v0.1）

|Category|Feature                                  |Note                    |
|--------|-----------------------------------------|------------------------|
|Core    |OIDC Provider (Authorization Code + PKCE)|RFC準拠、Discovery endpoint|
|Core    |OAuth2 Client Credentials                |M2M 認証                  |
|Auth    |Passkey (WebAuthn)                       |第一級の認証手段                |
|Auth    |TOTP                                     |Passkey 非対応環境のフォールバック   |
|Auth    |Password (opt-in)                        |推奨しないが現実として必要           |
|Auth    |Social Login (Google, GitHub)            |OAuth2 federation       |
|Identity|User 管理                                  |CRUD + search + metadata|
|Identity|Organization / Tenant                    |B2B SaaS 向けマルチテナント      |
|Identity|Group / Role (RBAC)                      |シンプルな Role ベース権限        |
|Ops     |Audit Log                                |構造化 JSON、stdout + API   |
|Ops     |Admin REST API                           |全操作を API で              |
|Ops     |Config as YAML                           |宣言的初期設定                 |
|Ops     |管理 UI（軽量）                                |API のビューア、デバッグ用         |
|Deploy  |Docker / docker compose                  |1コマンド起動                 |
|Deploy  |PostgreSQL backend                       |本番向け永続化                 |
|Deploy  |SQLite mode                              |開発・検証用ゼロ依存モード           |

## 絶対にやらないこと（v0.1 非スコープ）

|Feature                                |Reason                       |
|---------------------------------------|-----------------------------|
|SAML IdP/SP                            |企業フェデレーション需要は認めるが、初期の芯をブラさない |
|SCIM                                   |SAML と同じ文脈。後回し               |
|LDAP bridge                            |レガシー互換は Keycloak の仕事         |
|Fine-grained policy engine (ABAC/ReBAC)|RBAC で足りないケースは v0.2 以降       |
|HA クラスタ / 水平スケール                       |単一ノードで十分なスケールが先              |
|Email/SMS 配信の複雑な配線                     |Webhook で外部に投げる。組み込みSMTPは持たない|
|モバイル SDK                               |Web SDK + OIDC 標準で十分カバー      |
|Self-service ユーザーポータル                  |アプリ側の責務。認証基盤が持つ必要なし          |

-----

## 競合との差分

|              |Auth0|Clerk|Keycloak |Zitadel|Authentik|**seki**     |
|--------------|-----|-----|---------|-------|---------|-------------|
|運用形態          |SaaS |SaaS |Self-host|Both   |Self-host|**Self-host**|
|起動速度          |即    |即    |遅い       |中      |中        |**速い**       |
|Passkey       |○    |○    |△        |○      |△        |**◎ 第一級**    |
|OIDC          |○    |○    |○        |○      |○        |**◎ Only**   |
|SAML          |○    |×    |◎        |○      |○        |**× 捨てる**    |
|API first     |○    |○    |△        |○      |△        |**◎**        |
|Config as Code|△    |×    |△        |○      |△        |**◎ YAML**   |
|監査ログ          |○    |△    |△        |○      |○        |**◎ Day 1**  |
|B2B テナント      |○    |○    |△        |◎      |×        |**○**        |
|学習コスト         |低    |低    |高        |中      |中        |**低**        |
|データ主権         |×    |×    |◎        |○      |◎        |**◎**        |
|料金リスク         |高    |高    |無        |中      |無        |**無**        |

### seki が勝つ場所

- Auth0/Clerk から脱却したいが Keycloak は重すぎるチーム
- B2B SaaS を作っていて、認証を自前で持ちたいが車輪を再発明したくないチーム
- Passkey を本気で導入したいが、既存OSSではサポートが弱いチーム

### seki が負ける場所（= 使うべきでない場所）

- SAML 必須の企業間フェデレーション → Keycloak / Zitadel
- 認証に一切時間を割きたくない → Auth0 / Clerk
- 社内 IAM / ゼロトラスト基盤 → Authentik / Keycloak

-----

## アーキテクチャ原則

### Tech Stack（案）

- Language: **Go**
  - シングルバイナリ配布、起動が速い、並行処理が自然
  - 認証基盤OSSの主流言語（Zitadel, Casdoor, Dex = Go）
- DB: **PostgreSQL**（本番） / **SQLite**（dev/試用）
- Config: **YAML** + 環境変数
- Admin UI: **SPA（React or Svelte）** を組み込み配信
- Signing: **Ed25519** デフォルト（RSA もサポート）

### 構成図（概念）

```
┌─────────────────────────────────────────────┐
│                 seki                     │
│                                               │
│  ┌─────────┐  ┌──────────┐  ┌─────────────┐ │
│  │  OIDC   │  │  Admin   │  │   Webhook   │ │
│  │ Provider│  │   API    │  │   Emitter   │ │
│  └────┬────┘  └────┬─────┘  └──────┬──────┘ │
│       │            │               │         │
│  ┌────┴────────────┴───────────────┴──────┐  │
│  │            Core Engine                  │  │
│  │  ┌──────┐ ┌──────┐ ┌───────┐ ┌──────┐ │  │
│  │  │ User │ │ Org  │ │ Auth  │ │Audit │ │  │
│  │  │ Mgmt │ │Tenant│ │ Flow  │ │ Log  │ │  │
│  │  └──────┘ └──────┘ └───────┘ └──────┘ │  │
│  └────────────────┬────────────────────────┘  │
│                   │                           │
│  ┌────────────────┴────────────────────────┐  │
│  │         Storage Layer                    │  │
│  │    PostgreSQL / SQLite (switchable)      │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
         │              │              │
    ┌────┴────┐   ┌────┴────┐   ┌────┴────┐
    │ Your    │   │ Your    │   │External │
    │ Web App │   │ Mobile  │   │ Services│
    │ (OIDC)  │   │  App    │   │  (M2M)  │
    └─────────┘   └─────────┘   └─────────┘
```

### API 設計方針

- RESTful JSON API
- OpenAPI spec を truth とする
- 認証: Admin API は API Key + optional mTLS
- バージョニング: URL prefix (`/api/v1/`)
- ページネーション: cursor-based
- エラー: RFC 7807 Problem Details

### Config as Code 例

```yaml
# seki.yaml
server:
  address: ":8080"
  issuer: "https://auth.example.com"

database:
  driver: postgres  # or sqlite
  dsn: "postgres://seki:secret@localhost:5432/seki?sslmode=disable"

signing:
  algorithm: EdDSA
  key_file: /etc/seki/keys/signing.key

clients:
  - id: my-saas-app
    name: "My SaaS Application"
    redirect_uris:
      - "https://app.example.com/callback"
      - "http://localhost:3000/callback"
    grant_types:
      - authorization_code
    scopes:
      - openid
      - profile
      - email
    pkce_required: true

  - id: backend-worker
    name: "Backend Service"
    grant_types:
      - client_credentials
    scopes:
      - admin:read

organizations:
  - slug: acme-corp
    name: "Acme Corporation"
    domains:
      - acme-corp.com
    roles:
      - name: admin
        permissions: ["org:manage", "users:write", "audit:read"]
      - name: member
        permissions: ["users:read"]

authentication:
  passkey:
    enabled: true
    rp_name: "seki"
    rp_id: "auth.example.com"
  totp:
    enabled: true
    issuer: "seki"
  password:
    enabled: false  # opt-in, not default
  social:
    google:
      client_id: "${GOOGLE_CLIENT_ID}"
      client_secret: "${GOOGLE_CLIENT_SECRET}"
    github:
      client_id: "${GITHUB_CLIENT_ID}"
      client_secret: "${GITHUB_CLIENT_SECRET}"

audit:
  output: stdout  # stdout | webhook | both
  webhook:
    url: "https://your-siem.example.com/ingest"
    format: json
  retention_days: 90

webhooks:
  events:
    - user.created
    - user.login
    - user.login.failed
    - org.member.added
  endpoints:
    - url: "https://app.example.com/webhooks/auth"
      secret: "${WEBHOOK_SECRET}"
```

-----

## ロードマップ（概念）

### v0.1 — Foundation（MVP）

- OIDC Provider + Passkey + TOTP + Social Login
- User / Org / Role 管理
- Admin API + YAML config
- Audit log (stdout JSON)
- Docker compose 起動
- 軽量管理 UI

### v0.2 — Hardening

- Rate limiting / brute-force protection
- Session management の強化
- ABAC / policy engine（軽量）
- Email/SMS hook の改善
- Prometheus metrics

### v0.3 — Scale

- HA 構成ガイド
- Read replica 対応
- Terraform provider
- CLI ツール

### v1.0 — Production Ready

- セキュリティ監査通過
- SAML IdP（要望次第）
- SCIM provisioning
- Migration tool（Auth0 / Keycloak からの移行）

-----

## 名前: seki

### Why

- Gate（認証のゲート）+ Craft（設計思想を持って丁寧に作る）
- 重厚すぎない、でも軽薄でもない
- ドメイン・npm・GitHub org の取得可能性を要確認

### Alternative candidates

- Latch — シンプルだが既存プロダクトと被る可能性
- Authforge — 分かりやすいが generic
- Orbit Auth — 良いがやや抽象的

-----

## Next Steps

1. [ ] GitHub リポジトリ初期化（Go module + Docker compose）
1. [ ] OIDC Provider コア実装（Discovery + Authorization + Token endpoint）
1. [ ] WebAuthn / Passkey 認証フロー
1. [ ] User CRUD + PostgreSQL スキーマ
1. [ ] Admin API scaffold（OpenAPI spec first）
1. [ ] `seki.yaml` パーサー + 初期設定ローダー
1. [ ] Docker image ビルド
1. [ ] README + Getting Started ガイド
