# @entoten/seki

TypeScript client SDK for the [seki](https://github.com/entoten/seki) Admin API.

## Quick start

```typescript
import { SekiClient } from "@entoten/seki";

const seki = new SekiClient("http://localhost:8080", "your-api-key");

const user = await seki.createUser({ email: "alice@example.com", name: "Alice" });
const orgs = await seki.listOrgs({ limit: 10 });
```

Requires Node 18+ or any runtime with a global `fetch` implementation.
