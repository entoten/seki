# seki-client

Python client SDK for the [seki](https://github.com/entoten/seki) Admin API.

## Quick start

```python
from seki import SekiClient

client = SekiClient("http://localhost:8080", "your-api-key")

user = client.create_user(email="alice@example.com", name="Alice")
orgs = client.list_orgs(limit=10)
```

Requires Python 3.10+ and `httpx`.
