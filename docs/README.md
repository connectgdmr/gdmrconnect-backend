# API documentation

| File | What it is |
|---|---|
| `GDMR_Connect_API_Documentation.pdf` | Readable reference: authentication, roles, errors, limits, and all endpoints grouped by module |
| `openapi.json` | OpenAPI 3.0 file. Open it in Swagger UI / Postman / Insomnia, or generate client code from it |

Both files are **generated from the source code** (routes, permission checks, rate limits, request fields,
response codes and messages), so they never drift from the real API.

Rebuild after changing any route:

```
python tools/generate_api_docs.py
```

The overview text and module descriptions live in `tools/generate_api_docs.py`; the route reader is `tools/api_extract.py`.
