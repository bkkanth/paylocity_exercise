# Vulnerability Tracker API

**Paylocity DevSecOps Engineer Take-Home Exercise**
Author: Krishnakanth B.

A REST API and CLI client for tracking security vulnerabilities. Built with FastAPI and Python, with structured JSON logging, security headers, input validation, and correlation IDs throughout.

---

## Quick Start

### Windows PowerShell

```powershell
# Create virtual environment
python -m venv .venv

# If activation is blocked by execution policy, run this once:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Activate
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Start the API server
python server.py
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

Server starts at `http://127.0.0.1:8000`
Swagger UI: `http://127.0.0.1:8000/docs`

---

## Project Structure

```
paylocity_exercise/
├── server.py          # FastAPI application — routes, middleware, validation
├── cli.py             # Rich-powered CLI client for GET and POST
├── requirements.txt   # Python dependencies
├── Dockerfile         # Container build (non-root, health check)
├── Makefile           # Developer shortcuts
├── .env.example       # Environment variable reference
└── .gitignore
```

---

## CLI Commands

All commands default to `http://127.0.0.1:8000/api/v1/vulnerabilities`.
Open a **second terminal** while the server is running in the first.

### Fetch all vulnerabilities (colored table, sorted newest first)

```powershell
python cli.py get
```

### Fetch as raw JSON (pipeline-friendly)

```powershell
python cli.py get --format json
```

### POST the two bundled demo entries

```powershell
python cli.py post
```

Bundled entries are `XZ Utils Backdoor` (Supply Chain, 2024-03-29) and `HTTP Request Smuggling` (Request Smuggling, 2023-09-18). After posting, the CLI automatically re-fetches and displays the full updated collection with a `NEW` badge on the added rows.

### POST from a JSON file

```powershell
python cli.py post --file vulns.json
```

File must be a JSON array:

```json
[
  {
    "name": "Log4Shell",
    "type": "Remote Code Execution",
    "description": "JNDI injection in Apache Log4j2 allowing unauthenticated RCE via crafted log messages.",
    "date": "2021-12-09"
  }
]
```

### Target a different server

```powershell
python cli.py get --url http://staging:8000/api/v1/vulnerabilities
```

---

## API Reference

Base URL: `http://127.0.0.1:8000`

### GET /health

Liveness probe. Returns server status and current record count.

```powershell
curl.exe http://127.0.0.1:8000/health
```

```json
{
  "status": "healthy",
  "timestamp": "2024-03-29T12:00:00.000000Z",
  "record_count": 10
}
```

---

### GET /api/v1/vulnerabilities

Returns the full vulnerability collection. Unsorted by design — the CLI sorts by date descending; other consumers may sort differently.

```powershell
curl.exe http://127.0.0.1:8000/api/v1/vulnerabilities
```

```json
{
  "results": [
    {
      "name": "Log4Shell",
      "type": "Remote Code Execution",
      "description": "JNDI injection in Apache Log4j2 allowing unauthenticated RCE via crafted log messages.",
      "date": "2021-12-09"
    }
  ],
  "count": 10
}
```

---

### POST /api/v1/vulnerabilities

Accepts a JSON **array** of one or more vulnerability objects. Returns `201 Created`.
Minimum 1 item, maximum 50 items per request.

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/v1/vulnerabilities `
  -H "Content-Type: application/json" `
  -d '[{"name":"XZ Utils Backdoor","type":"Supply Chain","description":"Malicious code injected into XZ Utils 5.6.x enabling unauthorized SSH access on Linux.","date":"2024-03-29"}]'
```

**Request body fields:**

| Field | Type | Constraints |
|---|---|---|
| `name` | string | 1–120 chars, no injection patterns |
| `type` | string | 1–80 chars, no injection patterns |
| `description` | string | 1–500 chars, no injection patterns |
| `date` | string | ISO-8601 `YYYY-MM-DD` only |

**Success response (201):**

```json
{
  "results": [
    {
      "name": "XZ Utils Backdoor",
      "type": "Supply Chain",
      "description": "Malicious code injected into XZ Utils 5.6.x enabling unauthorized SSH access on Linux.",
      "date": "2024-03-29"
    }
  ],
  "count": 1
}
```

**Validation error (422):**

```json
{
  "detail": [
    {
      "loc": ["body", 0, "date"],
      "msg": "Date must be YYYY-MM-DD (e.g. 2023-06-01).",
      "type": "value_error"
    }
  ]
}
```

---

### GET /docs

Swagger UI — interactive API browser served by FastAPI.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `fastapi` | >=0.111.0 | ASGI web framework; automatic OpenAPI 3.1.0 schema and Swagger UI |
| `uvicorn[standard]` | >=0.29.0 | ASGI server that runs FastAPI; `[standard]` adds WebSocket and performance extras |
| `requests` | >=2.31.0 | HTTP client used by the CLI to call the API |
| `rich` | >=13.7.0 | Terminal output — colored tables, panels, spinners, and JSON syntax highlighting |
| `python-dotenv` | >=1.0.0 | Loads `API_HOST` and `API_PORT` from a `.env` file at startup |

---

## Security Controls

### Security Headers (OWASP Secure Headers Project)

Applied to every API response by `SecurityHeadersMiddleware`. The `/docs` and `/openapi.json` paths receive a relaxed CSP that allows the Swagger UI CDN (`cdn.jsdelivr.net`).

| Header | Value | Why |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Prevents browsers from guessing content type — stops a text file from being executed as JavaScript |
| `X-Frame-Options` | `DENY` | Blocks embedding in `<iframe>` — prevents clickjacking attacks |
| `X-XSS-Protection` | `1; mode=block` | Legacy IE/Edge header — blocks (not sanitizes) on XSS detection |
| `Cache-Control` | `no-store` | Vulnerability data is sensitive — tells every proxy and browser not to cache responses |
| `Content-Security-Policy` | `default-src 'none'` | Most restrictive CSP for a pure API — nothing to load |
| `Referrer-Policy` | `no-referrer` | Prevents the API URL from leaking via the HTTP `Referer` header |

### Correlation IDs

Every request is assigned a UUID by `CorrelationIDMiddleware`. It is:
- Attached to `request.state.correlation_id` so route handlers can include it in logs without extra parameters
- Returned in the `X-Correlation-ID` response header so callers can include it in bug reports
- Present in every structured log line for that request

This ties together the inbound request, all downstream log lines, and the response — critical for debugging in high-traffic environments.

### Structured JSON Logging

All log output is emitted as JSON by `StructuredJSONFormatter`. Every line is a flat JSON object:

```json
{
  "timestamp": "2024-03-29T12:00:00.000000Z",
  "level": "INFO",
  "logger": "vuln-tracker",
  "message": "POST /api/v1/vulnerabilities → 201",
  "correlation_id": "a3f2c1d4-...",
  "method": "POST",
  "path": "/api/v1/vulnerabilities",
  "status_code": 201,
  "duration_ms": 4.21,
  "client_ip": "127.0.0.1"
}
```

JSON logs ingest directly into Splunk, Datadog, CloudWatch Logs Insights, and the ELK stack without writing a parsing regex.

### Input Validation Layers

Two independent layers validate every POST body field:

**Layer 1 — Pydantic field constraints:**
- `min_length` / `max_length` on every string field — caps memory usage and catches blanks
- `date` parsed with `datetime.strptime` against `%Y-%m-%d` — rejects `"yesterday"`, `"2023/01/01"`, and impossible dates like `2024-13-99`

**Layer 2 — Injection pattern regex (`_SUSPICIOUS`):**
Scans `name`, `type`, and `description` for HTML/XML metacharacters (`< > { } & ;`), `<script`, `javascript:`, SQL keywords (`SELECT`, `DROP`, `INSERT`), and SQL comment markers (`--`, `/*`). Not a WAF replacement — a trip-wire for the obvious attack patterns.

### CORS

`CORSMiddleware` restricts allowed origins to `http://localhost:3000` and `http://127.0.0.1:3000`. A wildcard `allow_origins=["*"]` policy is classified as a misconfiguration in OWASP API Security Top 10 (API7:2023). Only `GET` and `POST` methods are exposed.

### API Versioning

All routes are prefixed `/api/v1/`. When a breaking change is needed, `/api/v2/` is introduced alongside v1. Existing callers keep working without a hard cutover.

---

## Architecture Decisions

| Decision | Rationale |
|---|---|
| FastAPI over Flask | Automatic OpenAPI schema generation, Pydantic validation built-in, async-ready from the start |
| POST accepts an array, not a single object | The spec says "one or more objects" — an array handles both with one endpoint; avoids N round trips for N items |
| Sorting in the CLI, not the server | Different consumers may want different sort orders; sorting server-side imposes one preference on all callers |
| 50-item POST cap | Without a size limit a single request can exhaust server memory; 50 is large enough for real batches |
| In-memory store, not a database | Exercise scope doesn't require persistence; a database adds infrastructure that prevents running in 30 seconds |
| `API_HOST` / `API_PORT` from environment variables | Twelve-Factor App principle III — same binary runs in dev, staging, and production without code changes |
| UUID correlation ID per request | Ties together all log lines for a single transaction; caller can reference it in support tickets |
| JSON-structured logging over `print()` | JSON logs ingest directly into Splunk, Datadog, ELK — `print()` requires a parsing regex |
| `rich` for CLI output | Same library used by Semgrep, Checkov, and Prowler; color-coding by risk type speeds up triage |
| Color codes by vulnerability type | Mirrors CVSS severity tiers — bold red = critical RCE, orange = high auth bypass, yellow = elevated, cyan = info |
| `datetime.strptime` for date sort | ISO-8601 strings sort correctly as strings today, but `strptime` makes the contract explicit and raises on format drift |
| `/health` endpoint (not in spec) | Every production service needs a liveness probe for Kubernetes, load balancers, and uptime monitors |
| `log.propagate = False` | Prevents every log line from appearing twice — once from the custom handler and once from the root logger |

---

## Docker

### Build

```powershell
docker build -t vuln-tracker .
```

### Run

```powershell
docker run -p 8000:8000 vuln-tracker
```

### Run with custom port

```powershell
docker run -p 9000:9000 -e API_PORT=9000 vuln-tracker
```

The container runs as non-root user `appuser` (uid 1001). The built-in `HEALTHCHECK` pings `/health` every 30 seconds with a 5-second timeout.

---

## Make Shortcuts

> **Windows note:** `make` is not built into PowerShell. Install it via Chocolatey: `choco install make`

| Target | What it does |
|---|---|
| `make install` | Create `.venv` and install all dependencies |
| `make server` | Start the API server |
| `make get` | `python cli.py get` |
| `make post` | `python cli.py post` (demo entries) |
| `make json` | `python cli.py get --format json` |
| `make health` | `curl /health` |
| `make headers` | `curl -I` to verify security response headers |
| `make docker-build` | `docker build -t vuln-tracker .` |
| `make docker-run` | `docker run -p 8000:8000 vuln-tracker` |
| `make clean` | Remove `.venv` and `__pycache__` |

---

## What's Missing for Production

| Gap | Production Solution |
|---|---|
| In-memory data store | PostgreSQL + SQLAlchemy ORM + Alembic migrations |
| No authentication | JWT or OAuth2 with scoped tokens per consumer |
| No rate limiting | `slowapi` + Redis sliding-window limiter |
| No pagination on GET | Cursor-based pagination with `limit` / `offset` query params |
| No duplicate detection | Unique constraint on `(name, date)` at the database layer |
| Single-process state | Stateless service behind a load balancer with a shared database |
| No TLS | Terminate TLS at the load balancer or nginx reverse proxy |
| Logs to stdout only | Ship to Splunk / Datadog / CloudWatch via a log collector sidecar |
| No metrics | Prometheus `/metrics` endpoint + Grafana dashboard |

---

## Windows PowerShell Notes

PowerShell's built-in `curl` is an alias for `Invoke-WebRequest`, not the real curl binary. Always use `curl.exe` explicitly:

```powershell
# Correct
curl.exe http://127.0.0.1:8000/health

# Wrong — this invokes Invoke-WebRequest
curl http://127.0.0.1:8000/health
```

For POST with a body, use backtick `` ` `` for line continuation:

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/v1/vulnerabilities `
  -H "Content-Type: application/json" `
  -d '[{"name":"Test","type":"Injection","description":"Test entry.","date":"2024-01-01"}]'
```

---

## .gitignore

```
.venv/
venv/
__pycache__/
*.pyc
.env
*.egg-info/
dist/
.pytest_cache/
```
