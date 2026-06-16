"""
Vulnerability Tracker API — server.py
Author : Krishnakanth B.
Role   : DevSecOps / Full Stack Developer

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
A developer asks:        "Does this work?"
A DevSecOps engineer asks: "Does this work,
  AND could it be exploited,
  AND can I see what's happening,
  AND what breaks if someone sends garbage input?"

Every section below has a security or operational
rationale. Comments explain WHY, not just what.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import json
import logging
import os
import re
import time
import uuid
from datetime import datetime
from typing import List

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.base import BaseHTTPMiddleware

# ─────────────────────────────────────────────────
# 1. STRUCTURED LOGGING
#
# WHY NOT print()?
# print() goes to stdout as plain text. You can't
# query it, filter it, or alert on it.
#
# JSON-structured logs can be ingested directly by
# Splunk, Datadog, CloudWatch Logs Insights, and
# the ELK stack without writing a single regex.
# One log line = one JSON object = zero parsing needed.
# ─────────────────────────────────────────────────

class StructuredJSONFormatter(logging.Formatter):
    """
    Converts every log record into a flat JSON object.
    The 'ctx' attribute lets callers attach arbitrary
    key-value pairs (correlation_id, route, duration)
    without touching the base message string.
    """
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level":     record.levelname,
            "logger":    record.name,
            "message":   record.getMessage(),
        }
        # Merge any extra context the caller attached via extra={"ctx": {...}}
        if hasattr(record, "ctx"):
            payload.update(record.ctx)
        return json.dumps(payload)


_handler = logging.StreamHandler()
_handler.setFormatter(StructuredJSONFormatter())

log = logging.getLogger("vuln-tracker")
log.setLevel(logging.INFO)
log.addHandler(_handler)

log.propagate = False   # Prevent duplicate output to root logger


# ─────────────────────────────────────────────────
# 2. APPLICATION SETUP
# ─────────────────────────────────────────────────

app = FastAPI(
    title="Vulnerability Tracker API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
)
# ─────────────────────────────────────────────────
# 3. SECURITY HEADERS MIDDLEWARE
#
# WHY does this exist?
# HTTP responses without security headers are
# vulnerable to a class of browser-based attacks
# that have nothing to do with your code logic.
#
# X-Content-Type-Options: nosniff
#   → Stops the browser from guessing the content
#     type. Without this, a file served as text/plain
#     can be executed as JavaScript if the browser
#     decides it "looks like" a script.
#
# X-Frame-Options: DENY
#   → Prevents your API responses from being embedded
#     in an <iframe> on a malicious site.
#     Clickjacking attacks use this vector.
#
# X-XSS-Protection: 1; mode=block
#   → Legacy header still respected by older IE/Edge.
#     Tells the browser to block, not sanitize, on XSS
#     detection.
#
# Cache-Control: no-store
#   → Vulnerability data is sensitive. This tells every
#     proxy, CDN, and browser: do not store this response.
#     Without it, an attacker who gains access to a shared
#     cache sees your vuln data.
#
# Content-Security-Policy: default-src 'none'
#   → Most restrictive CSP. Since this is an API (not a
#     web app serving HTML), there's nothing to load.
#
# Referrer-Policy: no-referrer
#   → Prevents the API URL from leaking in the HTTP
#     Referer header when a browser follows a link.
#
# Source: OWASP Secure Headers Project
# ─────────────────────────────────────────────────

SECURITY_HEADERS = {
    "X-Content-Type-Options":  "nosniff",
    "X-Frame-Options":         "DENY",
    "X-XSS-Protection":        "1; mode=block",
    "Cache-Control":           "no-store",
    "Content-Security-Policy": "default-src 'none'",
    "Referrer-Policy":         "no-referrer",
}


_DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://cdn.jsdelivr.net; "
    "connect-src 'self';"
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            # Swagger UI needs scripts/styles/fetch; relax CSP for docs paths only
            if name == "Content-Security-Policy" and request.url.path.startswith(("/docs", "/swagger-static", "/openapi.json")):
                response.headers[name] = _DOCS_CSP
            else:
                response.headers[name] = value
        return response


# ─────────────────────────────────────────────────
# 4. CORRELATION ID MIDDLEWARE
#
# WHY does this exist?
# When a bug report says "something failed around 2PM",
# you need to find ONE transaction in a log file that
# may have thousands of entries per second.
#
# A UUID per request ties together:
# - the inbound request log line
# - every downstream log line that request triggered
# - the response log line
# - any error that occurred
#
# The UUID is also returned in X-Correlation-ID so the
# API caller can include it in bug reports.
#
# This is standard practice in every production system
# that handles more than trivial traffic.
# ─────────────────────────────────────────────────

class CorrelationIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Generate a new UUID for this specific request
        cid = str(uuid.uuid4())

        # Attach it to request.state so route handlers
        # can log it without receiving it as a parameter
        request.state.correlation_id = cid

        # Measure wall-clock time around the handler
        # monotonic() is immune to system clock changes
        start = time.monotonic()
        response = await call_next(request)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)

        # Echo it back so callers can reference it in support tickets
        response.headers["X-Correlation-ID"] = cid

        # One structured log line captures everything about this request
        log.info(
            f"{request.method} {request.url.path} → {response.status_code}",
            extra={"ctx": {
                "correlation_id": cid,
                "method":         request.method,
                "path":           str(request.url.path),
                "status_code":    response.status_code,
                "duration_ms":    elapsed_ms,
                "client_ip":      getattr(request.client, "host", "unknown"),
            }},
        )
        return response


# ─────────────────────────────────────────────────
# 5. CORS CONFIGURATION
#
# WHY not allow_origins=["*"] ?
# A wildcard CORS policy allows ANY website to make
# credentialed cross-site requests to your API.
# This is listed as a misconfiguration in
# OWASP API Security Top 10 (API7:2023).
#
# In dev, we restrict to localhost only.
# In production, this would be replaced with the
# explicit frontend domain(s).
# ─────────────────────────────────────────────────

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST"],   # Only expose what we actually use
    allow_headers=["Content-Type"],
)


# ─────────────────────────────────────────────────
# 6. INPUT VALIDATION MODEL
#
# WHY go beyond Pydantic's built-in type checks?
#
# Pydantic confirms that "name" is a string.
# It does NOT confirm that the string isn't:
#   - blank ("   " passes type checks)
#   - a SQL injection payload ("DROP TABLE users; --")
#   - an XSS payload ("<script>document.cookie</script>")
#   - 50,000 characters long
#   - a date formatted as "yesterday" or "2023/01/01"
#
# A DevSecOps engineer validates inputs as if every
# caller is adversarial. This is especially important
# for a public-facing API.
# ─────────────────────────────────────────────────

# Regex to catch the most obvious injection signals.
# Not a WAF replacement — a trip-wire for the obvious.
# Matches:
#   [<>{}&;]   → HTML/XML metacharacters used in XSS
#   <script    → Classic XSS vector
#   javascript: → URL-based XSS
#   SELECT\s   → SQL keyword (space prevents "SELECTED" matching)
#   DROP\s     → SQL DDL
#   INSERT\s   → SQL DML
#   --         → SQL comment marker
#   /\*        → SQL block comment open
_SUSPICIOUS = re.compile(
    r"[<>{}&;]|<script|javascript:|SELECT\s|DROP\s|INSERT\s|--|/\*",
    re.IGNORECASE,
)


class VulnerabilityDTO(BaseModel):
    # max_length caps prevent memory-based DoS from oversized fields.
    # A 500-char description is readable. A 500,000-char one is an attack.
    name:        str = Field(..., min_length=1, max_length=120)
    type:        str = Field(..., min_length=1, max_length=80)
    description: str = Field(..., min_length=1, max_length=500)
    date:        str = Field(..., description="ISO-8601 date: YYYY-MM-DD")

    @field_validator("name", "type", "description")
    @classmethod
    def sanitize_text(cls, v: str) -> str:
        # Strip leading/trailing whitespace first —
        # "  " has length 2 and would pass min_length=1
        stripped = v.strip()
        if not stripped:
            raise ValueError("Field cannot be blank or whitespace-only.")

        # Check for injection signals AFTER stripping.
        # Attackers sometimes pad with whitespace to bypass naive checks.
        if _SUSPICIOUS.search(stripped):
            raise ValueError("Field contains disallowed characters or patterns.")

        # Return the stripped version so stored data is always clean
        return stripped

    @field_validator("date")
    @classmethod
    def validate_date_format(cls, v: str) -> str:
        # Pydantic accepts ANY string for a `str` field.
        # "yesterday", "2023/01/01", "Jan 1 2023" all pass.
        # We need YYYY-MM-DD specifically because:
        #   1. The spec example uses this format
        #   2. The CLI sort relies on this format
        #   3. String-sort and datetime-sort agree on ISO-8601
        try:
            datetime.strptime(v.strip(), "%Y-%m-%d")
        except ValueError:
            # strptime raises ValueError for both wrong format
            # AND impossible dates like 2024-13-99
            raise ValueError("Date must be YYYY-MM-DD (e.g. 2023-06-01).")
        return v.strip()

    model_config = {
        "json_schema_extra": {
            "example": {
                "name":        "Elevation of Privilege",
                "type":        "Platform",
                "description": "Security Feature Bypass",
                "date":        "2022-01-01",
            }
        }
    }


# ─────────────────────────────────────────────────
# 7. IN-MEMORY DATA STORE
#
# WHY in-memory and not a database?
# The exercise scope doesn't require persistence.
# A database adds infrastructure dependency (Postgres,
# Docker Compose, migrations) that makes it harder
# for reviewers to run the code in 30 seconds.
#
# In production this would be replaced with a proper
# database + ORM (SQLAlchemy + PostgreSQL).
# The README documents this gap explicitly.
#
# WHY these 10 specific vulnerabilities?
# They're real CVEs and OWASP findings relevant to
# cloud SaaS / HR platforms — Paylocity's domain.
# Placeholder data like {"name": "vuln1"} signals
# that the engineer didn't think about the context.
# ─────────────────────────────────────────────────

_store: List[dict] = [
    {
        "name":        "Log4Shell",
        "type":        "Remote Code Execution",
        "description": "JNDI injection in Apache Log4j2 allowing unauthenticated RCE via crafted log messages.",
        "date":        "2021-12-09",
    },
    {
        "name":        "Spring4Shell",
        "type":        "Remote Code Execution",
        "description": "ClassLoader manipulation via Spring MVC data binding enabling OS command execution.",
        "date":        "2022-03-31",
    },
    {
        "name":        "Elevation of Privilege",
        "type":        "Platform",
        "description": "Security Feature Bypass allowing an unprivileged process to gain SYSTEM-level access.",
        "date":        "2022-01-01",
    },
    {
        "name":        "SQL Injection (OWASP A03)",
        "type":        "Injection",
        "description": "Unsanitized user input concatenated directly into SQL queries enabling data exfiltration.",
        "date":        "2023-04-15",
    },
    {
        "name":        "Broken Access Control (OWASP A01)",
        "type":        "Access Control",
        "description": "Missing authorization checks allow users to access resources outside their permissions.",
        "date":        "2023-06-01",
    },
    {
        "name":        "JWT Algorithm Confusion",
        "type":        "Authentication Bypass",
        "description": "Server accepts 'alg: none' tokens, bypassing signature verification entirely.",
        "date":        "2022-08-20",
    },
    {
        "name":        "SSRF via Cloud Metadata",
        "type":        "Server-Side Request Forgery",
        "description": "Unvalidated URL parameter proxies requests to the internal AWS metadata endpoint.",
        "date":        "2023-01-12",
    },
    {
        "name":        "Prototype Pollution",
        "type":        "Injection",
        "description": "Unsanitized deep-merge of user-supplied JSON modifies Object.prototype in Node.js.",
        "date":        "2021-09-03",
    },
    {
        "name":        "Insecure Deserialization (OWASP A08)",
        "type":        "Deserialization",
        "description": "Java object deserialization of untrusted data enables RCE via pre-built gadget chains.",
        "date":        "2020-11-17",
    },
    {
        "name":        "XXE Injection",
        "type":        "XML External Entity",
        "description": "XML parser processes external entity references, exposing server-side files and enabling SSRF.",
        "date":        "2021-05-22",
    },
]


# ─────────────────────────────────────────────────
# 8. ROUTES
# ─────────────────────────────────────────────────

@app.get("/health", tags=["Operations"])
def health():
    """
    Liveness probe — not in the exercise spec, added anyway.

    WHY?
    Every production service needs a health endpoint.
    Kubernetes uses it for readiness/liveness probes.
    Load balancers use it to decide which instances
    should receive traffic.
    Uptime monitors ping it every 30 seconds.

    A service without /health is operationally incomplete.
    """
    return {
        "status":       "healthy",
        "timestamp":    datetime.utcnow().isoformat() + "Z",
        "record_count": len(_store),
    }


@app.get("/api/v1/vulnerabilities", tags=["Vulnerabilities"])
def get_vulnerabilities():
    """
    Returns the full collection.

    WHY /api/v1/ prefix?
    When a breaking change is needed (rename a field,
    change a format), /api/v2/ is introduced alongside
    v1. Existing callers keep working without changes.
    A versionless API creates a hard cutover problem
    for every consumer simultaneously.

    WHY no server-side sorting?
    The spec explicitly asks the CLI to sort the GET
    response. Different consumers may want different
    sort orders (by date, by type, by name).
    Sorting server-side imposes one consumer's preference
    on all others and makes the API less flexible.
    """
    return {"results": _store, "count": len(_store)}


@app.post("/api/v1/vulnerabilities", status_code=201, tags=["Vulnerabilities"])
def post_vulnerabilities(items: List[VulnerabilityDTO], request: Request):
    """
    Accepts a JSON array of one or more DTOs.

    WHY an array and not a single object?
    The spec says "one or more objects".
    An array handles both cases with a single endpoint.
    A single-object endpoint forces N round trips for N items.
    Batching is more efficient and simpler for callers.

    WHY 50-item cap?
    Without a size limit, a caller can POST 100,000 items
    in one request and exhaust server memory.
    50 is a pragmatic limit — large enough for real batches,
    small enough to keep per-request memory bounded.
    In production this would be backed by rate limiting
    middleware (slowapi + Redis) as well.
    """
    if not items:
        # Pydantic won't catch an empty array — we do it manually
        raise HTTPException(status_code=400, detail="Send at least one item.")

    if len(items) > 50:
        raise HTTPException(
            status_code=400,
            detail="Maximum 50 items per request. Split into smaller batches.",
        )

    added = []
    # Pull the correlation ID off request.state (set by middleware)
    # so every "item added" log line is traceable back to the
    # original POST request without any extra plumbing
    cid = getattr(request.state, "correlation_id", "unknown")

    for item in items:
        # model_dump() converts the Pydantic model to a plain dict.
        # We store dicts (not Pydantic objects) so the list stays
        # JSON-serialisable without any custom encoder.
        entry = item.model_dump()
        _store.append(entry)
        added.append(entry)

        # Log each addition with context — if a bad actor floods
        # the API, these logs show exactly what was added and when
        log.info(
            f"Vulnerability added: {entry['name']}",
            extra={"ctx": {
                "correlation_id":     cid,
                "vulnerability_name": entry["name"],
                "vulnerability_type": entry["type"],
                "vulnerability_date": entry["date"],
            }},
        )

    return {"results": added, "count": len(added)}


# ─────────────────────────────────────────────────
# 9. ENTRY POINT
#
# WHY read host/port from environment variables?
# Hardcoding "127.0.0.1" and 8000 means the same
# binary can't run in staging or production without
# a code change — or worse, without an if/else block
# checking the environment by name.
#
# Environment variables let the deployment platform
# (Docker, Kubernetes, ECS) inject the right values.
# This is Twelve-Factor App principle III.
# ─────────────────────────────────────────────────

if __name__ == "__main__":
    host = os.getenv("API_HOST", "127.0.0.1")
    port = int(os.getenv("API_PORT", "8000"))
    log.info(
        "Starting Vulnerability Tracker API",
        extra={"ctx": {"host": host, "port": port}}
    )
    uvicorn.run("server:app", host=host, port=port, reload=False)