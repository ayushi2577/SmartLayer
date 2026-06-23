# django-smart-layer

> **AI-powered security middleware for Django** — bot detection, request validation, subscription-aware rate limiting, and intelligent log analysis. Drop-in. Zero infrastructure.

[![PyPI version](https://img.shields.io/pypi/v/django-smart-layer.svg)](https://pypi.org/project/django-smart-layer/)
[![Python](https://img.shields.io/pypi/pyversions/django-smart-layer.svg)](https://pypi.org/project/django-smart-layer/)
[![Django](https://img.shields.io/badge/django-4.2%2B-green.svg)](https://www.djangoproject.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Middleware Reference](#middleware-reference)
  - [AIAnomalyDetector](#-aianomaly-detector)
  - [AIRequestValidator](#-airequestvalidator)
  - [RateLimiter](#-ratelimiter)
  - [WatchLog](#-watchlog)
  - [analyse\_logs](#-analyse_logs-management-command)
- [AI Provider Setup](#ai-provider-setup)
- [Full Settings Reference](#full-settings-reference)
- [Data Models](#data-models)
- [Proxy & IP Detection](#proxy--ip-detection)
- [Requirements](#requirements)
- [Known Limitations](#known-limitations)
- [Future Scope](#future-scope)
- [License](#license)

---

## Overview

Every Django application eventually needs the same security layer:

- Block malicious requests before they reach your views
- Detect and ban bots, scrapers, and attack patterns automatically
- Enforce per-plan API limits without writing boilerplate
- Understand what happened in your app — in plain English, every morning

**Smart Layer gives you all of this in one `pip install`.**

No external services. No vendor lock-in. No infrastructure to manage.  
Works with any OpenAI-compatible AI provider — including fully local models via Ollama.

---

## How It Works

Every incoming request passes through a layered pipeline before touching your views:

```
Incoming Request
       │
       ▼
┌──────────────────────────┐
│   AIAnomalyDetector      │  Bot? Attack pattern? → 403
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│   AIRequestValidator     │  Malicious payload? → 403
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│   RateLimiter            │  Over plan quota? → 429
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│   WatchLog               │  Logs everything (always runs)
└──────────┬───────────────┘
           │
           ▼
    Your Django View ✅
    Only clean, authorised requests get here.

Every morning:  python manage.py analyse_logs
                → Plain English report in Django admin
```

| Middleware | Responsibility | Requires AI |
|---|---|:---:|
| `AIAnomalyDetector` | Behavioural bot and attack-pattern detection | ✅ |
| `AIRequestValidator` | SQL injection, XSS, prompt injection blocking | ✅ |
| `RateLimiter` | Per-plan, per-path request quotas | ❌ |
| `WatchLog` | Persistent request logging to database | ❌ |
| `analyse_logs` | Daily plain-English log summary | ✅ |

---

## Quick Start

### 1. Install

```bash
pip install django-smart-layer
```

With auto-scheduling for daily log analysis:

```bash
pip install django-smart-layer[scheduler]
```

### 2. Add to `INSTALLED_APPS` and `MIDDLEWARE`

```python
# settings.py

INSTALLED_APPS = [
    ...
    'smartlayer',
]

MIDDLEWARE = [
    'smartlayer.middleware.AIAnomalyDetector',    # 1st — bot/attack detection
    'smartlayer.middleware.AIRequestValidator',    # 2nd — payload validation
    'smartlayer.middleware.RateLimiter',           # 3rd — subscription rate limiting
    'smartlayer.middleware.WatchLog',              # 4th — request logging (always last)
    ...
]
```

> **Order matters.** The pipeline above is the correct, tested sequence.

### 3. Run migrations

```bash
python manage.py migrate
```

### 4. Add configuration to `settings.py`

### Maximum Setup

**What you need:** An AI API key (Groq free tier is enough to start), Redis as cache backend, and optionally `apscheduler` for auto-scheduling.

**What works:**
- ✅ `AIAnomalyDetector` — full bot detection, behavioural scoring, AI verdicts, auto-expiring bans
- ✅ `AIRequestValidator` — pattern matching + AI confidence scoring for borderline payloads
- ✅ `RateLimiter` — per-plan quotas with persistent counters (Redis keeps them across restarts)
- ✅ `WatchLog` — full request logging
- ✅ `analyse_logs` — plain-English daily report delivered to Django admin, auto-scheduled
- ✅ Whitelisted IPs and paths skip anomaly detection entirely
- ✅ Proxy-aware real IP extraction for deployments behind Nginx, ALB, or Cloudflare
- ✅ Verbose terminal output for `analyse_logs` in non-production environments (`VERBOSE_REPORT: True`)

```python
# settings.py — Maximum setup

INSTALLED_APPS = [
    ...
    'smartlayer',
]

MIDDLEWARE = [
    'smartlayer.middleware.AIAnomalyDetector',    # 1st — bot/attack detection
    'smartlayer.middleware.AIRequestValidator',    # 2nd — payload validation
    'smartlayer.middleware.RateLimiter',           # 3rd — subscription rate limiting
    'smartlayer.middleware.WatchLog',              # 4th — logging (always last)
    ...
]

SMART_MIDDLEWARE = {

    # ── AI Backend ───────────────────────────────────────────────────────────
    # Used by: AIAnomalyDetector, AIRequestValidator, analyse_logs
    'AI_API_KEY':  'your-api-key',
    'AI_BASE_URL': 'https://api.groq.com/openai/v1',   # any OpenAI-compatible URL
    'AI_MODEL':    'llama3-8b-8192',

    # ── RateLimiter ──────────────────────────────────────────────────────────
    # PLAN_FIELD: attribute name on your User model (e.g. request.user.plan)
    # Paths use prefix matching — longest prefix wins.
    # Plans not listed here are let through without limiting.
    # Paths only in 'premium' return 403 for users on lower plans.
    'PLAN_FIELD': 'plan',
    'RATE_LIMIT_PLANS': {
        'free': {
            '/api/generate/': {
                'per_minute': 2,
                'per_hour':   20,
                'per_day':    100,
                'lifetime':   1000,    # total ever — never resets
            },
        },
        'basic': {
            '/api/generate/': {'per_minute': 10, 'per_hour': 100,  'per_day': 500},
            '/api/export/':   {'per_minute': 5,  'per_day':  100},
        },
        'premium': {
            '/api/generate/': {'per_minute': 50,  'per_day': 5000},
            '/api/export/':   {'per_minute': 20,  'per_day': 1000},
            '/api/analytics/':{'per_minute': 100, 'per_day': 10000},
        },
    },

    # ── Log Analysis ─────────────────────────────────────────────────────────
    # LOG_RETENTION_DAYS default: 7. Logs older than this are deleted on each run.
    # ANALYSE_LOGS_AT: remove this key entirely if you prefer cron (recommended in production).
    # VERBOSE_REPORT: if True, the full report is also printed to terminal (default: True).
    'LOG_RETENTION_DAYS': 7,
    'ANALYSE_LOGS_AT': '06:00',
    'VERBOSE_REPORT': False,                    # set True in dev to see report output in terminal

    # ── AIAnomalyDetector — scoring tuning ───────────────────────────────────
    # grey_suspicion_threshold: score at which AI is consulted (default: 5)
    # grey_hard_block_score:    score at which user is banned without asking AI (default: 8)
    # grey_sensitive_paths:     path prefixes that raise the sensitive-path signal (+3 score)
    'grey_suspicion_threshold': 5,
    'grey_hard_block_score':    8,
    'grey_sensitive_paths': [
        '/admin',
        '/.env',
        '/config',
        '/api/token',
        '/api/login',
    ],

    # ── Whitelist ────────────────────────────────────────────────────────────
    # These bypass AIAnomalyDetector entirely — before ban checks, before scoring.
    # WatchLog, RateLimiter, and AIRequestValidator still run for whitelisted requests.
    # WHITELIST_PATHS uses prefix matching — '/webhooks/' matches '/webhooks/stripe/' etc.
    'WHITELIST_IPS': [
        '10.0.0.5',          # internal service account
        '192.168.1.100',     # CI/CD runner
    ],
    'WHITELIST_PATHS': [
        '/health/',          # load balancer health check
        '/webhooks/',        # third-party webhook receiver
    ],

    # ── Proxy / IP Detection ─────────────────────────────────────────────────
    # Set True ONLY when Django is behind Nginx, AWS ALB, or Cloudflare.
    # Never enable on a direct-to-internet deployment — clients can forge X-Forwarded-For.
    # Priority order when True: CF-Connecting-IP → X-Forwarded-For (leftmost) → REMOTE_ADDR
    'TRUST_PROXY': True,
}
```

**Additional requirements for maximum setup:**

```bash
# AI support (httpx installed automatically with the package)
pip install django-smart-layer

# Auto-scheduling for analyse_logs
pip install django-smart-layer[scheduler]
```

```python
# Redis cache — keeps rate-limit counters alive across server restarts
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}
```

> Smart Layer emits a Django system check warning (`smartlayer.W001`) at startup if it detects the default in-memory cache is in use, reminding you to switch to Redis.

Your app is now protected. ✅

---
### Minimum Setup

**What you need:** Just logging and rate limiting — no AI key required. Zero risk of AI-related failures.

**What works:**
- ✅ `WatchLog` — every request is recorded to the database
- ✅ `RateLimiter` — per-plan, per-path quotas enforced
- ❌ `AIAnomalyDetector` — skipped (no AI key, fails open silently)
- ❌ `AIRequestValidator` — skipped (no AI key, fails open silently)
- ❌ `analyse_logs` — runs but produces a raw stats summary only, no plain-English AI report

```python
# settings.py — Minimum setup

INSTALLED_APPS = [
    ...
    'smartlayer',
]

MIDDLEWARE = [
    'smartlayer.middleware.RateLimiter',
    'smartlayer.middleware.WatchLog',
    ...
]

SMART_MIDDLEWARE = {
    # RateLimiter — the only thing that needs configuration here
    'PLAN_FIELD': 'plan',            # the attribute on your User model, e.g. user.plan
    'RATE_LIMIT_PLANS': {
        'free': {
            '/api/generate/': {'per_minute': 2, 'per_day': 50},
        },
        'premium': {
            '/api/generate/': {'per_minute': 50, 'per_day': 5000},
        },
    },
}
```

No `AI_API_KEY`. No migrations beyond the basic ones. Works immediately.

---


## Middleware Reference

---

### 🤖 AIAnomalyDetector

Watches per-user request behaviour and bans bots, scrapers, and attack patterns — without adding latency to your responses.

**Architecture: two-stage, non-blocking**

The middleware operates in two completely separate stages:

**Stage 1 — Main thread (instant)**

1. Ban check — is this user or IP already banned? → `403` immediately
2. Snapshot the request metadata (user ID, IP, path, user agent)
3. Pass the request to `get_response()` and return to the user
4. Hand snapshot off to a background thread — user never waits

**Stage 2 — Background thread (after response is sent)**

1. One DB query: fetch the last 40 minutes of logs for this user/IP
2. All time-window calculations done in Python — no further DB queries
3. BLACK rules evaluated first (deterministic, no AI needed)
4. GREY scoring evaluated if BLACK rules don't trigger
5. AI consulted only for ambiguous grey-zone cases

**BLACK rules — instant ban, no AI needed**

| Rule | Threshold | Ban Duration |
|---|---|---|
| Empty user agent | Any request | 24 hours |
| Burst rate | 50+ requests in 10 seconds | 1 hour |
| Error flood | 75%+ error rate in 2 minutes (min 10 requests) | 24 hours |

**GREY scoring — suspicion accumulation**

| Behavioural Signal | Score |
|---|---|
| Suspicious user agent (`curl`, `scrapy`, `wget`, etc.) | +2 |
| Elevated rate (20–49 requests in 10 seconds) | +3 |
| Moderate error rate (40–74% in 2 minutes) | +2 |
| Probing sensitive paths while unauthenticated (3+ hits) | +3 |
| Endpoint scanning (25+ distinct paths per minute) | +2 |
| Sequential ID probing (`/users/1`, `/users/2`, `/users/3`…) | +5 |
| Burst after idle period on same endpoint | +2 |
| Unauthenticated user | +1 |

- Score **≥ 8** → banned immediately for 7 days, no AI call
- Score **≥ 5** → AI consulted; banned on `BLOCK` verdict
- Score **< 5** → allowed, no action

**AI ban verdicts**

When the AI is consulted, it assigns a time-proportionate ban:

```
BLOCK:1    — 1 hour   (minor violation, rate-limit abuse)
BLOCK:24   — 24 hours (suspicious pattern, likely bot)
BLOCK:168  — 7 days   (clear attack, scanner, or malicious probe)
```

**Fail-open behaviour**

If no AI key is configured or the AI call fails for any reason, the middleware continues serving requests normally. Only deterministic BLACK rules still apply. Your application never breaks due to AI unavailability.

**Returns:** `403 Forbidden`

**Whitelisting IPs and paths:**

`WHITELIST_IPS` and `WHITELIST_PATHS` bypass `AIAnomalyDetector` entirely — checked before ban logic, before scoring, before any background work. `RateLimiter`, `WatchLog`, and `AIRequestValidator` still run for whitelisted requests. `WHITELIST_PATHS` uses prefix matching. See the [Configuration](#configuration--minimum-vs-maximum-setup) section for full examples and all available keys.

**Optional scoring tuning:**

```python
SMART_MIDDLEWARE = {
    ...
    'grey_suspicion_threshold': 5,    # default: 5 — score to trigger AI consult
    'grey_hard_block_score':    8,    # default: 8 — score to ban without AI
    'grey_sensitive_paths': [         # paths that raise the sensitive-path signal
        '/admin', '/.env', '/config', '/api/token', '/api/login',
    ],
}
```

---

### 🛡️ AIRequestValidator

Scans every request body for known attack patterns before the payload reaches your views. Uses a two-stage approach to minimise AI calls and maximise performance.

**Stage 1 — Pattern matching (instant, no AI)**

Detects the following attack categories via regex and heuristics:

- SQL injection (`UNION SELECT`, `OR 1=1`, `DROP TABLE`, comment injection)
- Cross-Site Scripting (XSS) — `<script>`, `javascript:`, event handlers
- Path traversal (`../`, encoded variants)
- Shell injection (backticks, `&&`, `||`, pipe chains)
- Prompt injection (attempts to override AI instructions in user input)
- Null byte injection
- Base64 and URL-encoded payload obfuscation

Scoring:

```
Score 0     → safe — no AI call, request passes through
Score 1–2   → borderline — sent to AI for confidence scoring
Score 3+    → obviously malicious — blocked immediately, no AI call
```

**Stage 2 — AI confidence scoring (borderline requests only)**

The AI analyses the full request body for attacks that bypass pattern matching:

- Encoded and split-field attacks
- Business logic abuse
- Social engineering payloads
- Obfuscated injection attempts

**Confidence ≥ 85%** → request blocked.

> **File uploads are excluded automatically.** `multipart/form-data` requests are not validated to avoid false positives on binary content.

**Fail-open behaviour:** If AI is unavailable, borderline requests (score 1–2) pass through. Requests scoring 3+ are still blocked by pattern matching alone.

**Returns:** `403 Forbidden`

---

### ⏱️ RateLimiter

Enforces per-user, per-plan, per-path request quotas. Designed for SaaS products with subscription tiers.

**Four independent limit types — use any combination:**

```python
'RATE_LIMIT_PLANS': {
    'free': {
        '/api/generate/': {
            'per_minute': 2,
            'per_hour':   20,
            'per_day':    100,
            'lifetime':   1000,   # never resets — total requests ever
        },
    },
}
```

**Key behaviours:**

- **Plan isolation** — paths defined only in `premium` return `403` for lower-plan users, enforcing feature gating cleanly
- **Independent counters** — upgrading a user's plan starts fresh counters; no carry-over
- **Cache-based counting** — `per_minute`, `per_hour`, and `per_day` use atomic cache `incr`. Zero extra DB queries for time-based limits
- **Atomic lifetime counting** — uses `UPDATE ... SET lifetime_count = lifetime_count + 1` with `F()` expressions; race-condition safe under concurrent load
- **Prefix matching** — `/api/` as a limit key matches `/api/generate/`, `/api/export/`, etc. Longest prefix wins
- **Anonymous users** — skipped entirely; only authenticated users are rate-limited

**Returns:** `429 Too Many Requests` with a plain JSON error body describing which limit was exceeded.

**Cache recommendation:** Use Redis as your Django cache backend. The default in-memory cache resets counters on every server restart. Smart Layer emits a Django system check warning (`smartlayer.W001`) if it detects in-memory cache is in use.

---

### 📝 WatchLog

Records every request to the `RequestLog` database table. Zero configuration. No performance impact.

All database writes happen in a **background thread** — your view's response is returned to the client immediately. Logging is never in the critical path.

**Fields recorded per request:**

| Field | Example | Notes |
|---|---|---|
| `method` | `GET` | HTTP method |
| `path` | `/api/generate/` | Request path |
| `status_code` | `200` | Response status |
| `response_time_ms` | `143.2` | End-to-end latency in ms |
| `timestamp` | `2024-01-15 14:32:01` | UTC |
| `user_id` | `42` | Set for authenticated users |
| `ip_address` | `192.168.1.1` | Set for anonymous users only |
| `was_blocked` | `True` | Set by upstream middleware if blocked |

`WatchLog` reads the `request._was_blocked` flag set by `RateLimiter`. Place `WatchLog` last in `MIDDLEWARE` to capture the correct blocked status from all upstream layers.

---

### 📊 `analyse_logs` Management Command

Reads the previous day's request logs and writes a plain-English report using AI. Report is saved to Django admin under **Daily Reports** and accessible without any extra tooling.

```bash
python manage.py analyse_logs
```

**Report covers:**

- Overall API health assessment with error rate interpretation
- Slowest endpoints and likely root causes
- Suspicious activity patterns worth investigating
- 2–3 concrete, actionable recommendations

**Auto-cleanup:** Logs older than `LOG_RETENTION_DAYS` are deleted automatically on each run. Your database never grows unbounded.

**Scheduling options:**

**Option A — APScheduler (in-process)**

```python
pip install django-smart-layer[scheduler]

SMART_MIDDLEWARE = {
    ...
    'ANALYSE_LOGS_AT': '06:00',   # runs daily at 6:00 AM server time
}
```

**Option B — Cron (recommended for production)**

```bash
0 6 * * * /path/to/venv/bin/python /path/to/manage.py analyse_logs
```

Cron is preferred in production for reliability, restartability, and visibility in system-level monitoring.

---

## AI Provider Setup

Smart Layer uses any **OpenAI-compatible** API endpoint. Set `AI_BASE_URL` to the provider of your choice:

| Provider | `AI_BASE_URL` | Notes |
|---|---|---|
| **Groq** | `https://api.groq.com/openai/v1` | Recommended — fast inference, generous free tier |
| **OpenAI** | `https://api.openai.com/v1` | Most capable models |
| **Google Gemini** | `https://generativelanguage.googleapis.com/v1beta/openai` | Free tier available |
| **Ollama** | `http://localhost:11434/v1` | Fully local — no data leaves your server, free |

> **`RateLimiter` and `WatchLog` never make AI calls.** Only `AIAnomalyDetector`, `AIRequestValidator`, and `analyse_logs` require a key. You can run the non-AI middleware without any `AI_*` configuration.

---

### What Each Key Does — At a Glance

| Key | Required | Default | Used By |
|---|:---:|---|---|
| `AI_API_KEY` | For AI features | — | `AIAnomalyDetector`, `AIRequestValidator`, `analyse_logs` |
| `AI_BASE_URL` | For AI features | — | Same as above |
| `AI_MODEL` | For AI features | — | Same as above |
| `PLAN_FIELD` | For `RateLimiter` | `'plan'` | `RateLimiter` |
| `RATE_LIMIT_PLANS` | For `RateLimiter` | `{}` | `RateLimiter` |
| `LOG_RETENTION_DAYS` | No | `7` | `analyse_logs` |
| `ANALYSE_LOGS_AT` | No | — (disabled) | `analyse_logs` auto-scheduler |
| `VERBOSE_REPORT` | No | `True` | `analyse_logs` terminal output |
| `grey_suspicion_threshold` | No | `5` | `AIAnomalyDetector` |
| `grey_hard_block_score` | No | `8` | `AIAnomalyDetector` |
| `grey_sensitive_paths` | No | Built-in list | `AIAnomalyDetector` |
| `WHITELIST_IPS` | No | `[]` | `AIAnomalyDetector` |
| `WHITELIST_PATHS` | No | `[]` | `AIAnomalyDetector` |
| `TRUST_PROXY` | No | `False` | All middleware (IP detection) |

---

## Data Models

Smart Layer creates four database tables via migrations.

**`RequestLog`**  
Every request recorded by `WatchLog`. Indexed on `(user_id, timestamp)` for fast anomaly-detection queries, and on `timestamp` alone for log analysis and cleanup.

**`BannedUser`**  
Users and IPs banned by `AIAnomalyDetector`. Bans are time-limited and expire automatically — no admin action required. Unique constraints prevent duplicate ban rows. Authenticated users are banned by `user_id`; anonymous users by IP.

**`UserRequestCount`**  
Lifetime request counters for `RateLimiter`. One row per `(user, path, plan)` combination. Updated via atomic `F()` expressions to handle concurrent requests safely.

**`DailyReport`**  
Plain-text reports written by `analyse_logs`. One row per day, ordered newest-first. Accessible via Django admin under **Daily Reports**.

---

## Proxy & IP Detection

By default, `REMOTE_ADDR` is used as the client IP. This is safe for direct-to-Django deployments.

If your Django app sits behind Nginx, AWS ALB, or Cloudflare, set `TRUST_PROXY: True` to extract the real client IP:

```python
SMART_MIDDLEWARE = {
    ...
    'TRUST_PROXY': True,
}
```

With `TRUST_PROXY` enabled, Smart Layer checks headers in this priority order:

1. `CF-Connecting-IP` (Cloudflare — single trusted value, no spoofing risk)
2. `X-Forwarded-For` leftmost value (Nginx / ALB)
3. `REMOTE_ADDR` as fallback

> **Security warning:** Never enable `TRUST_PROXY` if Django is directly internet-facing. Clients can forge `X-Forwarded-For` headers, bypassing IP-based bans entirely.

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.10+ | |
| Django | 4.2+ | |
| httpx | 0.27+ | Installed automatically |
| apscheduler | 3.10+ | Optional — only for `ANALYSE_LOGS_AT` |

**Recommended (not required):**

- Redis as Django cache backend — for persistent rate-limit counters across server restarts

---

## Known Limitations

| Limitation | Recommended Workaround |
|---|---|
| Coordinated attacks from many distinct IPs | Place Cloudflare or AWS WAF in front of Django |
| Slow drip attacks (1 request/hour over days) | These appear in daily `analyse_logs` reports for manual review |
| AI backend unavailable | All AI-dependent middleware fails open — app continues serving requests normally |
| Cache reset on server restart | Use Redis cache backend for persistent time-based rate limiting |
| `WatchLog` background thread is best-effort | In rare crash scenarios, a request may not be logged; not suitable as an audit log for compliance |

---

## Future Scope

- [ ] Usage dashboard at `/smart-layer/dashboard/`
- [ ] Email delivery for daily `analyse_logs` reports
- [ ] Webhook support for ban events
- [ ] Per-IP rate limiting (in addition to per-user)

---

## License

MIT — free to use, modify, and distribute.

---

*Built for Django developers who want real, layered protection without the operational complexity.*
