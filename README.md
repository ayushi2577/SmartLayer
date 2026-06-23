# django-smart-layer

> **AI-powered security middleware for Django.**  
> Bot detection. Payload validation. Subscription-aware rate limiting. Intelligent log analysis.  
> Drop in. Ship. Sleep soundly.

[![PyPI version](https://img.shields.io/pypi/v/django-smart-layer.svg)](https://pypi.org/project/django-smart-layer/)
[![Python](https://img.shields.io/pypi/pyversions/django-smart-layer.svg)](https://pypi.org/project/django-smart-layer/)
[![Django](https://img.shields.io/badge/django-4.2%2B-green.svg)](https://www.djangoproject.com/)
[![Tests](https://github.com/ayushi2577/SmartLayer/actions/workflows/test.yml/badge.svg)](https://github.com/ayushi2577/SmartLayer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

Every Django app eventually needs the same security scaffolding — and every developer ends up writing it from scratch. SmartLayer gives you a production-grade, AI-augmented security pipeline in a single `pip install`. No external services. No vendor lock-in. Works with Groq, OpenAI, Gemini, or a fully local Ollama instance.

---

## Table of Contents

- [What's Inside](#whats-inside)
- [How the Pipeline Works](#how-the-pipeline-works)
- [Quick Start](#quick-start)
  - [Minimum Setup](#minimum-setup-no-ai-key-required)
  - [Maximum Setup](#maximum-setup-full-ai-power)
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
- [Tests](#tests)
- [Requirements](#requirements)
- [Known Limitations](#known-limitations)
- [Future Scope](#future-scope)
- [License](#license)

---

## What's Inside

| Middleware | What it does | Needs AI? |
|---|---|:---:|
| `AIAnomalyDetector` | Behavioural bot and attack-pattern detection — bans automatically | ✅ |
| `AIRequestValidator` | Blocks SQL injection, XSS, prompt injection, path traversal | ✅ |
| `RateLimiter` | Per-plan, per-path request quotas for SaaS subscription tiers | ❌ |
| `WatchLog` | Persists every request to the database — zero latency impact | ❌ |
| `analyse_logs` | Daily plain-English security report, delivered to Django admin | ✅ |

**`RateLimiter` and `WatchLog` work with zero AI configuration.** You can adopt SmartLayer one piece at a time.

---

## How the Pipeline Works

Every incoming request passes through a layered security pipeline before it ever touches your views:

```
Incoming Request
       │
       ▼
┌──────────────────────────────┐
│   AIAnomalyDetector          │  Bot? Attack pattern? → 403
│   (background, non-blocking) │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│   AIRequestValidator         │  Malicious payload? → 403
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│   RateLimiter                │  Over plan quota? → 429
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│   WatchLog                   │  Logs everything (always runs)
└──────────────┬───────────────┘
               │
               ▼
        Your Django View ✅
   Only clean, authorised requests
           reach here.

Every morning:  python manage.py analyse_logs
                → Plain English report in Django admin
```

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

### 4. Configure

Pick the setup that fits where you are right now.

---

### Minimum Setup (no AI key required)

No API key. No Redis. Works immediately. Use this when you want logging and rate limiting today, and plan to layer in AI protection later.

**What works:**
- ✅ `WatchLog` — every request recorded to the database
- ✅ `RateLimiter` — per-plan, per-path quotas enforced
- ❌ `AIAnomalyDetector` — silently skipped (no AI key)
- ❌ `AIRequestValidator` — silently skipped (no AI key)
- ❌ `analyse_logs` — runs but produces raw stats only, no AI summary

```python
# settings.py

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
    'PLAN_FIELD': 'plan',   # attribute on your User model — request.user.plan
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

---

### Maximum Setup (full AI power)

**What you need:** An AI API key (Groq's free tier is enough to start) and Redis as your cache backend. Optionally `apscheduler` for automatic daily reports.

**What works:**
- ✅ `AIAnomalyDetector` — full bot detection, behavioural scoring, AI verdicts, auto-expiring bans
- ✅ `AIRequestValidator` — pattern matching + AI confidence scoring for borderline payloads
- ✅ `RateLimiter` — per-plan quotas with persistent counters across server restarts
- ✅ `WatchLog` — full request logging
- ✅ `analyse_logs` — plain-English daily report auto-delivered to Django admin
- ✅ IP and path whitelisting (health checks, internal services, webhooks)
- ✅ Proxy-aware real IP extraction for Nginx, AWS ALB, and Cloudflare deployments

```python
# settings.py

INSTALLED_APPS = [
    ...
    'smartlayer',
]

MIDDLEWARE = [
    'smartlayer.middleware.AIAnomalyDetector',
    'smartlayer.middleware.AIRequestValidator',
    'smartlayer.middleware.RateLimiter',
    'smartlayer.middleware.WatchLog',
    ...
]

SMART_MIDDLEWARE = {
    # AI — any OpenAI-compatible endpoint works
    'AI_API_KEY':  'your-api-key',
    'AI_BASE_URL': 'https://api.groq.com/openai/v1',
    'AI_MODEL':    'llama3-8b-8192',

    # RateLimiter — paths use prefix matching, longest prefix wins
    'PLAN_FIELD': 'plan',
    'RATE_LIMIT_PLANS': {
        'anonymous': {
            '/api/v1/login/': {'per_minute': 5, 'per_hour': 20},
        },
        'free': {
            '/api/generate/': {
                'per_minute': 2,
                'per_hour':   20,
                'per_day':    100,
                'lifetime':   1000,   # total ever — never resets
            },
        },
        'premium': {
            '/api/generate/': {'per_minute': 50,  'per_day': 5000},
            '/api/export/':   {'per_minute': 20,  'per_day': 1000},
        },
    },

    # Log analysis
    'LOG_RETENTION_DAYS': 7,
    'ANALYSE_LOGS_AT': '06:00',     # remove this key if you prefer cron
    'VERBOSE_REPORT': False,        # set True in dev to see report in terminal

    # Sensitive paths — raise suspicion score for unauthenticated probing
    'grey_sensitive_paths': [
        '/admin', '/.env', '/config', '/api/token', '/api/login',
    ],

    # Whitelist — bypass AIAnomalyDetector entirely for known-safe IPs/paths
    'WHITELIST_IPS': [
        '10.0.0.5',        # internal service account
        '192.168.1.100',   # CI/CD runner
    ],
    'WHITELIST_PATHS': [
        '/health/',        # load balancer health check
        '/webhooks/',      # third-party webhook receiver
    ],

    # Proxy — enable only if Django is behind Nginx, ALB, or Cloudflare
    'TRUST_PROXY': True,
}

# Redis cache — keeps rate-limit counters alive across server restarts
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}
```

> SmartLayer emits a Django system check warning (`smartlayer.W001`) at startup if the default in-memory cache is in use, reminding you to switch to Redis.

Your app is now protected. ✅

---

## Middleware Reference

---

### 🤖 AIAnomalyDetector

Watches per-user request behaviour across a rolling time window. Bots, scrapers, and attack patterns get banned automatically — without adding any latency to your responses.

#### Architecture: two-stage, non-blocking

**Stage 1 — Main thread (instant)**

1. Ban check — is this user or IP already banned? → `403` immediately
2. Snapshot request metadata (user ID, IP, path, user agent)
3. Pass the request to `get_response()` and return to the user
4. Hand snapshot off to a background thread — the user never waits

**Stage 2 — Background thread (after response is sent)**

1. One DB query: fetch the last 40 minutes of logs for this user/IP
2. All time-window calculations done in Python — no further DB queries
3. BLACK rules evaluated first (deterministic, zero AI calls)
4. GREY scoring evaluated if no BLACK rule triggers
5. AI consulted only for genuinely ambiguous grey-zone cases

#### BLACK rules — instant ban, no AI

| Rule | Threshold | Ban Duration |
|---|---|---|
| Empty user agent | Any request | 24 hours |
| Burst rate | 50+ requests in 10 seconds | 1 hour |
| Error flood | 75%+ error rate in 2 minutes (min 10 requests) | 24 hours |

#### GREY scoring — suspicion accumulation

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

#### AI ban verdicts

```
BLOCK:1    — 1 hour   (minor violation, rate-limit abuse)
BLOCK:24   — 24 hours (suspicious pattern, likely bot)
BLOCK:168  — 7 days   (clear attack, scanner, or malicious probe)
```

#### Fail-open

If no AI key is configured or the AI call fails for any reason, the middleware continues normally. Only deterministic BLACK rules still apply. Your app never goes down because an AI endpoint is unavailable.

**Returns:** `403 Forbidden`

#### Optional scoring tuning

```python
SMART_MIDDLEWARE = {
    ...
    'grey_suspicion_threshold': 5,    # default: 5 — score to trigger AI consult
    'grey_hard_block_score':    8,    # default: 8 — score to ban without AI
    'grey_sensitive_paths': [
        '/admin', '/.env', '/config', '/api/token', '/api/login',
    ],
}
```

#### Whitelisting

`WHITELIST_IPS` and `WHITELIST_PATHS` bypass `AIAnomalyDetector` entirely — checked before ban logic, before scoring, before any background work. `RateLimiter`, `WatchLog`, and `AIRequestValidator` still run for whitelisted requests. `WHITELIST_PATHS` uses prefix matching.

---

### 🛡️ AIRequestValidator

Scans every request body for known attack patterns before the payload reaches your views. Two-stage approach: fast regex first, AI only for the hard cases.

#### Stage 1 — Pattern matching (instant, no AI)

Detects:

- SQL injection (`UNION SELECT`, `OR 1=1`, `DROP TABLE`, comment injection)
- Cross-Site Scripting — `<script>`, `javascript:`, event handlers
- Path traversal (`../`, encoded variants)
- Shell injection (backticks, `&&`, `||`, pipe chains)
- Prompt injection (attempts to override AI instructions in user input)
- Null byte injection
- Base64 and URL-encoded payload obfuscation

Scoring:

```
Score 0     → safe — request passes, no AI call
Score 1–2   → borderline — forwarded to AI for confidence scoring
Score 3+    → obviously malicious — blocked immediately, no AI call
```

#### Stage 2 — AI confidence scoring (borderline only)

AI analyses the full request body for attacks that bypass pattern matching:

- Encoded and split-field attacks
- Business logic abuse
- Social engineering payloads
- Obfuscated injection attempts

**Confidence ≥ 85%** → request blocked.

> **File uploads are excluded automatically.** `multipart/form-data` requests are not validated to avoid false positives on binary content.

**Fail-open:** Borderline requests (score 1–2) pass through if AI is unavailable. Requests scoring 3+ are still blocked by pattern matching alone.

**Returns:** `403 Forbidden`

---

### ⏱️ RateLimiter

Enforces per-user, per-plan, per-path request quotas. Designed from the ground up for SaaS products with subscription tiers.

#### Four independent limit types — use any combination

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

#### Key behaviours

- **Plan isolation** — paths defined only in `premium` return `403` for lower-plan users, enforcing feature gating cleanly
- **Independent counters** — upgrading a user's plan starts fresh counters; no carry-over from the old plan
- **Cache-based counting** — `per_minute`, `per_hour`, and `per_day` use atomic cache `incr`. Zero extra DB queries for time-based limits
- **Atomic lifetime counting** — uses `UPDATE ... SET lifetime_count = lifetime_count + 1` with Django `F()` expressions; race-condition safe under concurrent load
- **Prefix matching** — `/api/` as a limit key matches `/api/generate/`, `/api/export/`, etc. Longest prefix wins
- **Anonymous users** — skipped entirely; only authenticated users are rate-limited

**Returns:** `429 Too Many Requests` with a JSON body describing which limit was hit.

> **Cache recommendation:** Use Redis as your Django cache backend. The default in-memory cache resets counters on every server restart. SmartLayer emits `smartlayer.W001` as a system check warning if in-memory cache is detected.

---

### 📝 WatchLog

Records every request to the `RequestLog` database table. Zero configuration. Zero latency impact — all writes happen in a background thread after the response is already on its way to the client.

#### Fields recorded per request

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

Reads the previous day's request logs and writes a plain-English report using AI. Delivered straight to Django admin under **Daily Reports** — no extra tooling required.

```bash
python manage.py analyse_logs
```

#### Report covers

- Overall API health assessment with error rate interpretation
- Slowest endpoints and likely root causes
- Suspicious activity patterns worth investigating
- 2–3 concrete, actionable recommendations

#### Auto-cleanup

Logs older than `LOG_RETENTION_DAYS` are deleted on each run. Your database never grows unbounded.

#### Scheduling options

**Option A — APScheduler (in-process)**

```bash
pip install django-smart-layer[scheduler]
```

```python
SMART_MIDDLEWARE = {
    ...
    'ANALYSE_LOGS_AT': '06:00',   # runs daily at 6:00 AM server time
}
```

**Option B — Cron (recommended for production)**

```bash
0 6 * * * /path/to/venv/bin/python /path/to/manage.py analyse_logs
```

Cron is preferred in production for restartability and visibility in system-level monitoring.

---

## AI Provider Setup

SmartLayer uses any **OpenAI-compatible** API endpoint. Point `AI_BASE_URL` at the provider of your choice:

| Provider | `AI_BASE_URL` | Notes |
|---|---|---|
| **Groq** | `https://api.groq.com/openai/v1` | Recommended — fast inference, generous free tier |
| **OpenAI** | `https://api.openai.com/v1` | Most capable models |
| **Google Gemini** | `https://generativelanguage.googleapis.com/v1beta/openai` | Free tier available |
| **Ollama** | `http://localhost:11434/v1` | Fully local — no data leaves your server |

> `RateLimiter` and `WatchLog` **never** make AI calls. You can run both without any `AI_*` configuration.

---

## Full Settings Reference

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

SmartLayer creates four tables via Django migrations.

**`RequestLog`** — every request recorded by `WatchLog`. Indexed on `(user_id, timestamp)` for fast anomaly-detection queries and on `timestamp` alone for log analysis and cleanup.

**`BannedUser`** — users and IPs banned by `AIAnomalyDetector`. Bans are time-limited and expire automatically — no admin action required. Unique constraints prevent duplicate ban rows. Authenticated users are banned by `user_id`; anonymous users by IP.

**`UserRequestCount`** — lifetime request counters for `RateLimiter`. One row per `(user, path, plan)` combination. Updated via atomic `F()` expressions for concurrent safety.

**`DailyReport`** — plain-text reports written by `analyse_logs`. One row per day, ordered newest-first. Accessible in Django admin under **Daily Reports**.

---

## Proxy & IP Detection

By default, `REMOTE_ADDR` is used as the client IP. This is safe for direct-to-Django deployments.

If your Django app sits behind Nginx, AWS ALB, or Cloudflare, set `TRUST_PROXY: True`:

```python
SMART_MIDDLEWARE = {
    ...
    'TRUST_PROXY': True,
}
```

With `TRUST_PROXY` enabled, SmartLayer checks headers in this order:

1. `CF-Connecting-IP` (Cloudflare — single trusted value, no spoofing risk)
2. `X-Forwarded-For` leftmost value (Nginx / ALB)
3. `REMOTE_ADDR` as fallback

> **Security warning:** Never enable `TRUST_PROXY` if Django is directly internet-facing. Clients can forge `X-Forwarded-For`, bypassing IP-based bans entirely.

---

## Tests

SmartLayer ships with a comprehensive pytest test suite — **1,362 lines** across six test files covering every component:

```
tests/
├── test_anomaly_detector.py   # AIAnomalyDetector — BLACK rules, GREY scoring, AI verdicts
├── test_request_validator.py  # AIRequestValidator — pattern matching, AI confidence scoring
├── test_rate_limiter.py       # RateLimiter — per-plan quotas, atomic counters, prefix matching
├── test_watch_log.py          # WatchLog — background logging, field capture, blocked flag
├── test_ai_utils.py           # AI utilities — provider calls, fail-open behaviour
├── test_models.py             # Data models — BannedUser, RequestLog, UserRequestCount
└── test_utils.py              # Utility functions — IP extraction, proxy header parsing
```

Run the full suite:

```bash
pip install pytest pytest-django
pytest
```

Run a specific component:

```bash
pytest tests/test_anomaly_detector.py
pytest tests/test_rate_limiter.py -v
```

The CI pipeline runs the full test suite on every push via GitHub Actions (`.github/workflows/test.yml`).

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.10+ | |
| Django | 4.2+ | |
| httpx | 0.27+ | Installed automatically |
| apscheduler | 3.10+ | Optional — only for `ANALYSE_LOGS_AT` auto-scheduling |

**Recommended (not required):**

- Redis as Django cache backend — for persistent rate-limit counters across server restarts

---

## Known Limitations

| Limitation | Recommended Workaround |
|---|---|
| Coordinated attacks from many distinct IPs | Place Cloudflare or AWS WAF in front of Django |
| Slow drip attacks (1 request/hour over days) | Appear in daily `analyse_logs` reports for manual review |
| AI backend unavailable | All AI-dependent middleware fails open — app continues normally |
| Cache reset on server restart | Use Redis cache backend for persistent time-based rate limiting |
| `WatchLog` background thread is best-effort | In rare crash scenarios, a request may not be logged — not suitable as a compliance audit log |

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

*Built by [Ayushi Agrawal](https://github.com/ayushi2577) · [PyPI](https://pypi.org/project/django-smart-layer/) · [GitHub](https://github.com/ayushi2577/SmartLayer)*