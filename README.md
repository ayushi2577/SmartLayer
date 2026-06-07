# 🛡️ django-smart-layer

> **AI-powered middleware for Django** — security, rate limiting, anomaly detection, and log analysis.
> Drop it in. Configure once. Forget about it.

---

## Why django-smart-layer?

Every Django app eventually needs the same things:

- 🔒 Block malicious requests before they touch your views
- 🤖 Detect bots and scrapers automatically
- 💳 Enforce subscription plan limits without writing boilerplate
- 📋 Understand what happened in your app — in plain English

**Smart Layer gives you all of this in one pip install.**

No external services. No accounts. No infrastructure.
Just add it to `MIDDLEWARE` and you're protected.

---

## What's Inside

| Middleware | Job | AI? |
|---|---|---|
| `AIAnomalyDetector` | Detects bots and attack patterns | ✅ |
| `AIRequestValidator` | Blocks SQL injection, XSS, prompt injection | ✅ |
| `RateLimiter` | Enforces per-plan, per-path request limits | ❌ |
| `WatchLog` | Logs every request to your database | ❌ |
| `analyse_logs` | Morning report — plain English summary | ✅ |

---

## How It All Fits Together

```
Incoming Request
        │
        ▼
┌───────────────────────┐
│   AIAnomalyDetector   │  Is this user a bot? Suspicious pattern?
└───────────┬───────────┘  Blocked → 403
            │
            ▼
┌───────────────────────┐
│   AIRequestValidator  │  Is this payload malicious?
└───────────┬───────────┘  Blocked → 403
            │
            ▼
┌───────────────────────┐
│      RateLimiter      │  Is this user over their plan limit?
└───────────┬───────────┘  Blocked → 429
            │
            ▼
┌───────────────────────┐
│       WatchLog        │  Log everything — always runs
└───────────┬───────────┘
            │
            ▼
    Your Django View ✅
    Only clean requests reach here.

Every morning →  python manage.py analyse_logs
                 Plain English report saved to Django admin
```

---

## Quick Start

### 1. Install

```bash
pip install django-smart-layer
```

With auto-scheduling support:
```bash
pip install django-smart-layer[scheduler]
```

### 2. Add to settings

```python
INSTALLED_APPS = [
    ...
    'smartlayer',
]

MIDDLEWARE = [
    'smartlayer.middleware.AIAnomalyDetector',    # 1st — bot detection
    'smartlayer.middleware.AIRequestValidator',    # 2nd — payload validation
    'smartlayer.middleware.RateLimiter',           # 3rd — rate limiting
    'smartlayer.middleware.WatchLog',              # 4th — logging (always last)
    ...
]
```

### 3. Run migrations

```bash
python manage.py migrate
```

### 4. Configure

```python
SMART_MIDDLEWARE = {

    # ── AI Backend ──────────────────────────────────────────────────────
    'AI_API_KEY':  'your-api-key',
    'AI_BASE_URL': 'https://api.groq.com/openai/v1',
    'AI_MODEL':    'llama3-8b-8192',

    # ── Rate Limiter ─────────────────────────────────────────────────────
    'PLAN_FIELD': 'plan',       # field name on your User model — e.g. user.plan

    'RATE_LIMIT_PLANS': {
        'free': {
            '/api/generate/': {'per_minute': 2,  'per_day': 50},
        },
        'basic': {
            '/api/generate/': {'per_minute': 10, 'per_day': 500},
            '/api/export/':   {'per_minute': 5,  'per_day': 100},
        },
        'premium': {
            '/api/generate/': {'per_minute': 50,  'per_day': 5000},
            '/api/export/':   {'per_minute': 20,  'per_day': 1000},
            '/api/analytics/':{'per_minute': 100, 'per_day': 10000},
        },
    },

    # ── Log Analysis ─────────────────────────────────────────────────────
    'LOG_RETENTION_DAYS': 30,       # auto delete logs older than 30 days
    'ANALYSE_LOGS_AT': '06:00',     # auto run report daily at 6am (needs apscheduler)
}
```

That's it. Your app is protected. ✅

---

## Middleware — In Detail

---

### 🤖 AIAnomalyDetector

Watches request patterns and blocks bots before they can do damage.

**Three instant block rules:**

```
1. Empty user agent              → block immediately
2. 50+ requests in 10 seconds   → block immediately
3. 75%+ errors in last 2 minutes → block immediately
```

**Suspicion scoring for subtle attacks:**

| Signal | Score |
|---|---|
| Suspicious user agent (curl, scrapy, wget...) | +2 |
| Elevated request rate (20–49 in 10s) | +3 |
| Moderate error rate (40–74%) | +2 |
| Hitting sensitive paths (/admin, /.env) | +4 |
| Scanning 15+ distinct endpoints per minute | +2 |
| Sequential ID probing (/users/1, /users/2...) | +5 |
| Burst after long idle on same endpoint | +2 |

Score ≥ 8 → blocked immediately.
Score 4–7 → AI asked in background. Banned on next request if AI says BLOCK.

> ⚡ New users get a **grace period** — first 20 requests are never scored.
> Legitimate users exploring your app are never penalised.

**Returns:** `403 Forbidden`

---

### 🛡️ AIRequestValidator

Scans every request body for attacks before they reach your views.

**Stage 1 — Pattern matching (instant, free)**

Detects SQL injection, XSS, path traversal, shell injection,
prompt injection, null bytes, and encoding tricks.

```
Score 0   → safe, no AI call needed
Score 1–2 → borderline, sent to AI
Score 3+  → obviously malicious, blocked immediately
```

**Stage 2 — AI analysis (only for borderline requests)**

Catches clever attacks that bypass regex:
encoded attacks, split-field attacks, business logic abuse,
social engineering, and obfuscated payloads.

Confidence > 85% → blocked.

> 💡 File uploads (multipart) are skipped automatically.

**Returns:** `403 Forbidden`

---

### ⏱️ RateLimiter

Enforces per-user, per-plan, per-path limits. Built for SaaS.

**Supports four limit types — use any combination:**

```python
'RATE_LIMIT_PLANS': {
    'free': {
        '/api/generate/': {
            'per_minute': 2,
            'per_hour':   20,
            'per_day':    100,
            'lifetime':   1000,   # never resets
        },
    },
}
```

**Key behaviours:**
- Routes only in `premium` automatically return `403` for lower plan users
- Each plan gets **independent counters** — upgrading starts fresh
- Cache-based counting — zero extra DB load for time-based limits
- Lifetime limits use atomic DB increments — race condition safe

**Returns:** `429 Too Many Requests`

---

### 📝 WatchLog

Silently records every request to the database. Zero configuration needed.

Writes happen in a **background thread** — response returns instantly,
database write happens after. Zero performance impact.

**What gets saved:**

| Field | Example |
|---|---|
| `method` | `GET` |
| `path` | `/api/generate/` |
| `status_code` | `200` |
| `response_time_ms` | `143.2` |
| `timestamp` | `2024-01-15 14:32:01` |
| `user_id` | `42` (authenticated users) |
| `ip_address` | `192.168.1.1` (anonymous only) |
| `was_blocked` | `True / False` |

---

### 📊 analyse_logs

Reads yesterday's logs and writes a plain English report using AI.

```bash
python manage.py analyse_logs
```

**What it covers:**
- Overall API health assessment
- Error rate and what it means
- Slowest endpoints and likely causes
- Suspicious activity worth investigating
- 2–3 clear actionable recommendations

**Report saved to Django admin → Daily Reports. Always accessible.**

**Auto cleanup:** Logs older than `LOG_RETENTION_DAYS` deleted automatically.
Your database never grows out of control.

**Auto schedule (requires apscheduler):**

```python
SMART_MIDDLEWARE = {
    ...
    'ANALYSE_LOGS_AT': '06:00',   # runs every day at 6am automatically
}
```

**Or use cron:**

```bash
0 6 * * * /path/to/venv/bin/python /path/to/manage.py analyse_logs
```

---

## AI Providers

Works with any OpenAI-compatible provider:

| Provider | `AI_BASE_URL` | Notes |
|---|---|---|
| **Groq** | `https://api.groq.com/openai/v1` | Fast, generous free tier — recommended |
| **OpenAI** | `https://api.openai.com/v1` | Most capable |
| **Gemini** | `https://generativelanguage.googleapis.com/v1beta/openai` | Google free tier |
| **Ollama** | `http://localhost:11434/v1` | Fully local, completely free |

> 💡 `RateLimiter` and `WatchLog` need zero AI configuration.
> Only `AIAnomalyDetector`, `AIRequestValidator`, and `analyse_logs` need a key.

---

## Complete Settings Reference

```python
SMART_MIDDLEWARE = {

    # AI — required for AI middlewares and analyse_logs
    'AI_API_KEY':  'your-key',
    'AI_BASE_URL': 'https://api.groq.com/openai/v1',
    'AI_MODEL':    'llama3-8b-8192',

    # RateLimiter
    'PLAN_FIELD': 'plan',           # field name on User model
    'RATE_LIMIT_PLANS': {
        'free': {
            '/api/generate/': {
                'per_minute': 2,
                'per_hour':   20,
                'per_day':    100,
                'lifetime':   1000,
            },
        },
        'premium': {
            '/api/generate/': {
                'per_minute': 50,
                'per_day':    5000,
            },
        },
    },

    # analyse_logs
    'LOG_RETENTION_DAYS': 30,       # default: 30
    'ANALYSE_LOGS_AT': '06:00',     # remove to use cron instead

    # AIAnomalyDetector — optional tuning
    'grey_suspicion_threshold': 4,
    'grey_hard_block_score':    8,
    'grey_sensitive_paths': [
        '/admin', '/.env', '/api/token',
    ],
}
```

---

## Requirements

- Python 3.10+
- Django 4.2+
- `httpx` — installed automatically
- `apscheduler` — optional, only for `ANALYSE_LOGS_AT`

---

## Known Limitations

| Limitation | Workaround |
|---|---|
| Coordinated attacks from many IPs | Use Cloudflare or AWS WAF in front |
| Slow drip attacks (1 req/hour over days) | Will appear in `analyse_logs` report |
| AI backend unreachable | All middleware fails open — app never breaks |
| Cache resets on server restart | Use Redis cache for persistent rate limiting |

---

## Roadmap

- [ ] Usage dashboard at `/smart-layer/usage/`
- [ ] Grey-zone AI analysis in `AIAnomalyDetector`
- [ ] Email delivery for daily reports
- [ ] Test suite

---

## License

MIT — free to use, modify, and distribute.

---

*Built for Django developers who want real protection without the complexity.*
