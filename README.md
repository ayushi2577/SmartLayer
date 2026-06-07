# 🛡️ django-smart-layer

> **AI-powered middleware for Django** — security, rate limiting, anomaly detection, and log analysis. Drop it in, configure once, forget about it.

---

## Why Smart Layer?

Every Django app eventually needs the same things:

- 🔒 Block malicious requests before they hit your views
- 🤖 Detect bots and scrapers automatically
- 📊 Know which users are hitting your API and how often
- 💳 Enforce subscription plan limits without writing boilerplate
- 📋 Understand what happened in your app yesterday — in plain English

Smart Layer gives you all of this in **one pip install.**

---

## What's Inside

| Middleware | Job | AI? |
|---|---|---|
| `AIAnomalyDetector` | Detects bots and attack patterns | ✅ Yes |
| `AIRequestValidator` | Blocks SQL injection, XSS, prompt injection | ✅ Yes |
| `RateLimiter` | Enforces per-plan request limits | ❌ No |
| `WatchLog` | Logs every request to your database | ❌ No |
| `analyse_logs` | Morning report — plain English summary of yesterday | ✅ Yes |

---

## How It All Fits Together

```
Incoming Request
        │
        ▼
┌───────────────────────┐
│   AIAnomalyDetector   │  ──── Is this user a bot? Suspicious pattern?
└───────────┬───────────┘       Blocked → 403
            │
            ▼
┌───────────────────────┐
│   AIRequestValidator  │  ──── Is this payload malicious?
└───────────┬───────────┘       Blocked → 403
            │
            ▼
┌───────────────────────┐
│      RateLimiter      │  ──── Is this user over their plan limit?
└───────────┬───────────┘       Blocked → 429
            │
            ▼
┌───────────────────────┐
│       WatchLog        │  ──── Log the request + response time
└───────────┬───────────┘       Always runs
            │
            ▼
    Your Django View  ✅
    (only clean requests reach here)

Every morning →  python manage.py analyse_logs
                 → Plain English report of yesterday
```

---

## Quick Start

### 1. Install

```bash
pip install django-smart-layer
```

### 2. Add to your settings

```python
INSTALLED_APPS = [
    ...
    'smart_layer',
]

MIDDLEWARE = [
    'smart_layer.middleware.AIAnomalyDetector',   # 1st — bot detection
    'smart_layer.middleware.AIRequestValidator',   # 2nd — payload validation
    'smart_layer.middleware.RateLimiter',          # 3rd — rate limiting
    'smart_layer.middleware.WatchLog',             # 4th — logging (always last)
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

    # ── AI Backend ──────────────────────────────────────────────
    'AI_API_KEY':  'your-api-key',
    'AI_BASE_URL': 'https://api.groq.com/openai/v1',   # see AI Providers below
    'AI_MODEL':    'llama3-8b-8192',

    # ── Rate Limiter ─────────────────────────────────────────────
    'PLAN_FIELD': 'plan',   # the field on your User model — e.g. request.user.plan

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
                'per_minute': 10,
                'per_hour':   200,
                'per_day':    1000,
                'lifetime':   10000,
            },
        },
    },

}
```

That's it. Your app is now protected. ✅

---

## Middleware — In Detail

---

### 🔍 AIAnomalyDetector

Watches request patterns and blocks bots before they can do damage.

**How it works — 3 checks, cheapest first:**

```
1. Empty user agent?              → Block immediately (no real browser does this)
2. 50+ requests in 10 seconds?    → Block immediately (obvious bot speed)
3. 75%+ errors in last 2 minutes? → Block immediately (scanning behaviour)
```

For borderline cases it uses a **suspicion scoring system:**

| Signal | Score |
|---|---|
| Suspicious user agent (curl, scrapy, wget...) | +2 |
| Elevated request rate (20–49 in 10s) | +3 |
| Moderate error rate (40–74%) | +2 |
| Hitting sensitive paths (/admin, /.env) | +4 |
| Scanning many distinct endpoints | +2 |
| Sequential ID probing (/users/1, /users/2...) | +5 |
| Burst after long idle, same endpoint | +2 |

Score ≥ 8 → blocked immediately, no AI needed.
Score 4–7 → request let through, AI asked in background. Banned on next request if AI says BLOCK.

> ⚡ **New users get a grace period** — first 20 requests are never scored, so legitimate users exploring your app aren't penalised.

**Returns:** `403 Forbidden`

---

### 🛡️ AIRequestValidator

Scans every request body for attacks before they reach your views.

**Two stages:**

**Stage 1 — Pattern matching (instant, free)**

Detects:
- SQL injection (`OR 1=1`, `UNION SELECT`, `DROP TABLE`...)
- XSS (`<script>`, `javascript:`, `onerror=`...)
- Path traversal (`../`, `/etc/passwd`...)
- Shell injection (`rm -rf`, `$(command)`...)
- Prompt injection (`ignore previous instructions`, `jailbreak`...)
- Null bytes and encoding tricks

Scoring:
```
Score 0   → clearly safe, no AI call needed
Score 1–2 → borderline, sent to AI for deeper analysis
Score 3+  → obviously malicious, blocked immediately (no AI call wasted)
```

**Stage 2 — AI analysis (only for score 1–2)**

AI looks for clever hidden attacks that bypass regex:
- Encoded attacks (base64, hex, unicode)
- Attacks split across multiple fields
- Business logic attacks (negative prices, impossible quantities)
- Social engineering attempts

Confidence > 85% → blocked.

> 💡 **File uploads are skipped** — multipart requests bypass validation automatically.

**Returns:** `403 Forbidden`

---

### ⏱️ RateLimiter

Enforces per-user, per-plan, per-path request limits. Built for SaaS.

**How plans work:**

```python
RATE_LIMIT_PLANS = {
    'free': {
        '/api/generate/': {'per_minute': 2, 'per_day': 50},
        '/api/export/':   {'per_minute': 1, 'per_day': 10},
    },
    'basic': {
        '/api/generate/': {'per_minute': 10, 'per_day': 500},
        '/api/export/':   {'per_minute': 5,  'per_day': 100},
    },
    'premium': {
        '/api/generate/': {'per_minute': 50, 'per_day': 5000},
        '/api/export/':   {'per_minute': 20, 'per_day': 1000},
        '/api/analytics/':{'per_minute': 100,'per_day': 10000},  # premium-only route
    },
}
```

- Routes only in `premium` automatically return `403` for free/basic users
- Each plan gets **independent counters** — upgrading starts fresh, never carries over old count
- Supports: `per_minute`, `per_hour`, `per_day`, `lifetime` — use any combination

**When a user upgrades their plan:**

```python
from smart_layer.utils import clear_user_cache

# call this in your plan upgrade view after updating the user's plan field
clear_user_cache(user)
```

**Returns:** `429 Too Many Requests`

---

### 📝 WatchLog

Records every request silently to the database. No configuration needed.

**What gets saved:**

| Field | Example |
|---|---|
| `method` | `GET` |
| `path` | `/api/generate/` |
| `status_code` | `200` |
| `response_time_ms` | `143.2` |
| `timestamp` | `2024-01-15 14:32:01` |
| `user_id` | `42` |
| `ip_address` | `192.168.1.1` (anonymous only) |
| `was_blocked` | `True / False` |

This data powers the `analyse_logs` command and the `AIAnomalyDetector`.

---

### 📊 analyse_logs (Management Command)

Run every morning to get a plain English summary of yesterday.

```bash
python manage.py analyse_logs
```

**What it reports:**
- Total requests and error rate
- Average response time
- Top 5 slowest endpoints
- Top 5 most hit endpoints
- Blocked request count
- AI recommendations — what to fix and why

**Schedule with cron (every morning at 6am):**

```bash
0 6 * * * /path/to/venv/bin/python /path/to/manage.py analyse_logs >> /var/log/smartlayer-daily.log
```

---

## AI Providers

Smart Layer uses the OpenAI-compatible API format. Works with any provider that supports it:

| Provider | `AI_BASE_URL` | Notes |
|---|---|---|
| **Groq** | `https://api.groq.com/openai/v1` | Fast, generous free tier — recommended |
| **OpenAI** | `https://api.openai.com/v1` | Most capable |
| **Gemini** | `https://generativelanguage.googleapis.com/v1beta/openai` | Google's free tier |
| **Ollama** | `http://localhost:11434/v1` | Fully local, completely free |

```python
# Example — using Groq
SMART_MIDDLEWARE = {
    'AI_API_KEY':  'gsk_...',
    'AI_BASE_URL': 'https://api.groq.com/openai/v1',
    'AI_MODEL':    'llama3-8b-8192',
    ...
}

# Example — using Ollama (free, local, no API key needed)
SMART_MIDDLEWARE = {
    'AI_API_KEY':  'ollama',
    'AI_BASE_URL': 'http://localhost:11434/v1',
    'AI_MODEL':    'llama3',
    ...
}
```

> 💡 **AI is optional for RateLimiter and WatchLog** — those two middlewares work with zero AI configuration. Only `AIAnomalyDetector`, `AIRequestValidator`, and `analyse_logs` need an API key.

---

## Requirements

- Python 3.10+
- Django 4.2+
- `httpx` — installed automatically with the package
- Redis *(recommended)* — for rate limit cache. Django's default in-memory cache works too but resets on server restart.

---

## Known Limitations

| Limitation | Workaround |
|---|---|
| Distributed attacks from many IPs | Use Cloudflare or AWS WAF in front |
| Slow drip attacks (1 req/hour over days) | Will appear in `analyse_logs` report |
| AI backend down | All middleware fails open — your app never breaks because of us |
| Plan changes need cache clear | Call `clear_user_cache(user)` in your upgrade view |

---

## Roadmap

- [ ] Grey-zone AI analysis in `AIAnomalyDetector`
- [ ] Usage dashboard at `/smart-layer/usage/`
- [ ] Email delivery for daily reports
- [ ] PyPI publishing
- [ ] Test suite

---

## License

MIT — free to use, modify, and distribute.

---

*Built for Django developers who want real security without the complexity.*
