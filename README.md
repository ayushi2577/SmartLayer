# django-smart-layer

A pip-installable Django middleware package that adds AI-powered security, rate limiting, anomaly detection, and log analysis to any Django project.

---

## What's Inside

| Middleware | What it does |
|---|---|
| `WatchLog` | Logs every request and response to your database |
| `RateLimiter` | Per-user rate limiting based on subscription plans |
| `AIRequestValidator` | Blocks malicious request bodies using regex + AI |
| `AIAnomalyDetector` | Detects bot behaviour by analysing request patterns |
| `analyse_logs` | Management command — generates a plain English daily report |

---

## How They Work Together

```
Request arrives
→ [AIAnomalyDetector]   is this user a bot?         blocked if suspicious
→ [AIRequestValidator]  is this payload safe?        blocked if malicious
→ [RateLimiter]         is this user allowed?        blocked if over limit
→ [WatchLog]            record everything            always runs
→ Your Django View      actual business logic        only clean requests reach here
↑
[WatchLog]              record response time + status

Meanwhile, every morning:
python manage.py analyse_logs → reads logs → writes plain English report
```

---

## Installation

```bash
pip install django-smart-layer
```

Add to `INSTALLED_APPS` and `MIDDLEWARE` in your `settings.py`:

```python
INSTALLED_APPS = [
    ...
    'smart_layer',
]

MIDDLEWARE = [
    'smart_layer.middleware.AIAnomalyDetector',   # 1st — bot detection
    'smart_layer.middleware.AIRequestValidator',   # 2nd — payload validation
    'smart_layer.middleware.RateLimiter',          # 3rd — rate limiting
    'smart_layer.middleware.WatchLog',             # 4th — logging
    ...
]
```

Run migrations:
```bash
python manage.py migrate
```

---

## Configuration

Add `SMART_MIDDLEWARE` to your `settings.py`:

```python
SMART_MIDDLEWARE = {

    # --- AI Backend ---
    'AI_BACKEND': 'groq',           # 'groq' (cloud) or 'ollama' (local, free)
    'GROQ_API_KEY': env('GROQ_API_KEY'),   # only needed for groq

    # --- Rate Limiter ---
    'PLAN_FIELD': 'plan',           # field name on your User model (e.g. user.plan)
    'RATE_LIMIT_PLANS': {
        'free': {
            '/api/generate/': {
                'per_minute': 2,
                'per_hour': 20,
                'per_day': 100,
                'lifetime': 1000,
            },
        },
        'premium': {
            '/api/generate/': {
                'per_minute': 10,
                'per_hour': 200,
                'per_day': 1000,
                'lifetime': 10000,
            },
        },
    },

}
```

All fields are optional — only configure what you need.

---

## Middleware Details

### WatchLog
Saves every request to the `RequestLog` database table. Fields saved:
- `method`, `path`, `status_code`, `response_time_ms`
- `timestamp`, `was_blocked`, `user_id`, `ip_address`

No configuration needed.

---

### RateLimiter
Enforces per-user request limits based on their subscription plan.

Supports four limit types — all optional, set only what you need:
- `per_minute` — resets every 60 seconds
- `per_hour` — resets every hour
- `per_day` — resets every 24 hours
- `lifetime` — never resets (stored in database)

Returns `429 Too Many Requests` when limit is exceeded.

**Important:** When a user upgrades their plan, clear their rate limit cache:
```python
from smart_layer.utils import clear_user_cache
clear_user_cache(user)  # call this in your plan upgrade view
```

---

### AIRequestValidator
Two-stage validation on every incoming request body:

**Stage 1 — Regex scoring (free, instant):**
Checks for SQL injection, XSS, path traversal, shell injection, prompt injection, null bytes, and encoding tricks. Scores 0–N based on how many patterns match.

- Score 0 → safe, no AI call
- Score 3+ → obviously malicious, blocked immediately
- Score 1–2 → borderline, sent to AI

**Stage 2 — AI confidence check:**
AI analyses only borderline requests and returns a confidence score (0–100). Requests scoring above 85 are blocked.

Returns `403 Forbidden` for blocked requests.

---

### AIAnomalyDetector
Detects bot behaviour using three rules (cheapest first):

1. **Empty user agent** → block immediately (no real browser sends empty user agent)
2. **Speed check** → 50+ requests in last 10 seconds → block
3. **Error rate** → 10+ requests in last 2 minutes with 75%+ error rate → block

Returns `403 Forbidden` for blocked requests.

---

### Daily Log Analysis

Run every morning manually or via cron:

```bash
python manage.py analyse_logs
```

Schedule with cron (every morning at 6am):
```
0 6 * * * /path/to/venv/bin/python /path/to/manage.py analyse_logs
```

Reads yesterday's `RequestLog` entries, builds a traffic summary, and asks AI to write a plain English report covering:
- Total requests and error rate
- Slowest endpoints
- Most hit endpoints
- Blocked request count
- Recommendations

---

## Requirements

- Python 3.10+
- Django 4.2+
- `httpx` — for AI API calls
- Redis (recommended) — for rate limiting cache. Django's default cache works too but resets on server restart.

---

## AI Backend Setup

### Groq (recommended for production)
1. Get a free API key at [console.groq.com](https://console.groq.com)
2. Add to `.env`: `GROQ_API_KEY=gsk_...`
3. Set `'AI_BACKEND': 'groq'` in `SMART_MIDDLEWARE`

### Ollama (recommended for development — 100% free, local)
1. Download from [ollama.com/download](https://ollama.com/download)
2. Run: `ollama pull llama3 && ollama serve`
3. Set `'AI_BACKEND': 'ollama'` in `SMART_MIDDLEWARE`

---

## Known Limitations

- **Global/distributed attacks** (multiple IPs coordinating) are not detected. For this, use Cloudflare or AWS WAF in front of your server.
- **Slow attacks** (one request per hour over days) are not caught by `AIAnomalyDetector` but may appear in the daily `analyse_logs` report.
- **AI calls can fail** — all middleware fails open (lets request through) if the AI backend is unreachable, so your app never goes down because of us.
- **Plan changes** require manual cache clearing (see RateLimiter section).

---

## What's Not Done Yet (Roadmap)

- [ ] `AIAnomalyDetector` grey area — AI analysis of borderline user behaviour patterns
- [ ] Usage dashboard at `/smart-layer/usage/`
- [ ] Email delivery for daily reports
- [ ] `pyproject.toml` — package not yet publishable to PyPI
- [ ] Tests

---

## License

MIT
