# Changelog

All notable changes to django-smart-layer will be documented here.

---

## [0.1.3] — 2026-06-23

### Added
- Anonymous user rate limiting via `RATE_LIMIT_PLANS['anonymous']`  —
  developers can now define per-path limits for unauthenticated requests,
  tracked by IP address
- Full test suite added across all middleware components — previously
  untested code paths are now covered

### Fixed
- Race condition in rate limiter resolved using atomic cache operations
- Whitelisted IPs are now correctly bypassed across all middleware layers
- Cloudflare and reverse-proxy headers (`CF-Connecting-IP`, `X-Forwarded-For`)
  now correctly resolved for real client IP detection

---

## [0.1.2] — Earlier release

- `AIRequestValidator` — AI-powered request body scanning
- `AIAnomalyDetector` — background anomaly detection with IP banning
- `RateLimiter` — subscription plan based rate limiting
- `WatchLog` — async request logging to database