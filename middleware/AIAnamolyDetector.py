"""
Global level anomaly detection middleware.

Detects anomalies in request patterns and blocks malicious requests.
Patterns are divided into 3 categories: BLACK, GREY, WHITE.

BLACK:
    1. Empty user_agent → BLOCK
    2. 50+ requests in last 10 seconds → BLOCK
    3. 75%+ error rate in last 2 minutes (min 10 requests) → BLOCK

GREY:
    Suspicion scoring system. If score >= threshold → ask AI.
    AI receives raw behavioral data only (no score, no labels).
    If score >= 8 → block immediately without AI call.
    If score 4-7 → let request through, ask AI async, ban on next request.

WHITE:
    Not BLACK, not GREY → let through.

Configuration in settings.py:
    SMART_MIDDLEWARE = {
        'api_key': 'your_groq_api_key',
        'grey_suspicion_threshold': 4,       # default 4
        'grey_hard_block_score': 8,          # default 8, block without AI
        'grey_sensitive_paths': [            # optional, has defaults
            '/admin', '/.env', '/config',
            '/api/token', '/api/login',
        ],
    }

Currently only supports GROQ. If no API key is provided or AI call fails,
middleware will still run and fall back to allowing the request through.
"""

import re
import threading
from datetime import timedelta

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone

from .models import RequestLog
from .utils import ask_ai  # your existing function


# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_SENSITIVE_PATHS = [
    '/admin', '/.env', '/config', '/phpmyadmin',
    '/wp-admin', '/api/token', '/api/login',
]

SUSPICIOUS_UA_KEYWORDS = [
    'curl', 'python-requests', 'go-http', 'java/',
    'headlesschrome', 'phantomjs', 'scrapy', 'wget',
    'libwww', 'httpx', 'okhttp', 'aiohttp',
]

# Minimum requests before we start scoring
# Protects new users exploring the site
NEW_USER_GRACE_LIMIT = 20

# Score weights
W_SUSPICIOUS_UA         = 2
W_ELEVATED_RATE         = 3   # 20-49 req/10s
W_MODERATE_ERROR_RATE   = 2   # 40-74% errors in 2min
W_SENSITIVE_PATH        = 4   # hitting /.env /admin etc
W_ENDPOINT_SCANNING     = 2   # 15+ distinct paths/min
W_SEQUENTIAL_ID_PROBING = 5   # /users/1 /users/2 /users/3...
W_BURST_SAME_ENDPOINT   = 2   # burst after idle, same endpoint
W_UNAUTHENTICATED       = 1


# ═══════════════════════════════════════════════════════════════════════════════
#  MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

class AIAnomalyDetector:

    def __init__(self, get_response):
        self.get_response = get_response
        cfg = getattr(settings, 'SMART_MIDDLEWARE', {})
        self.grey_threshold     = cfg.get('grey_suspicion_threshold', 4)
        self.grey_hard_block    = cfg.get('grey_hard_block_score', 8)
        self.sensitive_paths    = cfg.get('grey_sensitive_paths', DEFAULT_SENSITIVE_PATHS)


    def __call__(self, request):
        now = timezone.now()

        # ── BLACK ────────────────────────────────────────────────────────────
        block_response = self._black_check(request, now)
        if block_response:
            return block_response

        # ── GREY ─────────────────────────────────────────────────────────────
        grey_response = self._grey_check(request, now)
        if grey_response:
            return grey_response

        # ── WHITE ─────────────────────────────────────────────────────────────
        return self.get_response(request)


    # ═══════════════════════════════════════════════════════════════════════════
    #  BLACK CHECKS
    # ═══════════════════════════════════════════════════════════════════════════

    def _black_check(self, request, now):

        # 1. Empty user agent
        if not request.META.get('HTTP_USER_AGENT'):
            return self._block(request)

        # 2. 50+ requests in last 10 seconds
        last_10s = now - timedelta(seconds=10)
        count_10s = RequestLog.objects.filter(
            user_id=request.user.id,
            timestamp__gte=last_10s
        ).count()
        if count_10s >= 50:
            return self._block(request)

        # 3. 75%+ error rate in last 2 minutes (min 10 requests)
        last_2min = now - timedelta(minutes=2)
        qs_2min = RequestLog.objects.filter(
            user_id=request.user.id,
            timestamp__gte=last_2min
        )
        total_2min = qs_2min.count()
        if total_2min >= 10:
            error_count = qs_2min.filter(status_code__gte=400).count()
            if (error_count / total_2min * 100) >= 75:
                return self._block(request)

        return None


    # ═══════════════════════════════════════════════════════════════════════════
    #  GREY CHECKS
    # ═══════════════════════════════════════════════════════════════════════════

    def _grey_check(self, request, now):
        score, payload = self._score_request(request, now)

        if score <= 0:
            return None

        # Hard block - score so high AI is not needed
        if score >= self.grey_hard_block:
            return self._block(request)

        # Soft grey - let request through, ask AI in background ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        if score >= self.grey_threshold:
            thread = threading.Thread(
                target=self._async_ai_check,
                args=(request.user.id, payload),
                daemon=True
            )
            thread.start()

        return None


    def _score_request(self, request, now):
        """
        Returns (score, raw_payload_for_ai).
        Score is computed internally and never passed to AI.
        Payload contains only raw behavioral facts.
        """
        score = 0
        user_id = request.user.id

        # ── GRACE PERIOD: new users are not scored ───────────────────────────
        last_24h = now - timedelta(hours=24)
        historical_count = RequestLog.objects.filter(
            user_id=user_id,
            timestamp__gte=last_24h
        ).count()
        if historical_count < NEW_USER_GRACE_LIMIT:
            return 0, {}

        # ── FETCH RECENT DATA (shared across checks) ─────────────────────────
        last_10s   = now - timedelta(seconds=10)
        last_1min  = now - timedelta(minutes=1)
        last_2min  = now - timedelta(minutes=2)
        last_30min = now - timedelta(minutes=30)
        last_40min = now - timedelta(minutes=40)

        count_10s = RequestLog.objects.filter(
            user_id=user_id,
            timestamp__gte=last_10s
        ).count()

        qs_2min = RequestLog.objects.filter(
            user_id=user_id,
            timestamp__gte=last_2min
        )

        total_2min  = qs_2min.count()
        error_count = qs_2min.filter(status_code__gte=400).count() if total_2min else 0
        error_rate  = (error_count / total_2min * 100) if total_2min else 0

        recent_paths = list(
            RequestLog.objects.filter(
                user_id=user_id,
                timestamp__gte=last_1min
            ).values_list('path', flat=True)
        )
        distinct_paths = len(set(recent_paths))

        ua = request.META.get('HTTP_USER_AGENT', '').lower()

        # ── SCORING ───────────────────────────────────────────────────────────

        # 1. Suspicious user agent
        if any(kw in ua for kw in SUSPICIOUS_UA_KEYWORDS):
            score += W_SUSPICIOUS_UA

        # 2. Elevated rate (20-49/10s) - 50+ is already black
        if 20 <= count_10s < 50:
            score += W_ELEVATED_RATE

        # 3. Moderate error rate (40-74%) - 75%+ is already black
        if total_2min >= 10 and 40 <= error_rate < 75:
            score += W_MODERATE_ERROR_RATE

        # 4. Sensitive path checking
        if any(request.path.startswith(p) for p in self.sensitive_paths):
            score += W_SENSITIVE_PATH

        # 5. Endpoint scanning - too many distinct paths in 1 min
        if distinct_paths >= 15:
            score += W_ENDPOINT_SCANNING

        # 6. Sequential ID checking - /users/1 /users/2 /users/3
        if self._is_sequential_probing(recent_paths):
            score += W_SEQUENTIAL_ID_PROBING

        # 7. Burst after long idle on same endpoint
        was_idle = not RequestLog.objects.filter(
            user_id=user_id,
            timestamp__gte=last_40min,
            timestamp__lt=last_30min
        ).exists()
        if was_idle and count_10s >= 15 and distinct_paths <= 2:
            score += W_BURST_SAME_ENDPOINT

        # 8. Unauthenticated user
        if not request.user.is_authenticated:
            score += W_UNAUTHENTICATED

        # ── BUILD RAW PAYLOAD FOR AI (no score, no labels) ───────────────────
        payload = {
            "user_agent"          : request.META.get('HTTP_USER_AGENT'),
            "is_authenticated"    : request.user.is_authenticated,
            "current_path"        : request.path,
            "recent_endpoints"    : recent_paths,
            "request_count_10s"   : count_10s,
            "distinct_paths_1min" : distinct_paths,
            "error_rate_2min"     : round(error_rate, 2),
            "total_requests_2min" : total_2min,
        }

        return score, payload


    # ═══════════════════════════════════════════════════════════════════════════
    #  HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _is_sequential_probing(self, paths, threshold=5):
        """
        Detects if recent paths contain sequentially incrementing IDs.
        e.g. /users/1 /users/2 /users/3 → True
             /products/4 /products/89 /products/247 → False (random = human)
        """
        id_pattern = re.compile(r'(\d+)$')
        numbers = []

        for path in paths:
            match = id_pattern.search(path)
            if match:
                numbers.append(int(match.group(1)))

        if len(numbers) < threshold:
            return False

        numbers.sort()
        consecutive = sum(
            1 for i in range(1, len(numbers))
            if numbers[i] - numbers[i - 1] == 1
        )
        return consecutive >= (threshold - 1)


    def _async_ai_check(self, user_id, payload):
        """
        Runs in background thread. Asks AI with raw payload only.
        If AI says BLOCK, flag user in DB for next request.
        """
        try:
            verdict = ask_ai(payload)   # utils function
            if verdict == "BLOCK":
                RequestLog.objects.filter(user_id=user_id).update(
                    ai_flagged=True     # add this field to your model
                )
        except Exception:
            pass    # AI failure never blocks the request


    @staticmethod
    def _block(request):
        request._was_blocked = True
        return JsonResponse({"error": "blocked"}, status=403)