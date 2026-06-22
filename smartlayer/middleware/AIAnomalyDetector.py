"""
Global level anomaly detection middleware.

Detects anomalies in request patterns and blocks malicious requests.
Patterns are divided into 3 categories: BLACK, GREY, WHITE.

BLACK:
    1. Empty user_agent → BLOCK (24h ban)
    2. 50+ requests in last 10 seconds → BLOCK (1h ban)
    3. 75%+ error rate in last 2 minutes (min 10 requests) → BLOCK (24h ban)

GREY:
    Suspicion scoring system. If score >= threshold → ask AI.
    AI receives raw behavioral data only (no score, no labels).
    AI responds with BLOCK:1 / BLOCK:24 / BLOCK:168 / ALLOW.
    If score >= 8 → block immediately without AI call (7 day ban).
    If score 4-7 → let request through, ask AI async, ban on next request.

WHITE:
    Not BLACK, not GREY → let through.

All bans are time-limited and expire automatically via BannedUser.is_banned().
No admin action is needed to lift expired bans.

Configuration in settings.py:
    SMART_MIDDLEWARE = {
        'AI_API_KEY': 'your_ai_api_key',
        'AI_BASE_URL': 'https://api.groq.com/openai/v1',
        'AI_MODEL': 'llama3-8b-8192',

        'grey_suspicion_threshold': 4,       # default 4
        'grey_hard_block_score': 8,          # default 8, block without AI
        'grey_sensitive_paths': [            # optional, has defaults
            '/admin', '/.env', '/config',
            '/api/token', '/api/login',
        ],
    }

Works with any OpenAI-compatible provider (Groq, OpenAI, Gemini, Ollama, etc.)
via AI_BASE_URL. If no API key is provided or AI call fails,
middleware will still run and fall back to allowing the request through.
"""

import re
import threading
from datetime import timedelta

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone

from concurrent.futures import ThreadPoolExecutor
import atexit

from ..models import RequestLog, BannedUser
from ..utils import ask_ai_verdict, get_client_ip


# ======================================================================
#  CONSTANTS
# ======================================================================

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
W_SENSITIVE_PATH        = 3   # hitting /.env /admin etc
W_ENDPOINT_SCANNING     = 2   # 15+ distinct paths/min
W_SEQUENTIAL_ID_PROBING = 5   # /users/1 /users/2 /users/3...
W_BURST_SAME_ENDPOINT   = 2   # burst after idle, same endpoint
W_UNAUTHENTICATED       = 1

# Ban durations for BLACK checks (deterministic, no AI needed)
BAN_HOURS_EMPTY_UA      = 24   # Empty user agent - likely bot
BAN_HOURS_RATE_LIMIT    = 1    # 50+ req/10s - burst, may be accidental
BAN_HOURS_ERROR_RATE    = 24   # 75%+ error rate - scanning or broken client
BAN_HOURS_HARD_BLOCK    = 168  # Grey score >= 8 - high confidence threat (7 days)


# ======================================================================        
#  MIDDLEWARE
# ======================================================================

class AIAnomalyDetector:

    executor=ThreadPoolExecutor(max_workers=4)  # limit to 4 concurrent log writes to avoid overwhelming the DB
    """class level cuz only one ThreadPoolExecutor is created for the entire lifetime of the server"""

    atexit.register(executor.shutdown,wait=True)  # ensure executor is cleaned up on app exit

    def __init__(self, get_response):
        self.get_response = get_response
        cfg = getattr(settings, 'SMART_MIDDLEWARE', {})
        self.grey_threshold  = cfg.get('grey_suspicion_threshold', 5)
        self.grey_hard_block = cfg.get('grey_hard_block_score', 8)
        self.sensitive_paths = cfg.get('grey_sensitive_paths', DEFAULT_SENSITIVE_PATHS)


    def __call__(self, request):

        # -- BAN CHECK ------------------------------------------------------------
        # For authenticated users, check by user_id.
        # For anonymous users, check by IP (unauthenticated = no user_id to track).
        # Expired bans are ignored automatically inside is_banned().

        ip = get_client_ip(request)   # replaces REMOTE_ADDR
        user_id = request.user.id if request.user.is_authenticated else None

        if BannedUser.is_banned(user_id=user_id, ip_address=ip if not user_id else None):
            request._was_blocked = True
            return JsonResponse({"error": "blocked"}, status=403)
        
        snapshot = {
            'user_id' : user_id,
            'ip'      : ip,
            'path'    : request.path,
            'ua'      : request.META.get('HTTP_USER_AGENT', ''),
            'is_auth' : request.user.is_authenticated,
            'now'     : timezone.now(),
        }
        
        self.executor.submit(self.analysis, snapshot)      # submit to thread pool for async logging - won't block the response
        return self.get_response(request)

        
    
    def analysis(self, snapshot):
        """
        Runs entirely in background thread.
        Main thread has already returned the response to the user.

        1. One DB query - fetch 40min of logs
        2. Slice in Python - no more DB queries for counting
        3. Black check - hard rules
        4. Grey check - scoring + AI
        """
        try:
            user_id = snapshot['user_id']
            ip      = snapshot['ip']
            now     = snapshot['now']
            lookup  = {'user_id': user_id} if user_id else {'ip_address': ip}

            # -- ONE QUERY ---------------------------------------------
            # Fetch widest window needed (40min).
            # Everything else is sliced from this in Python.

            last_40min = now - timedelta(minutes=40)
            logs = list(
                RequestLog.objects.filter(
                    timestamp__gte=last_40min,
                    **lookup
                ).values('timestamp', 'status_code', 'path')
            )

            # -- SLICE ---------------------------------------
            last_10s   = now - timedelta(seconds=10)
            last_1min  = now - timedelta(minutes=1)
            last_2min  = now - timedelta(minutes=2)
            last_30min = now - timedelta(minutes=30)

            logs_10s  = [l for l in logs if l['timestamp'] >= last_10s]
            logs_1min = [l for l in logs if l['timestamp'] >= last_1min]
            logs_2min = [l for l in logs if l['timestamp'] >= last_2min]
            logs_idle = [l for l in logs if last_40min <= l['timestamp'] < last_30min]

            total_2min  = len(logs_2min)
            error_count = sum(1 for l in logs_2min if l['status_code'] >= 400)
            error_rate  = (error_count / total_2min * 100) if total_2min else 0
            recent_paths = [l['path'] for l in logs_1min]

            behavior = {
                'count_10s'     : len(logs_10s),
                'total_2min'    : total_2min,
                'error_rate'    : error_rate,
                'error_count'   : error_count,
                'recent_paths'  : recent_paths,
                'distinct_paths': len(set(recent_paths)),
                'was_idle'      : len(logs_idle) == 0,
            }

            # black first, grey only if black did not ban
            banned = self._black_check(snapshot, behavior)
            if not banned:
                self._grey_check(snapshot, behavior)

        except Exception:
            pass  # analysis failure never affects the user


    # ======================================================================
    #  BLACK CHECK
    # ======================================================================

    def _black_check(self, snapshot, behavior):
        """
        Hard deterministic rules. No AI needed.
        Returns True if a ban was written, False otherwise.
        """

        # 1. Empty user agent
        if not snapshot['ua']:
            self._ban(snapshot, BAN_HOURS_EMPTY_UA, 'Empty user agent')
            return True

        # 2. 50+ requests in last 10 seconds
        if behavior['count_10s'] >= 50:
            self._ban(
                snapshot, BAN_HOURS_RATE_LIMIT,
                f"Burst: {behavior['count_10s']} requests in 10s"
            )
            return True

        # 3. 75%+ error rate in last 2 minutes (min 10 requests)
        if behavior['total_2min'] >= 10 and behavior['error_rate'] >= 75:
            self._ban(
                snapshot, BAN_HOURS_ERROR_RATE,
                f"High error rate: {behavior['error_count']}/{behavior['total_2min']} in 2min"
            )
            return True

        return False


    # ======================================================================
    #  GREY CHECK
    # ======================================================================

    def _grey_check(self, snapshot, behavior):
        """
        Scoring system. If score is high enough, ban or ask AI.
        Already running in background thread - AI call is direct, no new thread.
        """
        score = self._score(snapshot, behavior)

        if score <= 0:
            return

        # score so high we don't need AI - ban immediately
        if score >= self.grey_hard_block:
            self._ban(
                snapshot, BAN_HOURS_HARD_BLOCK,
                f'Hard block: suspicion score {score}'
            )
            return

        # borderline - ask AI, it decides ban duration
        if score >= self.grey_threshold:
            self._ask_ai_and_ban(snapshot, behavior)


    def _score(self, snapshot, behavior):
        """
        Computes suspicion score from behavior dict.
        Score is never passed to AI - only raw behavioral facts are.
        """
    

        score = 0
        ua    = snapshot['ua'].lower()

        # 1. Suspicious user agent
        if any(kw in ua for kw in SUSPICIOUS_UA_KEYWORDS):
            score += W_SUSPICIOUS_UA

        # 2. Elevated rate (20-49/10s) - 50+ is already black
        if 20 <= behavior['count_10s'] < 50:
            score += W_ELEVATED_RATE

        # 3. Moderate error rate (40-74%) - 75%+ is already black
        if behavior['total_2min'] >= 10 and 40 <= behavior['error_rate'] < 75:
            score += W_MODERATE_ERROR_RATE

        # 4. Sensitive path
        if not snapshot['is_auth'] and any(snapshot['path'].startswith(p) for p in self.sensitive_paths):
            score += W_SENSITIVE_PATH

        # 5. Endpoint scanning - 15+ distinct paths in 1 min
        if behavior['distinct_paths'] >= 25:
            score += W_ENDPOINT_SCANNING

        # 6. Sequential ID probing - /users/1 /users/2 /users/3
        if self._is_sequential_probing(behavior['recent_paths']):
            score += W_SEQUENTIAL_ID_PROBING

        # 7. Burst after long idle on same endpoint
        if behavior['was_idle'] and behavior['count_10s'] >= 15 and behavior['distinct_paths'] <= 2:
            score += W_BURST_SAME_ENDPOINT

        # 8. Unauthenticated
        if not snapshot['is_auth']:
            score += W_UNAUTHENTICATED

        return score


    # ======================================================================
    #  HELPERS
    # ======================================================================

    def _ask_ai_and_ban(self, snapshot, behavior):
        """
        Calls AI with raw behavioral facts.
        AI returns verdict + ban duration.
        Already in background thread - no new thread needed.
        """
        try:
            cfg = getattr(settings, 'SMART_MIDDLEWARE', {})

            payload = {
                'user_agent'          : snapshot['ua'],
                'is_authenticated'    : snapshot['is_auth'],
                'current_path'        : snapshot['path'],
                'recent_endpoints'    : behavior['recent_paths'],
                'request_count_10s'   : behavior['count_10s'],
                'distinct_paths_1min' : behavior['distinct_paths'],
                'error_rate_2min'     : round(behavior['error_rate'], 2),
                'total_requests_2min' : behavior['total_2min'],
            }

            result = ask_ai_verdict(payload, cfg)

            if result['verdict'] == 'BLOCK':
                self._ban(
                    snapshot,
                    result['ban_hours'],
                    f"AI verdict: {result['ban_hours']}h ban"
                )
        except Exception:
            pass  # AI failure never bans anyone


    def _ban(self, snapshot, ban_hours, reason):
        """
        Writes a time-limited ban to DB.
        Expires automatically - no admin action needed.
        """
        try:
            expires_at = timezone.now() + timedelta(hours=ban_hours)

            if snapshot['user_id']:
                BannedUser.objects.update_or_create(
                    user_id=snapshot['user_id'],
                    defaults={'reason': reason, 'expires_at': expires_at}
                )
            else:
                BannedUser.objects.update_or_create(
                    ip_address=snapshot['ip'],
                    defaults={'reason': reason, 'expires_at': expires_at}
                )
        except Exception:
            pass  # DB failure never crashes the middleware


    @staticmethod
    def _is_sequential_probing(paths, threshold=5):
        """
        Detects sequentially incrementing IDs in recent paths.
        /users/1 /users/2 /users/3 → True  (sequential probe)
        /products/4 /products/89 /products/247 → False (random = human)

        Looks for a single unbroken run, not scattered pairs.
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

        # find longest consecutive run
        max_run = 1
        current_run = 1
        for i in range(1, len(numbers)):
            if numbers[i] - numbers[i - 1] == 1:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1

        return max_run >= threshold