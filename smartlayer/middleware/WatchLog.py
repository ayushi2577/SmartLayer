#get_response = next bouncer
"""
WatchLog is a middleware that logs all requests to the database.
Basically populated RequestLog model with all the info about the request.
"""

import time
from ..models import RequestLog

import time
import threading
from ..models import RequestLog


class WatchLog:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start    = time.monotonic()
        response = self.get_response(request)
        end      = time.monotonic()

        response_time_ms = (end - start) * 1000

        # write in background — request returns immediately
        threading.Thread(
            target=self._save_log,
            args=(request, response, response_time_ms),
            daemon=True
        ).start()

        return response

    def _save_log(self, request, response, response_time_ms):
        try:
            RequestLog.objects.create(
                user_id          = request.user.id if request.user.is_authenticated else None,
                ip_address       = request.META.get('REMOTE_ADDR') if not request.user.is_authenticated else None,
                method           = request.method,
                path             = request.path,
                status_code      = response.status_code,
                response_time_ms = response_time_ms,
                was_blocked      = getattr(request, '_was_blocked', False)
            )
        except Exception:
            pass  # never crash the app over a log write 

#========================    Q&A    ====================================================================
"""

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'smartlayer.middleware.AIRequestValidator',    # 1st — block bad requests
    'smartlayer.middleware.AIAnomalyDetector',     # 2nd — detect patterns
    'corsheaders.middleware.CorsMiddleware',        # 3rd — CORS
    'smartlayer.middleware.WatchLog',              # 4th — log everything
    'smartlayer.middleware.RateLimiter',           # last — rate limit
]
"""