#get_response = next bouncer
"""
WatchLog is a middleware that logs all requests to the database.
Basically populated RequestLog model with all the info about the request.
It uses a ThreadPoolExecutor to write logs asynchronously, so it doesn't block the response.
We also register an atexit handler to ensure the executor is properly shut down when the app exits.
"""

import time
from concurrent.futures import ThreadPoolExecutor
import atexit
from ..models import RequestLog
from ..utils import get_client_ip


class WatchLog:

    executor=ThreadPoolExecutor(max_workers=4)  # limit to 4 concurrent log writes to avoid overwhelming the DB
    """class level cuz only one ThreadPoolExecutor is created for the entire lifetime of the server"""

    atexit.register(executor.shutdown,wait=True)  # ensure executor is cleaned up on app exit

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start    = time.monotonic()
        response = self.get_response(request)
        end      = time.monotonic()

        # resolve all request data NOW, in the main thread before giving it to the executor, to avoid any issues with request object being accessed in another thread after the response is returned
        log_data = {
            'user_id'          : request.user.id if request.user.is_authenticated else None,
            'ip_address'       : get_client_ip(request) if not request.user.is_authenticated else None,
            'method'           : request.method,
            'path'             : request.path,
            'status_code'      : response.status_code,
            'response_time_ms' : (end - start) * 1000,
            'was_blocked'      : getattr(request, '_was_blocked', False),
        }

        self.executor.submit(self._save_log, log_data)      # submit to thread pool for async logging - won't block the response
        return response

    def _save_log(self, log_data):
        try:
            RequestLog.objects.create(**log_data)
        except Exception:
            pass  # never crash the app over a log write 

#========================    Q&A    ====================================================================
"""
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',           # 1st - CORS on all responses
    'smartlayer.middleware.AIAnomalyDetector',         # 2nd - ban check + pattern detection
    'smartlayer.middleware.AIRequestValidator',        # 3rd - payload scanning
    'smartlayer.middleware.RateLimiter',               # 4th - plan limits
    'smartlayer.middleware.WatchLog',                  # last - log everything including blocks
]
"""