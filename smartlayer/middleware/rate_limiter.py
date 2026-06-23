"""
RateLimiter is a middleware that limits requests to the backend.
Basically for  implemeting Subscription Plans to the backend.
Highest Level of configuration it demands for -
SMART_MIDDLEWARE dict in settings.py

SMART_MIDDLEWARE={
    'PLAN_FIELD': 'plan',  # WHAT IS THE PLAN FIELD IN USER MODEL
    'RATE_LIMIT_PLANS': {
        'anonymous': {
            '/api/v1/login/': {
                'per_minute': 5,
                'per_hour': 20,
            },
            '/api/v1/register/': {
                'per_minute': 3,
            },
        },
        'free': {
            '/api/v1/users/1': {
                'per_minute': 10,
                'per_hour': 100,
                'per_day': 1000,
                'lifetime': 10000,
            },
        },
        'pro': {
            '/api/v1/users/42': {
                'per_minute': 20,
                'per_hour': 200,
                'per_day': 2000,
                'lifetime': 20000,
            },
        },
    }
}

We provide a facilty to add rate limiting from lifetime -> per day -> per hour -> per minute. 
Checking Scores for each of them and then limiting the request.
Scope checking Precedence -: Lifetime -> per day -> per hour -> per minute

"""
from django.db import transaction
from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from ..models import UserRequestCount
from django.db.models import F

def get_path_limits(limits: dict, request_path: str) -> dict | None:
    if request_path in limits:
        return limits[request_path]
    
    # longest matching prefix wins
    matches = [p for p in limits if request_path.startswith(p)]
    if matches:
        return limits[max(matches, key=len)]
    
    return None


class RateLimiter:
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        
        try:
            config = settings.SMART_MIDDLEWARE
        except AttributeError:
            return self.get_response(request)                   # no config - just let through      

        if not request.user.is_authenticated:
            anon_limits = config.get('RATE_LIMIT_PLANS', {}).get('anonymous')
            if anon_limits:
                ip         = request.META.get('REMOTE_ADDR', 'unknown')
                path_limit = get_path_limits(anon_limits, request.path)

                if path_limit:
                    per_minute = path_limit.get('per_minute')
                    per_hour   = path_limit.get('per_hour')
                    per_day    = path_limit.get('per_day')

                    if per_minute:
                        key = f"rl:anon:min:{ip}:{request.path}"
                        cache.add(key, 0, 60)
                        if cache.incr(key) > per_minute:
                            request._was_blocked = True
                            response = JsonResponse({"error": "too many requests"}, status=429)
                            response["Retry-After"] = 60
                            return response

                    if per_hour:
                        key = f"rl:anon:hour:{ip}:{request.path}"
                        cache.add(key, 0, 3600)
                        if cache.incr(key) > per_hour:
                            request._was_blocked = True
                            response = JsonResponse({"error": "too many requests"}, status=429)
                            response["Retry-After"] = 3600
                            return response

                    if per_day:
                        key = f"rl:anon:day:{ip}:{request.path}"
                        cache.add(key, 0, 86400)
                        if cache.incr(key) > per_day:
                            request._was_blocked = True
                            response = JsonResponse({"error": "too many requests"}, status=429)
                            response["Retry-After"] = 86400
                            return response

            return self.get_response(request)

        plan_field = config.get('PLAN_FIELD', 'plan')       # default to 'plan'
        user_plan = getattr(request.user, plan_field)       # request.user.plan_filed like user.plan or user.subscription

        limits = config.get('RATE_LIMIT_PLANS', {}).get(user_plan)  #get all path limits

        if limits is None:                                  # plan not found in config - just let through
            response = self.get_response(request)
            return response
        
        path_limits = get_path_limits(limits, request.path)             # limit for incoming path

        if path_limits is None:                             # path not rate limited - let through
            response = self.get_response(request)
            return response

        per_minute =  path_limits.get('per_minute')         # per minute limit
        per_hour = path_limits.get('per_hour')              # per hour limit
        per_day = path_limits.get('per_day')                # per day limit
        lifetime = path_limits.get('lifetime')              # lifetime of limit

        # check fastest/cheapest limits FIRST, using atomic incr exactly as before
        if per_minute:
            key = f"rl:min:{request.user.id}:{user_plan}:{request.path}"
            cache.add(key, 0, 60)
            count = cache.incr(key)
            if count > per_minute:
                request._was_blocked = True
                response = JsonResponse({"error": "too many requests per minute"}, status=429)
                response["Retry-After"] = 60
                return response

        if per_hour:
            key = f"rl:hour:{request.user.id}:{user_plan}:{request.path}"
            cache.add(key, 0, 3600)
            count = cache.incr(key)
            if count > per_hour:
                request._was_blocked = True
                response = JsonResponse({"error": "rate limit exceeded for this hour"}, status=429)
                response["Retry-After"] = 3600
                return response

        if per_day:
            key = f"rl:day:{request.user.id}:{user_plan}:{request.path}"
            cache.add(key, 0, 86400)
            count = cache.incr(key)
            if count > per_day:
                request._was_blocked = True
                response = JsonResponse({"error": "rate limit exceeded for today"}, status=429)
                response["Retry-After"] = 86400
                return response

        if lifetime:
            with transaction.atomic():
                record = (
                    UserRequestCount.objects
                    .select_for_update()
                    .get_or_create(user=request.user, path=request.path, plan_field=user_plan)[0]
                )
                if record.lifetime_count >= lifetime:
                    request._was_blocked = True
                    return JsonResponse({"error": "Lifetime rate limit exceeded"}, status=429)
                record.lifetime_count = F('lifetime_count') + 1
                record.save(update_fields=['lifetime_count'])

        response=self.get_response(request)
        return response