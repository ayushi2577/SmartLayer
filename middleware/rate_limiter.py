"""
RateLimiter is a middleware that limits requests to the backend.
Basically for  implemeting Subscription Plans to the backend.
Highest Level of configuration it demands for -
SMART_MIDDLEWARE dict in settings.py

SMART_MIDDLEWARE={
    'PLAN_FIELD': 'plan',  # WHAT IS THE PLAN FIELD IN USER MODEL
    'RATE_LIMIT_PLANS': {
        'free': {
            '/api/v1/users/1': {
                'per_minute': 10,
                'per_hour': 100,
                'per_day': 1000,
                'lifetime': 10000,
            },
        },
        'pro': {
            '/api/v1/users/1': {
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
from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from .models import UserRequestCount
from django.db.models import F

config = settings.SMART_MIDDLEWARE

class RateLimiter:
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        if not request.user.is_authenticated:
            response = self.get_response(request)
            return response
        
        plan_field = config.get('PLAN_FIELD', 'plan')       # default to 'plan'
        user_plan = getattr(request.user, plan_field)       # request.user.plan_filed like user.plan or user.subscription

        limits = config['RATE_LIMIT_PLANS'].get(user_plan)  #get all path limits

        if limits is None:                                  # plan not found in config - just let through
            response = self.get_response(request)
            return response
        
        path_limits = limits.get(request.path)              # limit for incoming path

        if path_limits is None:                             # path not rate limited - let through
            response = self.get_response(request)
            return response

        per_minute =  path_limits.get('per_minute')         # per minute limit
        per_hour = path_limits.get('per_hour')              # per hour limit
        per_day = path_limits.get('per_day')                # per day limit
        lifetime = path_limits.get('lifetime')              # lifetime of limit

        if lifetime:
            record, created = UserRequestCount.objects.get_or_create(user=request.user, path=request.path)
            count = record.lifetime_count
            if count >= lifetime:
                request._was_blocked = True
                return JsonResponse({"error": "Lifetime rate limit exceeded"}, status=429)
            UserRequestCount.objects.filter(pk=record.pk).update(lifetime_count=F('lifetime_count') + 1)        #to prevent race conditions -- concurrent requests causing multiple increments -- we do it in single query with F expression instead of fetching, incrementing and saving
            record.save()

        if per_day:
            key = f"rl:day:{request.user.id}:{user_plan}:{request.path}"
            count = cache.get(key, 0)
            if count >= per_day:
                request._was_blocked = True
                return JsonResponse({"error": "rate limit exceeded for today"}, status=429)
            cache.set(key, count + 1, 3600*24)  

        if per_hour:
            key = f"rl:hour:{request.user.id}:{user_plan}:{request.path}"
            count = cache.get(key, 0)
            if count >= per_hour:
                request._was_blocked = True
                return JsonResponse({"error": "rate limit exceeded for this hour"}, status=429)
            cache.set(key, count + 1, 3600)

        if per_minute:
            key = f"rl:min:{request.user.id}:{user_plan}:{request.path}"
            count = cache.get(key, 0)
            if count >= per_minute:
                request._was_blocked = True
                return JsonResponse({"error": "too many requests per minute"}, status=429)
            cache.set(key, count + 1, 60)
            
        response=self.get_response(request)
        return response