#get_response = next bouncer

import time
from .models import RequestLog

class WatchLog:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        
        start=time.monotonic()
        response=self.get_response(request)
        end=time.monotonic()
        
        response_time_ms=(end-start)*1000                                                   #in milliseconds

        RequestLog.objects.create(user_id=request.user.id if request.user.is_authenticated else None,
                        ip_address=request.META.get('REMOTE_ADDR'),
                        method=request.method, 
                        path=request.path, 
                        status_code=response.status_code, 
                        response_time_ms=response_time_ms,
                        was_blocked=getattr(request, '_was_blocked', False))


        return response