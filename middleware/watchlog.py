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

        RequestLog.objects.create(method=request.method, path=request.path, status_code=response.status_code, response_time_ms=response_time_ms)


        return response