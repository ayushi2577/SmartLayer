#get_response = next bouncer
"""
WatchLog is a middleware that logs all requests to the database.
Basically populated RequestLog model with all the info about the request.
"""

import time
from .models import RequestLog

class WatchLog:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        
        start=time.monotonic()   #start a monotonic timer for response time
        response=self.get_response(request)
        end=time.monotonic()
        
        response_time_ms=(end-start)*1000                                                   #in milliseconds

        RequestLog.objects.create(user_id=request.user.id if request.user.is_authenticated else None,
                        ip_address=request.META.get('REMOTE_ADDR'),
                        method=request.method, 
                        path=request.path, 
                        status_code=response.status_code, 
                        response_time_ms=response_time_ms,
                        was_blocked=getattr(request, '_was_blocked', False))                #get_attr(obj,attr,default) = obj.attr+if not available then default


        return response
    

#========================    Q&A    ====================================================================
"""
Watch log counts the timme in which backend reposnds to the client.
then it should be in starting ?
but starting is with corsheaders and other and we have our ratelimiter that must be at last 
so if the user have other middleware's impllemented how can we hadle order pressure
"""