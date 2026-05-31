#global level anamoly detection coming soon 


from .models import RequestLog
from django.conf import settings
from django.http import JsonResponse
from datetime import timedelta
from django.utils import timezone

class AIAnamolyDetector():
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):

        #=============================================================== BLACK ANAMOLY DETECTION ==========================
        #If user_agent is empty → BLOCK
        if not request.META.get('HTTP_USER_AGENT'):
            request._was_blocked = True
            return JsonResponse({"error": "blocked"}, status=403)


        #If user made 50 requests in last 10 seconds → BLOCK
        last_10secs=timezone.now()-timedelta(seconds=10)
        if RequestLog.objects.filter(user_id=request.user.id,timestamp__gte=last_10secs).count() >= 50:
            request._was_blocked = True
            return JsonResponse({"error": "blocked"}, status=403)
        
        #If user's last 20 requests in lst 2 minutes have 15+ errors (404/403/500) → BLOCK
        last2mins=timezone.now()-timedelta(minutes=2)
        request_in_2min=RequestLog.objects.filter(user_id=request.user.id,timestamp__gte=last2mins)
        if request_in_2min.count() <= 10:
            pass
        else:
            errors=request_in_2min.filter(status_code__gte=400).count()
            error_percent=errors/request_in_2min.count()*100
            if error_percent >= 75:
                request._was_blocked = True
                return JsonResponse({"error": "blocked"}, status=403)

        #=================================================   GREY ANAMOLY DETECTION WILL COME SOON ================================================
        
        response = self.get_response(request)
        return response
        
        