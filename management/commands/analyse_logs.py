
from django.core.management.base import BaseCommand
from datetime import date,timedelta
from django.db.models import Avg,Count
from middleware.utils import ask_ai_text
from django.conf import settings


class Command(BaseCommand):
    help = 'Analyse logs'
    def handle(self, *args, **options):
        
        from middleware.models import RequestLog
        
        yesterday = date.today() - timedelta(days=1)
        logs=RequestLog.objects.filter(timestamp__date=yesterday)
        
        #total — total requests
        total=logs.count()

        #errors — status code >= 400
        errors=logs.filter(status_code__gte=400).count()

        #avg_time — average response time
        avg_time=logs.aggregate(Avg('response_time_ms'))['response_time_ms__avg']
              
        #slowest — top 5 slowest paths
        slowest = logs.values('path').annotate(avg_time=Avg('response_time_ms')).order_by('-avg_time')[:5]

        #top_paths — top 5 most hit paths
        top_paths= logs.values('path').annotate(count=Count('path')).order_by('-count')[:5]

        #blocked — requests blocked by our middleware
        blocked=logs.filter(was_blocked=True).count()

        summary = f"""
            Date: {yesterday}
            Total requests: {total}
            Errors: {errors}
            Avg response time: {avg_time}ms
            Blocked: {blocked}

            Top 5 slowest:
            {slowest}

            Top 5 most hit:
            {top_paths}
            """
        
        prompt = f"""
            You are an API monitoring expert.
            Analyze this API traffic report and write a plain English summary in 8-10 lines.
            Cover: overall health, slowest endpoints, error rate, anything suspicious.
            Give recommendations at the end.

            Data:
            {summary}
            """
        config = getattr(settings, 'SMART_MIDDLEWARE', {}) 
        if not config:
            return summary+"\n\nAI reviews not avalilable as no API key is set."
        result= ask_ai_text(prompt, config)
        return result


        


