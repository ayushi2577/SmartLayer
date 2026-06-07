"""
Analyse API logs and generate a plain English summary.
Making it easy for developers to understand the overall health of their API, 
identify slow endpoints, spot error patterns, and get actionable recommendations without digging through raw log data.

Minimal configuration needed in settings.py
SMART_MIDDLEWARE = {
        'AI_API_KEY': 'your_ai_api_key',
        'AI_BASE_URL': 'https://api.groq.com/openai/v1',
        'AI_MODEL': 'llama3-8b-8192',
    }

Currently only supports GROQ but can be extended to support other AI providers in future
If no API key is provided or if AI call fails for any reason, the command will still run and 
provide the summary without AI insights, to avoid breaking the app.
"""
from django.core.management.base import BaseCommand
from datetime import date,timedelta
from django.db.models import Avg,Count
from smartlayer.utils import ask_ai_text
from django.conf import settings


class Command(BaseCommand):
    help = 'Analyse logs'
    def handle(self, *args, **options):
        
        from smartlayer.models import RequestLog
        
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

        slowest_text = "\n".join([f"{r['path']}: {r['avg_time']:.1f}ms" for r in slowest])
        top_paths_text = "\n".join([f"{r['path']}: {r['count']} hits" for r in top_paths])

        summary = f"""
            Date: {yesterday}
            Total requests: {total}
            Errors: {errors}
            Avg response time: {avg_time}ms
            Blocked: {blocked}

            Top 5 slowest:
            {slowest_text}

            Top 5 most hit:
            {top_paths_text}
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
        self.stdout.write(result)  # not return result as here we are giving him in the terminal

#======================================================= Q&A  ===========================================       
"""
How will it know when to run beacuse along iwth collecting log will it run and the how is 
it a midlle ware what will be its actuall lifecycle look like?
"""

