"""
Analyse API logs and generate a plain English summary.

Making it easy for developers to understand the overall health of their API,
identify slow endpoints, spot error patterns, and get actionable recommendations
without digging through raw log data.

Minimal configuration needed in settings.py:

SMART_MIDDLEWARE = {
    'AI_API_KEY':          'your_ai_api_key',
    'AI_BASE_URL':         'https://api.groq.com/openai/v1',
    'AI_MODEL':            'llama3-8b-8192',
    'ANALYSE_LOGS_AT':     '06:00',  # optional, default is 6am
    'LOG_RETENTION_DAYS':  30,    # optional, default is 30 days
}

Works with any OpenAI-compatible provider — Groq, OpenAI, Gemini, Ollama.
If no API key is provided or AI call fails, command still runs and provides
raw summary without AI insights — app never breaks because of us.

Schedule with cron (every morning at 6am):
    0 6 * * * /path/to/venv/bin/python /path/to/manage.py analyse_logs
"""

from django.core.management.base import BaseCommand
from django.db.models import Avg, Count
from django.conf import settings
from django.utils import timezone
from smartlayer.models import BannedUser
from datetime import date, timedelta, datetime


class Command(BaseCommand):
    help = 'Analyse yesterday logs and save plain English report to database'

    def handle(self, *args, **options):

        from smartlayer.models import RequestLog, DailyReport

        config = getattr(settings, 'SMART_MIDDLEWARE', {})
        yesterday = date.today() - timedelta(days=1)

        # --Auto cleanup old logs ------------------------------
        retention_days = config.get('LOG_RETENTION_DAYS', 7)
        cutoff = datetime.now() - timedelta(days=retention_days)
        deleted_count, _ = RequestLog.objects.filter(timestamp__lt=cutoff).delete()
        if deleted_count:
            self.stdout.write(f"[Smart Layer] Cleaned up {deleted_count} logs older than {retention_days} days")

        # -- Auto cleanup expired bans -------------------------
        deleted_bans, _ = BannedUser.objects.filter(
            expires_at__isnull=False,
            expires_at__lt=timezone.now()
        ).delete()
        if deleted_bans:
            self.stdout.write(f"[Smart Layer] Cleaned up {deleted_bans} expired bans")


        # -- Collect yesterday's stats --------------------------
        logs = RequestLog.objects.filter(timestamp__date=yesterday)
        total    = logs.count()

        if total == 0:
            self.stdout.write(f"[Smart Layer] No logs found for {yesterday}. Nothing to analyse.")
            return

        errors   = logs.filter(status_code__gte=400).count()
        blocked  = logs.filter(was_blocked=True).count()
        avg_time = logs.aggregate(Avg('response_time_ms'))['response_time_ms__avg'] or 0

        slowest = (
            logs.values('path')
            .annotate(avg_time=Avg('response_time_ms'))
            .order_by('-avg_time')[:5]
        )

        top_paths = (
            logs.values('path')
            .annotate(count=Count('path'))
            .order_by('-count')[:5]
        )

        slowest_text   = "\n".join([f"  {r['path']}: {r['avg_time']:.1f}ms" for r in slowest])
        top_paths_text = "\n".join([f"  {r['path']}: {r['count']} hits" for r in top_paths])

        # -- Build raw summary -----------------------------------
        summary = f"""
            Date:              {yesterday}
            Total requests:    {total}
            Errors (4xx/5xx):  {errors} ({(errors/total*100):.1f}%)
            Avg response time: {avg_time:.1f}ms
            Blocked requests:  {blocked}

            Top 5 slowest endpoints:
            {slowest_text}

            Top 5 most hit endpoints:
            {top_paths_text}
                    """.strip()

        # -- Asking AI to explain it in plain English ---------------
        ai_available = bool(
            config.get('AI_API_KEY') and
            config.get('AI_BASE_URL') and
            config.get('AI_MODEL')
        )

        if ai_available:
            try:
                from smartlayer.utils import ask_ai_text

                prompt = f"""
                    You are an API monitoring expert reviewing a Django app's daily traffic report.

                    Write a plain English summary in 8-10 lines covering:
                    - Overall API health
                    - Error rate assessment
                    - Slowest endpoints and why they might be slow
                    - Anything suspicious or worth investigating
                    - 2-3 clear actionable recommendations

                    Keep it simple — the developer reading this is busy.
                    Do not repeat raw numbers, just explain what they mean.

                    Data:
                    {summary}
                """.strip()

                result = ask_ai_text(prompt, config)

                final_report = f"""
                    {'='*60}
                    SMART LAYER — DAILY REPORT — {yesterday}
                    {'='*60}

                    {result}

                    {'-'*60}
                    RAW STATS:
                    {summary}
                    {'='*60}
                    """.strip()

            except Exception as e:
                # AI failed — fall back to raw summary, never crash
                final_report = f"""
                    {'='*60}
                    SMART LAYER — DAILY REPORT — {yesterday}
                    {'='*60}

                    AI analysis unavailable ({str(e)})

                    RAW STATS:
                    {summary}
                    {'='*60}
                """.strip()

        else:
            # no AI configured — just save raw summary
            final_report = f"""
                {'='*60}
                SMART LAYER — DAILY REPORT — {yesterday}
                {'='*60}

                AI analysis not configured.
                Add AI_API_KEY, AI_BASE_URL and AI_MODEL to SMART_MIDDLEWARE for plain English insights.

                RAW STATS:
                {summary}
                {'='*60}
            """.strip()

        # -- Save to DB ------------------------------------------
        # saves to developer's existing database
        # uses async write so this never blocks anything
        report_obj, created = DailyReport.objects.update_or_create(
            date=yesterday,
            defaults={'report': final_report}
        )

        action = "Created" if created else "Updated"
        self.stdout.write(f"[Smart Layer] {action} report for {yesterday} — visible in Django admin → Daily Reports")

        # -- Print to terminal too ------------------------------
        is_production = not config.get('VERBOSE_REPORT', True)
        if not is_production:
            self.stdout.write(final_report)
    
        # always write a simple status line
        # this goes to cron logs in production — short and clean
        self.stdout.write(
        f"[Smart Layer] Report for {yesterday} saved. "
        f"Total: {total} requests, Errors: {errors}, Blocked: {blocked}"
        )