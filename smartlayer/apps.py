# smart_layer/apps.py
from django.apps import AppConfig

class SmartLayerConfig(AppConfig):
    name = 'smart_layer'

    def ready(self):
        from django.conf import settings
        config = getattr(settings, 'SMART_MIDDLEWARE', {})
        
        # only schedule if developer wants it
        schedule_time = config.get('ANALYSE_LOGS_AT')
        if not schedule_time:
            return   # developer didn't set it — skip, they'll use cron

        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from django.core.management import call_command

            hour, minute = schedule_time.split(':')

            scheduler = BackgroundScheduler()
            scheduler.add_job(
                lambda: call_command('analyse_logs'),
                'cron',
                hour=int(hour),
                minute=int(minute)
            )
            scheduler.start()

        except ImportError:
            pass  # apscheduler not installed — silently skip