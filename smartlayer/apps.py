from django.apps import AppConfig


class SmartLayerConfig(AppConfig):
    name = 'smartlayer'                                     # ← fixed

    def ready(self):
        from django.conf import settings
        config = getattr(settings, 'SMART_MIDDLEWARE', {})

        schedule_time = config.get('ANALYSE_LOGS_AT')
        if not schedule_time:
            return

        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from django.core.management import call_command

            hour, minute = schedule_time.split(':')

            scheduler = BackgroundScheduler()
            scheduler.add_job(
                lambda: call_command('analyse_logs'),
                'cron',
                hour=int(hour),
                minute=int(minute),
                id='smartlayer_analyse_logs',
                replace_existing=True
            )
            scheduler.start()

        except ImportError:
            import warnings
            warnings.warn(                                  # ← added warning
                "[Smart Layer] ANALYSE_LOGS_AT is set but apscheduler is not installed. "
                "Run: pip install apscheduler  "
                "Or remove ANALYSE_LOGS_AT and use cron instead.",
                RuntimeWarning
            )