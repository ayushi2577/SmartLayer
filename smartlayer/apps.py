from django.apps import AppConfig
from django.core.checks import Warning, register

#if cache backend is locmem(not redis), then show warning that rate limit counters will reset on every server restart.
def check_cache_backend(app_configs, **kwargs):
    from django.core.cache import cache
    if 'locmem' in cache.__class__.__module__:
        return [Warning(
            'SmartLayer is using in-memory cache. '
            'Rate limit counters will reset on every server restart.',
            hint='Set up Redis as your Django cache backend for persistent rate limiting.',
            id='smartlayer.W001',
        )]
    return []


class SmartlayerConfig(AppConfig):
    name = 'smartlayer'

    def ready(self):
        register(check_cache_backend)  # Register the cache backend check
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
            warnings.warn(                                  # warning
                "[Smart Layer] ANALYSE_LOGS_AT is set but apscheduler is not installed. "
                "Run: pip install apscheduler  "
                "Or remove ANALYSE_LOGS_AT and use cron instead.",
                RuntimeWarning
            )
            