SECRET_KEY = 'test-secret-key-not-for-production'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME':   ':memory:',
    }
}

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'smartlayer',
]

MIDDLEWARE = []

SMART_MIDDLEWARE = {
    'AI_API_KEY':  'test-key',
    'AI_BASE_URL': 'https://api.groq.com/openai/v1',
    'AI_MODEL':    'llama3-8b-8192',
    'RATE_LIMIT_PLANS': {
        'free': {
            '/api/generate/': {
                'per_minute': 2,
                'per_day':    10,
                'lifetime':   100,
            },
        },
        'premium': {
            '/api/generate/': {
                'per_minute': 50,
                'per_day':    5000,
            },
        },
    },
    'WHITELIST_IPS':   [],
    'WHITELIST_PATHS': [],
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
USE_TZ = True