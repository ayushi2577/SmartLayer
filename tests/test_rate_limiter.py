from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth.models import User
from smartlayer.middleware.Rate_Limiter import RateLimiter
from django.core.cache import cache
from smartlayer.models import UserRequestCount


def make_response(status_code=200):
    return type('R', (), {'status_code': status_code})()

class TestRateLimiter(TestCase):

    def setUp(self):
        cache.clear()                  
        self.factory    = RequestFactory()
        self.middleware = RateLimiter(get_response=lambda r: make_response(200))
        self.user       = User.objects.create_user(username='testuser', password='test')
        self.user.plan  = 'free'

    def tearDown(self):
        cache.clear()                  

    def _make_request(self, path='/', user=None):
        request      = self.factory.get(path)
        request.user = user or self.user
        return request

    def test_unauthenticated_user_passes_through(self):
        from django.contrib.auth.models import AnonymousUser
        request      = self.factory.get('/')
        request.user = AnonymousUser()
        response     = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_no_config_passes_through(self):
        with override_settings(SMART_MIDDLEWARE={}):
            middleware = RateLimiter(get_response=lambda r: make_response(200))
            request    = self._make_request()
            response   = middleware(request)
            self.assertEqual(response.status_code, 200)

    def test_path_not_rate_limited_passes_through(self):
        request  = self._make_request(path='/some/other/path/')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_plan_not_in_config_passes_through(self):
        self.user.plan = 'enterprise'  # not in config
        request        = self._make_request()
        response       = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_per_minute_limit_enforced(self):
        request = self._make_request(path='/api/generate/')
        # first 2 requests should pass (free plan limit is 2 per minute)
        for _ in range(2):
            response = self.middleware(request)
            self.assertEqual(response.status_code, 200)
        # 3rd request should be blocked
        response = self.middleware(request)
        self.assertEqual(response.status_code, 429)

    def test_per_day_limit_enforced(self):
        with override_settings(SMART_MIDDLEWARE={
            'PLAN_FIELD': 'plan',
            'RATE_LIMIT_PLANS': {
                'free': {
                    '/api/generate/': {
                        'per_day': 2,
                    },
                },
            },
        }):
            middleware = RateLimiter(get_response=lambda r: make_response(200))
            request    = self._make_request(path='/api/generate/')
            for _ in range(2):
                response = middleware(request)
                self.assertEqual(response.status_code, 200)
            response = middleware(request)
            self.assertEqual(response.status_code, 429)

    def test_lifetime_limit_enforced(self):
        with override_settings(SMART_MIDDLEWARE={
            'PLAN_FIELD': 'plan',
            'RATE_LIMIT_PLANS': {
                'free': {
                    '/api/generate/': {
                        'lifetime': 2,
                    },
                },
            },
        }):
            middleware = RateLimiter(get_response=lambda r: make_response(200))
            request    = self._make_request(path='/api/generate/')
            for _ in range(2):
                response = middleware(request)
                self.assertEqual(response.status_code, 200)
            response = middleware(request)
            self.assertEqual(response.status_code, 429)

    def test_premium_plan_has_higher_limits(self):
        self.user.plan = 'premium'
        request        = self._make_request(path='/api/generate/')
        # premium is 50 per minute — first 50 should all pass
        for _ in range(10):  # just test 10 to keep test fast
            response = self.middleware(request)
            self.assertEqual(response.status_code, 200)

    def test_different_users_have_independent_counters(self):
        user2       = User.objects.create_user(username='user2', password='test')
        user2.plan  = 'free'

        request1 = self._make_request(path='/api/generate/', user=self.user)
        request2 = self._make_request(path='/api/generate/', user=user2)

        # use up user1's limit
        for _ in range(2):
            self.middleware(request1)

        # user1 should be blocked
        response1 = self.middleware(request1)
        self.assertEqual(response1.status_code, 429)

        # user2 should still pass
        response2 = self.middleware(request2)
        self.assertEqual(response2.status_code, 200)

    def test_per_hour_limit_enforced(self):
        with override_settings(SMART_MIDDLEWARE={
            'PLAN_FIELD': 'plan',
            'RATE_LIMIT_PLANS': {
                'free': {
                    '/api/generate/': {
                        'per_hour': 2,
                    },
                },
            },
        }):
            middleware = RateLimiter(get_response=lambda r: make_response(200))
            request = self._make_request(path='/api/generate/')
            for _ in range(2):
                response = middleware(request)
                self.assertEqual(response.status_code, 200)
            response = middleware(request)
            self.assertEqual(response.status_code, 429)

    def test_prefix_path_matching(self):
        """A config entry for '/api/' should also match '/api/generate/'."""
        with override_settings(SMART_MIDDLEWARE={
            'PLAN_FIELD': 'plan',
            'RATE_LIMIT_PLANS': {
                'free': {
                    '/api/': {
                        'per_minute': 1,
                    },
                },
            },
        }):
            middleware = RateLimiter(get_response=lambda r: make_response(200))
            request = self._make_request(path='/api/generate/')
            response = middleware(request)
            self.assertEqual(response.status_code, 200)
            # 2nd request should be blocked — prefix limit applies
            response = middleware(request)
            self.assertEqual(response.status_code, 429)

    def test_lifetime_checked_before_per_day(self):
        """lifetime block should trigger before per_day is even incremented."""
        with override_settings(SMART_MIDDLEWARE={
            'PLAN_FIELD': 'plan',
            'RATE_LIMIT_PLANS': {
                'free': {
                    '/api/generate/': {
                        'lifetime': 1,
                        'per_day': 100,
                    },
                },
            },
        }):
            middleware = RateLimiter(get_response=lambda r: make_response(200))
            request = self._make_request(path='/api/generate/')
            middleware(request)          # uses up lifetime=1
            response = middleware(request)
            self.assertEqual(response.status_code, 429)
            self.assertIn('Lifetime', response.content.decode())

    def test_was_blocked_flag_set_on_429(self):
        """Blocked requests must have request._was_blocked = True."""
        request = self._make_request(path='/api/generate/')
        for _ in range(2):
            self.middleware(request)
        self.middleware(request)  # this is the blocked one
        self.assertTrue(getattr(request, '_was_blocked', False))

    def test_custom_plan_field(self):
        """PLAN_FIELD setting should support non-default attribute names."""
        self.user.subscription = 'free'
        with override_settings(SMART_MIDDLEWARE={
            'PLAN_FIELD': 'subscription',
            'RATE_LIMIT_PLANS': {
                'free': {
                    '/api/generate/': {
                        'per_minute': 1,
                    },
                },
            },
        }):
            middleware = RateLimiter(get_response=lambda r: make_response(200))
            request = self._make_request(path='/api/generate/')
            response = middleware(request)
            self.assertEqual(response.status_code, 200)
            response = middleware(request)
            self.assertEqual(response.status_code, 429)

    def test_lifetime_counter_increments_in_db(self):
        """UserRequestCount.lifetime_count should go up on each allowed request."""
        with override_settings(SMART_MIDDLEWARE={
            'PLAN_FIELD': 'plan',
            'RATE_LIMIT_PLANS': {
                'free': {
                    '/api/generate/': {
                        'lifetime': 10,
                    },
                },
            },
        }):
            middleware = RateLimiter(get_response=lambda r: make_response(200))
            request = self._make_request(path='/api/generate/')
            for _ in range(3):
                middleware(request)
            record = UserRequestCount.objects.get(
                user=self.user, path='/api/generate/', plan_field='free'
            )
            self.assertEqual(record.lifetime_count, 3)