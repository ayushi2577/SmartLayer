from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth.models import User
from smartlayer.middleware.Rate_Limiter import RateLimiter


def make_response(status_code=200):
    return type('R', (), {'status_code': status_code})()


class TestRateLimiter(TestCase):

    def setUp(self):
        self.factory    = RequestFactory()
        self.middleware = RateLimiter(get_response=lambda r: make_response(200))
        self.user       = User.objects.create_user(username='testuser', password='test', )
        # add plan field to user
        self.user.plan  = 'free'

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