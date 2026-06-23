from django.test import TestCase, RequestFactory
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import AnonymousUser, User
from smartlayer.middleware.ai_anomaly_detector import AIAnomalyDetector
from smartlayer.models import BannedUser, RequestLog


# ======================================================================
#  HELPERS
# ======================================================================

def make_middleware():
    return AIAnomalyDetector(get_response=lambda r: type('R', (), {'status_code': 200})())


# ======================================================================
#  BAN CHECK — tests for __call__ (main thread only)
# ======================================================================

class TestBanCheck(TestCase):

    def setUp(self):
        self.factory    = RequestFactory()
        self.middleware = make_middleware()

    def _make_request(self, path='/', ip='9.9.9.9'):
        request = self.factory.get(path)
        request.META['REMOTE_ADDR'] = ip
        request.user = AnonymousUser()
        return request

    def test_banned_ip_gets_403(self):
        BannedUser.objects.create(
            ip_address='1.2.3.4',
            reason='test',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        request  = self._make_request(ip='1.2.3.4')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_expired_ban_does_not_block(self):
        BannedUser.objects.create(
            ip_address='1.2.3.4',
            reason='test',
            expires_at=timezone.now() - timedelta(hours=1)  # already expired
        )
        request  = self._make_request(ip='1.2.3.4')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_clean_ip_gets_through(self):
        request  = self._make_request(ip='9.9.9.9')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_banned_user_id_gets_403(self):
        user = User.objects.create_user(username='baduser', password='test')
        BannedUser.objects.create(
            user_id=user.id,
            reason='test',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        request      = self._make_request()
        request.user = user
        response     = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_different_ip_not_affected_by_ban(self):
        BannedUser.objects.create(
            ip_address='1.2.3.4',
            reason='test',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        request  = self._make_request(ip='5.5.5.5')  # different IP
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_whitelisted_ip_always_gets_through(self):
        # even if banned, whitelist takes precedence
        from django.test import override_settings
        with override_settings(SMART_MIDDLEWARE={
            'WHITELIST_IPS': ['1.2.3.4'],
            'WHITELIST_PATHS': [],
        }):
            BannedUser.objects.create(
                ip_address='1.2.3.4',
                reason='test',
                expires_at=timezone.now() + timedelta(hours=24)
            )
            request  = self._make_request(ip='1.2.3.4')
            response = self.middleware(request)
            self.assertEqual(response.status_code, 200)

    def test_whitelisted_path_skips_analysis(self):
        from django.test import override_settings
        with override_settings(SMART_MIDDLEWARE={
            'WHITELIST_IPS': [],
            'WHITELIST_PATHS': ['/health/'],
        }):
            request  = self._make_request(path='/health/')
            response = self.middleware(request)
            self.assertEqual(response.status_code, 200)


# ======================================================================
#  BLACK CHECK — tests for _black_check directly
# ======================================================================

class TestBlackCheck(TestCase):

    def setUp(self):
        self.middleware = make_middleware()

    def _make_snapshot(self, ua='Mozilla/5.0', ip='1.2.3.4', path='/', is_auth=False):
        return {
            'user_id' : None,
            'ip'      : ip,
            'path'    : path,
            'ua'      : ua,
            'is_auth' : is_auth,
            'now'     : timezone.now(),
        }

    def _make_behavior(self, count_10s=0, total_2min=0, error_rate=0, error_count=0,
                       recent_paths=None, distinct_paths=0, was_idle=False):
        return {
            'count_10s'     : count_10s,
            'total_2min'    : total_2min,
            'error_rate'    : error_rate,
            'error_count'   : error_count,
            'recent_paths'  : recent_paths or [],
            'distinct_paths': distinct_paths,
            'was_idle'      : was_idle,
        }

    def test_empty_user_agent_triggers_ban(self):
        snapshot = self._make_snapshot(ua='')
        behavior = self._make_behavior()
        banned   = self.middleware._black_check(snapshot, behavior)
        self.assertTrue(banned)
        self.assertTrue(BannedUser.objects.filter(ip_address='1.2.3.4').exists())

    def test_normal_user_agent_not_banned(self):
        snapshot = self._make_snapshot(ua='Mozilla/5.0')
        behavior = self._make_behavior()
        banned   = self.middleware._black_check(snapshot, behavior)
        self.assertFalse(banned)

    def test_burst_50_requests_triggers_ban(self):
        snapshot = self._make_snapshot()
        behavior = self._make_behavior(count_10s=50)
        banned   = self.middleware._black_check(snapshot, behavior)
        self.assertTrue(banned)

    def test_burst_49_requests_not_banned(self):
        snapshot = self._make_snapshot()
        behavior = self._make_behavior(count_10s=49)
        banned   = self.middleware._black_check(snapshot, behavior)
        self.assertFalse(banned)

    def test_high_error_rate_triggers_ban(self):
        snapshot = self._make_snapshot()
        behavior = self._make_behavior(total_2min=10, error_rate=75, error_count=8)
        banned   = self.middleware._black_check(snapshot, behavior)
        self.assertTrue(banned)

    def test_error_rate_below_threshold_not_banned(self):
        snapshot = self._make_snapshot()
        behavior = self._make_behavior(total_2min=10, error_rate=74, error_count=7)
        banned   = self.middleware._black_check(snapshot, behavior)
        self.assertFalse(banned)

    def test_high_error_rate_needs_min_10_requests(self):
        # 9 requests even at 100% error rate should not trigger
        snapshot = self._make_snapshot()
        behavior = self._make_behavior(total_2min=9, error_rate=100, error_count=9)
        banned   = self.middleware._black_check(snapshot, behavior)
        self.assertFalse(banned)


# ======================================================================
#  SCORING — tests for _score directly
# ======================================================================

class TestScoring(TestCase):

    def setUp(self):
        self.middleware = make_middleware()

    def _make_snapshot(self, ua='Mozilla/5.0', path='/', is_auth=False):
        return {
            'user_id' : None,
            'ip'      : '1.2.3.4',
            'path'    : path,
            'ua'      : ua,
            'is_auth' : is_auth,
            'now'     : timezone.now(),
        }

    def _make_behavior(self, count_10s=0, total_2min=0, error_rate=0,
                       recent_paths=None, distinct_paths=0, was_idle=False):
        return {
            'count_10s'     : count_10s,
            'total_2min'    : total_2min,
            'error_rate'    : error_rate,
            'error_count'   : 0,
            'recent_paths'  : recent_paths or [],
            'distinct_paths': distinct_paths,
            'was_idle'      : was_idle,
        }

    def test_clean_behavior_scores_zero(self):
        snapshot = self._make_snapshot(is_auth=True)  # authenticated = no unauthenticated penalty
        behavior = self._make_behavior()
        score    = self.middleware._score(snapshot, behavior)
        self.assertEqual(score, 0)

    def test_suspicious_ua_adds_score(self):
        snapshot = self._make_snapshot(ua='python-requests/2.28')
        behavior = self._make_behavior()
        score    = self.middleware._score(snapshot, behavior)
        self.assertGreaterEqual(score, 2)

    def test_elevated_rate_adds_score(self):
        snapshot = self._make_snapshot()
        behavior = self._make_behavior(count_10s=25)
        score    = self.middleware._score(snapshot, behavior)
        self.assertGreaterEqual(score, 3)

    def test_moderate_error_rate_adds_score(self):
        snapshot = self._make_snapshot()
        behavior = self._make_behavior(total_2min=10, error_rate=50)
        score    = self.middleware._score(snapshot, behavior)
        self.assertGreaterEqual(score, 2)

    def test_sensitive_path_unauthenticated_adds_score(self):
        # 3 hits on sensitive path
        snapshot = self._make_snapshot(path='/admin', is_auth=False)
        behavior = self._make_behavior(
            recent_paths=['/admin', '/admin', '/admin']
        )
        score = self.middleware._score(snapshot, behavior)
        self.assertGreaterEqual(score, 3)

    def test_sensitive_path_authenticated_no_score(self):
        # authenticated admin visiting /admin should not be scored
        snapshot = self._make_snapshot(path='/admin', is_auth=True)
        behavior = self._make_behavior(
            recent_paths=['/admin', '/admin', '/admin']
        )
        score = self.middleware._score(snapshot, behavior)
        self.assertEqual(score, 0)

    def test_endpoint_scanning_adds_score(self):
        paths    = [f'/api/endpoint{i}/' for i in range(26)]  # 26 distinct paths
        snapshot = self._make_snapshot()
        behavior = self._make_behavior(recent_paths=paths, distinct_paths=26)
        score    = self.middleware._score(snapshot, behavior)
        self.assertGreaterEqual(score, 2)

    def test_unauthenticated_adds_score(self):
        snapshot = self._make_snapshot(is_auth=False)
        behavior = self._make_behavior()
        score    = self.middleware._score(snapshot, behavior)
        self.assertEqual(score, 1)  # W_UNAUTHENTICATED = 1

    def test_authenticated_user_no_unauth_score(self):
        snapshot = self._make_snapshot(is_auth=True)
        behavior = self._make_behavior()
        score    = self.middleware._score(snapshot, behavior)
        self.assertEqual(score, 0)


# ======================================================================
#  SEQUENTIAL PROBING — tests for _is_sequential_probing directly
# ======================================================================

class TestSequentialProbing(TestCase):

    def setUp(self):
        self.middleware = make_middleware()

    def test_sequential_ids_detected(self):
        paths  = ['/users/1', '/users/2', '/users/3', '/users/4', '/users/5']
        result = self.middleware._is_sequential_probing(paths)
        self.assertTrue(result)

    def test_random_ids_not_detected(self):
        paths  = ['/products/4', '/products/89', '/products/247', '/products/3', '/products/901']
        result = self.middleware._is_sequential_probing(paths)
        self.assertFalse(result)

    def test_not_enough_paths(self):
        paths  = ['/users/1', '/users/2', '/users/3']  # only 3, threshold is 5
        result = self.middleware._is_sequential_probing(paths)
        self.assertFalse(result)

    def test_scattered_pairs_not_detected(self):
        # 1,2 and 5,6 are pairs but no single run of 5
        paths  = ['/users/1', '/users/2', '/users/5', '/users/6', '/users/10']
        result = self.middleware._is_sequential_probing(paths)
        self.assertFalse(result)

    def test_paths_without_ids_not_detected(self):
        paths  = ['/home', '/about', '/contact', '/blog', '/login']
        result = self.middleware._is_sequential_probing(paths)
        self.assertFalse(result)

    def test_mixed_paths_with_sequential_ids_detected(self):
        # mix of paths but sequential IDs present
        paths = ['/users/10', '/users/11', '/users/12', '/users/13', '/users/14']
        result = self.middleware._is_sequential_probing(paths)
        self.assertTrue(result)


# ======================================================================
#  BAN HELPER — tests for _ban directly
# ======================================================================

class TestBanHelper(TestCase):

    def setUp(self):
        self.middleware = make_middleware()

    def test_ban_writes_to_db_by_ip(self):
        snapshot = {
            'user_id': None,
            'ip'     : '3.3.3.3',
            'path'   : '/',
            'ua'     : 'test',
            'is_auth': False,
            'now'    : timezone.now(),
        }
        self.middleware._ban(snapshot, ban_hours=24, reason='test ban')
        self.assertTrue(BannedUser.objects.filter(ip_address='3.3.3.3').exists())

    def test_ban_writes_to_db_by_user_id(self):
        snapshot = {
            'user_id': 99,
            'ip'     : '3.3.3.3',
            'path'   : '/',
            'ua'     : 'test',
            'is_auth': True,
            'now'    : timezone.now(),
        }
        self.middleware._ban(snapshot, ban_hours=24, reason='test ban')
        self.assertTrue(BannedUser.objects.filter(user_id=99).exists())

    def test_ban_expiry_is_correct(self):
        snapshot = {
            'user_id': None,
            'ip'     : '4.4.4.4',
            'path'   : '/',
            'ua'     : 'test',
            'is_auth': False,
            'now'    : timezone.now(),
        }
        before = timezone.now()
        self.middleware._ban(snapshot, ban_hours=24, reason='test')
        after  = timezone.now()

        ban = BannedUser.objects.get(ip_address='4.4.4.4')
        self.assertGreater(ban.expires_at, before + timedelta(hours=23))
        self.assertLess(ban.expires_at,    after  + timedelta(hours=25))