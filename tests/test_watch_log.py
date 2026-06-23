from django.test import TestCase, RequestFactory
from django.contrib.auth.models import AnonymousUser, User
from smartlayer.middleware.watch_log import WatchLog
from smartlayer.models import RequestLog


def make_response(status_code=200):
    return type('R', (), {'status_code': status_code})()


class TestWatchLog(TestCase):

    def setUp(self):
        self.factory    = RequestFactory()
        self.middleware = WatchLog(get_response=lambda r: make_response(200))

    def _make_request(self, path='/', ip='1.2.3.4', method='GET'):
        request = getattr(self.factory, method.lower())(path)
        request.META['REMOTE_ADDR'] = ip
        request.user = AnonymousUser()
        return request

    def _log(self, request, status_code=200, response_time_ms=50.0, was_blocked=False):
        # call _save_log directly — no threading, no transaction issues
        request._was_blocked = was_blocked
        response = make_response(status_code)
        log_data = {
            'user_id'          : request.user.id if request.user.is_authenticated else None,
            'ip_address'       : request.META.get('REMOTE_ADDR') if not request.user.is_authenticated else None,
            'method'           : request.method,
            'path'             : request.path,
            'status_code'      : response.status_code,
            'response_time_ms' : response_time_ms,
            'was_blocked'      : getattr(request, '_was_blocked', False),
        }
        self.middleware._save_log(log_data)
        return log_data

    def test_request_is_logged(self):
        request = self._make_request()
        self._log(request)
        self.assertEqual(RequestLog.objects.count(), 1)

    def test_correct_path_is_logged(self):
        request = self._make_request(path='/api/test/')
        self._log(request)
        log = RequestLog.objects.first()
        self.assertEqual(log.path, '/api/test/')

    def test_correct_method_is_logged(self):
        request = self._make_request(method='GET')
        self._log(request)
        log = RequestLog.objects.first()
        self.assertEqual(log.method, 'GET')

    def test_correct_status_code_is_logged(self):
        request = self._make_request()
        self._log(request, status_code=404)
        log = RequestLog.objects.first()
        self.assertEqual(log.status_code, 404)

    def test_response_time_is_recorded(self):
        request = self._make_request()
        self._log(request, response_time_ms=143.5)
        log = RequestLog.objects.first()
        self.assertGreater(log.response_time_ms, 0)
        self.assertEqual(log.response_time_ms, 143.5)

    def test_anonymous_user_logs_ip_not_user_id(self):
        request = self._make_request(ip='5.5.5.5')
        self._log(request)
        log = RequestLog.objects.first()
        self.assertIsNone(log.user_id)
        self.assertEqual(log.ip_address, '5.5.5.5')

    def test_authenticated_user_logs_user_id_not_ip(self):
        user         = User.objects.create_user(username='testuser', password='test')
        request      = self._make_request()
        request.user = user
        self._log(request)
        log = RequestLog.objects.first()
        self.assertEqual(log.user_id, user.id)
        self.assertIsNone(log.ip_address)

    def test_blocked_request_is_flagged(self):
        request = self._make_request()
        self._log(request, was_blocked=True)
        log = RequestLog.objects.first()
        self.assertTrue(log.was_blocked)

    def test_normal_request_not_flagged_as_blocked(self):
        request = self._make_request()
        self._log(request, was_blocked=False)
        log = RequestLog.objects.first()
        self.assertFalse(log.was_blocked)

    def test_multiple_requests_all_logged(self):
        for i in range(5):
            request = self._make_request(path=f'/api/endpoint{i}/')
            self._log(request)
        self.assertEqual(RequestLog.objects.count(), 5)
    
    def test_save_log_never_crashes_app(self):
        from unittest.mock import patch
        with patch('smartlayer.models.RequestLog.objects') as mock_objects:
            mock_objects.create.side_effect = Exception('DB is down')
            try:
                self.middleware._save_log({'method': 'GET', 'path': '/'})
            except Exception:
                self.fail('_save_log should never raise exceptions')