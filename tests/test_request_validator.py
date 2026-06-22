from unittest.mock import patch

from django.test import TestCase, RequestFactory, override_settings

from smartlayer.middleware.AIRequestValidator import AIRequestValidator


# ======================================================================
#  HELPERS
# ======================================================================

def make_middleware():
    return AIRequestValidator(get_response=lambda r: type('R', (), {'status_code': 200})())


def make_post_request(factory, body=b'{}', content_type='application/json'):
    return factory.post('/', data=body, content_type=content_type)


# ======================================================================
#  CLEAN / OBVIOUS CASES — no AI call needed
# ======================================================================

class TestNoAICallNeeded(TestCase):

    def setUp(self):
        self.factory    = RequestFactory()
        self.middleware = make_middleware()

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_clean_body_passes_through_without_calling_ai(self, mock_ai):
        request  = make_post_request(self.factory, body=b'{"name": "John", "email": "john@example.com"}')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        mock_ai.assert_not_called()

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_obvious_attack_blocked_without_calling_ai(self, mock_ai):
        # 3+ suspicious patterns -- SQL injection + shell injection + path traversal
        body     = b"' OR 1=1 -- ; rm -rf / ../../etc/passwd"
        request  = make_post_request(self.factory, body=body)
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)
        mock_ai.assert_not_called()

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_blocked_response_has_error_payload(self, mock_ai):
        body     = b"' OR 1=1 -- ; rm -rf / ../../etc/passwd"
        request  = make_post_request(self.factory, body=body)
        response = self.middleware(request)
        self.assertJSONEqual(response.content, {"error": "blocked"})


# ======================================================================
#  BORDERLINE CASES — exactly 1 or 2 patterns matched, AI gets called
# ======================================================================

class TestBorderlineCallsAI(TestCase):

    def setUp(self):
        self.factory    = RequestFactory()
        self.middleware = make_middleware()

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_borderline_score_calls_ai(self, mock_ai):
        mock_ai.return_value = 10
        # single suspicious pattern: "../" path traversal
        request  = make_post_request(self.factory, body=b'{"path": "../file.txt"}')
        response = self.middleware(request)
        mock_ai.assert_called_once()
        self.assertEqual(response.status_code, 200)

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_ai_high_confidence_blocks_request(self, mock_ai):
        mock_ai.return_value = 90
        request  = make_post_request(self.factory, body=b'{"path": "../file.txt"}')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_ai_confidence_at_threshold_not_blocked(self, mock_ai):
        # threshold is ">85", so exactly 85 should pass through
        mock_ai.return_value = 85
        request  = make_post_request(self.factory, body=b'{"path": "../file.txt"}')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_ai_confidence_just_above_threshold_blocks(self, mock_ai):
        mock_ai.return_value = 86
        request  = make_post_request(self.factory, body=b'{"path": "../file.txt"}')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_ai_low_confidence_allows_request(self, mock_ai):
        mock_ai.return_value = 5
        request  = make_post_request(self.factory, body=b'{"path": "../file.txt"}')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_ai_failure_fails_open(self, mock_ai):
        # if AI call raises for any reason, request should be let through
        mock_ai.side_effect = Exception('AI provider down')
        request  = make_post_request(self.factory, body=b'{"path": "../file.txt"}')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_ai_called_with_smart_middleware_config(self, mock_ai):
        mock_ai.return_value = 0
        custom_config = {
            'AI_API_KEY':  'custom-key',
            'AI_BASE_URL': 'https://api.groq.com/openai/v1',
            'AI_MODEL':    'llama3-8b-8192',
        }
        with override_settings(SMART_MIDDLEWARE=custom_config):
            request = make_post_request(self.factory, body=b'{"path": "../file.txt"}')
            self.middleware(request)
            args, _ = mock_ai.call_args
            self.assertEqual(args[1], custom_config)

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_two_patterns_still_borderline_calls_ai(self, mock_ai):
        mock_ai.return_value = 0
        # two patterns: "../" path traversal + "<script>" XSS
        body     = b'{"a": "../etc", "b": "<script>x</script>"}'
        request  = make_post_request(self.factory, body=body)
        response = self.middleware(request)
        mock_ai.assert_called_once()
        self.assertEqual(response.status_code, 200)


# ======================================================================
#  REQUEST SHAPE HANDLING — multipart, undecodable bodies, empty bodies
# ======================================================================

class TestRequestShapeHandling(TestCase):

    def setUp(self):
        self.factory    = RequestFactory()
        self.middleware = make_middleware()

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_multipart_request_skips_validation_entirely(self, mock_ai):
        request = self.factory.post(
            '/',
            data={'file': b"' OR 1=1 -- ; rm -rf / ../../etc/passwd"},
            format='multipart',
        )
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        mock_ai.assert_not_called()

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_undecodable_body_passes_through(self, mock_ai):
        # invalid utf-8 bytes should not be treated as a text attack
        request = self.factory.post(
            '/', data=b'\xff\xfe\x00\x01', content_type='application/octet-stream'
        )
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        mock_ai.assert_not_called()

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_empty_body_passes_through_without_ai(self, mock_ai):
        request  = make_post_request(self.factory, body=b'')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        mock_ai.assert_not_called()

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_get_request_with_no_body_passes_through(self, mock_ai):
        request  = self.factory.get('/')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        mock_ai.assert_not_called()


# ======================================================================
#  BASE64-ENCODED ATTACKS — decoded before scoring
# ======================================================================

class TestBase64Handling(TestCase):

    def setUp(self):
        self.factory    = RequestFactory()
        self.middleware = make_middleware()

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_base64_encoded_attack_is_decoded_and_blocked(self, mock_ai):
        import base64
        payload  = base64.b64encode(b"' OR 1=1 -- ; rm -rf / ../../etc/passwd").decode()
        request  = make_post_request(self.factory, body=payload.encode(), content_type='text/plain')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)
        mock_ai.assert_not_called()

    @patch('smartlayer.middleware.AIRequestValidator.ask_ai_score')
    def test_base64_encoded_clean_text_passes(self, mock_ai):
        import base64
        payload  = base64.b64encode(b"hello world, nothing suspicious here at all").decode()
        request  = make_post_request(self.factory, body=payload.encode(), content_type='text/plain')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        mock_ai.assert_not_called()