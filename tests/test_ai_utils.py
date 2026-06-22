"""
Tests for smartlayer/utils.py — the AI-calling helpers.

These cover call_ai (the raw HTTP layer) and the three thin wrappers
around it: ask_ai_score, ask_ai_text, ask_ai_verdict.

httpx.post is mocked at the module level (smartlayer.utils.httpx.post)
so we exercise the real parsing/fallback logic in utils.py without
making a network call. This is one level deeper than test_request_validator.py
and test_anomaly_detector.py, which mock ask_ai_score/ask_ai_verdict directly —
here those functions themselves are the thing under test.
"""
from unittest.mock import patch, MagicMock

from django.test import TestCase

from smartlayer.utils import call_ai, ask_ai_score, ask_ai_text, ask_ai_verdict


VALID_CONFIG = {
    'AI_API_KEY': 'test-key',
    'AI_BASE_URL': 'https://api.groq.com/openai/v1',
    'AI_MODEL': 'llama3-8b-8192',
}


def make_response(content: str, status_code: int = 200):
    """Builds a fake httpx.Response-like object carrying `content` as the
    model's message text."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    mock_response.raise_for_status = MagicMock()
    return mock_response


class TestCallAi(TestCase):
    """call_ai is the shared HTTP layer every AI middleware goes through."""

    def test_missing_api_key_raises_value_error(self):
        config = {'AI_BASE_URL': 'https://api.groq.com/openai/v1', 'AI_MODEL': 'llama3-8b-8192'}
        with self.assertRaises(ValueError):
            call_ai('hello', config)

    def test_missing_base_url_raises_value_error(self):
        config = {'AI_API_KEY': 'key', 'AI_MODEL': 'llama3-8b-8192'}
        with self.assertRaises(ValueError):
            call_ai('hello', config)

    def test_missing_model_raises_value_error(self):
        config = {'AI_API_KEY': 'key', 'AI_BASE_URL': 'https://api.groq.com/openai/v1'}
        with self.assertRaises(ValueError):
            call_ai('hello', config)

    def test_empty_config_raises_value_error(self):
        with self.assertRaises(ValueError):
            call_ai('hello', {})

    @patch('smartlayer.utils.httpx.post')
    def test_strips_whitespace_from_response(self, mock_post):
        mock_post.return_value = make_response('  42  \n')
        result = call_ai('hello', VALID_CONFIG)
        self.assertEqual(result, '42')

    @patch('smartlayer.utils.httpx.post')
    def test_sends_correct_request_shape(self, mock_post):
        mock_post.return_value = make_response('ALLOW')
        call_ai('my prompt', VALID_CONFIG, max_tokens=7, temperature=0.3)

        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], 'https://api.groq.com/openai/v1/chat/completions')
        self.assertEqual(kwargs['headers']['Authorization'], 'Bearer test-key')
        self.assertEqual(kwargs['json']['model'], 'llama3-8b-8192')
        self.assertEqual(kwargs['json']['messages'], [{"role": "user", "content": "my prompt"}])
        self.assertEqual(kwargs['json']['max_tokens'], 7)
        self.assertEqual(kwargs['json']['temperature'], 0.3)
        self.assertEqual(kwargs['timeout'], 10.0)

    @patch('smartlayer.utils.httpx.post')
    def test_http_error_propagates(self, mock_post):
        """If the AI backend returns 4xx/5xx, raise_for_status should raise
        and call_ai must propagate it — callers (ask_ai_*) are responsible
        for catching this, not call_ai itself."""
        mock_response = make_response('', status_code=500)
        mock_response.raise_for_status.side_effect = Exception("server error")
        mock_post.return_value = mock_response

        with self.assertRaises(Exception):
            call_ai('hello', VALID_CONFIG)


class TestAskAiScore(TestCase):
    """ask_ai_score — used by AIRequestValidator. Must always return an int,
    even when the AI responds with garbage, since the caller compares it
    against a numeric threshold (> 85)."""

    @patch('smartlayer.utils.call_ai')
    def test_clean_numeric_response_parsed(self, mock_call_ai):
        mock_call_ai.return_value = '92'
        score = ask_ai_score('some body', VALID_CONFIG, '{body}')
        self.assertEqual(score, 92)

    @patch('smartlayer.utils.call_ai')
    def test_zero_response_parsed(self, mock_call_ai):
        mock_call_ai.return_value = '0'
        score = ask_ai_score('safe body', VALID_CONFIG, '{body}')
        self.assertEqual(score, 0)

    @patch('smartlayer.utils.call_ai')
    def test_non_numeric_response_defaults_to_zero(self, mock_call_ai):
        """AI says something like 'I cannot determine this' instead of a number."""
        mock_call_ai.return_value = 'I cannot determine this'
        score = ask_ai_score('some body', VALID_CONFIG, '{body}')
        self.assertEqual(score, 0)

    @patch('smartlayer.utils.call_ai')
    def test_response_with_explanation_defaults_to_zero(self, mock_call_ai):
        """AI ignores the 'reply with ONLY a number' instruction and explains itself."""
        mock_call_ai.return_value = 'Score: 90 - this looks malicious'
        score = ask_ai_score('some body', VALID_CONFIG, '{body}')
        self.assertEqual(score, 0)

    @patch('smartlayer.utils.call_ai')
    def test_empty_response_defaults_to_zero(self, mock_call_ai):
        mock_call_ai.return_value = ''
        score = ask_ai_score('some body', VALID_CONFIG, '{body}')
        self.assertEqual(score, 0)

    @patch('smartlayer.utils.call_ai')
    def test_float_string_response_defaults_to_zero(self, mock_call_ai):
        """int('92.5') raises ValueError — this must fail safe, not crash."""
        mock_call_ai.return_value = '92.5'
        score = ask_ai_score('some body', VALID_CONFIG, '{body}')
        self.assertEqual(score, 0)

    @patch('smartlayer.utils.call_ai')
    def test_negative_number_response_parsed(self, mock_call_ai):
        """int() happily parses '-5'; document the real (odd) behaviour rather
        than assume it's been special-cased."""
        mock_call_ai.return_value = '-5'
        score = ask_ai_score('some body', VALID_CONFIG, '{body}')
        self.assertEqual(score, -5)

    @patch('smartlayer.utils.call_ai')
    def test_out_of_range_number_is_not_clamped(self, mock_call_ai):
        """AI is asked for 0-100 but nothing in the code enforces that range —
        a hallucinated 9999 is parsed as-is. Documents current behaviour;
        callers comparing > 85 would still treat this as malicious, which
        happens to be safe, but it's worth knowing this isn't validated."""
        mock_call_ai.return_value = '9999'
        score = ask_ai_score('some body', VALID_CONFIG, '{body}')
        self.assertEqual(score, 9999)

    @patch('smartlayer.utils.call_ai')
    def test_body_is_truncated_to_500_chars_before_formatting(self, mock_call_ai):
        mock_call_ai.return_value = '0'
        long_body = 'a' * 1000
        ask_ai_score(long_body, VALID_CONFIG, 'PROMPT: {body}')

        sent_prompt = mock_call_ai.call_args[0][0]
        # 'PROMPT: ' (8 chars) + 500 a's
        self.assertEqual(len(sent_prompt), 8 + 500)


class TestAskAiText(TestCase):
    """ask_ai_text — used by analyse_logs. Just a pass-through, but confirm
    it requests a larger token budget and higher temperature than the
    scoring helpers (since it produces prose, not a single token)."""

    @patch('smartlayer.utils.call_ai')
    def test_returns_call_ai_result_unmodified(self, mock_call_ai):
        mock_call_ai.return_value = 'Everything looks healthy today.'
        result = ask_ai_text('summarise this', VALID_CONFIG)
        self.assertEqual(result, 'Everything looks healthy today.')

    @patch('smartlayer.utils.call_ai')
    def test_uses_higher_token_and_temperature_budget(self, mock_call_ai):
        mock_call_ai.return_value = 'report text'
        ask_ai_text('summarise this', VALID_CONFIG)

        _, kwargs = mock_call_ai.call_args
        self.assertEqual(kwargs.get('max_tokens'), 500)
        self.assertEqual(kwargs.get('temperature'), 0.7)


class TestAskAiVerdict(TestCase):
    """ask_ai_verdict — used by AIAnomalyDetector. This is the highest-stakes
    parser in the codebase: a malformed response here must never result in
    an unbounded or wrong ban duration."""

    PAYLOAD = {'user_agent': 'curl/8.0', 'is_authenticated': False}

    @patch('smartlayer.utils.call_ai')
    def test_allow_verdict(self, mock_call_ai):
        mock_call_ai.return_value = 'ALLOW'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'ALLOW', 'ban_hours': None})

    @patch('smartlayer.utils.call_ai')
    def test_allow_verdict_lowercase(self, mock_call_ai):
        """Response is uppercased before comparison — lowercase 'allow' must
        still be treated as ALLOW, not fall through to BLOCK."""
        mock_call_ai.return_value = 'allow'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'ALLOW', 'ban_hours': None})

    @patch('smartlayer.utils.call_ai')
    def test_block_with_valid_hours(self, mock_call_ai):
        mock_call_ai.return_value = 'BLOCK:24'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'BLOCK', 'ban_hours': 24})

    @patch('smartlayer.utils.call_ai')
    def test_block_with_1_hour(self, mock_call_ai):
        mock_call_ai.return_value = 'BLOCK:1'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'BLOCK', 'ban_hours': 1})

    @patch('smartlayer.utils.call_ai')
    def test_block_with_168_hours(self, mock_call_ai):
        mock_call_ai.return_value = 'BLOCK:168'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'BLOCK', 'ban_hours': 168})

    @patch('smartlayer.utils.call_ai')
    def test_block_without_colon_defaults_to_24h(self, mock_call_ai):
        """AI replies just 'BLOCK' with no duration — parts[1] doesn't exist,
        IndexError must be caught and default to 24h, not crash."""
        mock_call_ai.return_value = 'BLOCK'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'BLOCK', 'ban_hours': 24})

    @patch('smartlayer.utils.call_ai')
    def test_block_with_non_numeric_hours_defaults_to_24h(self, mock_call_ai):
        """'BLOCK:forever' — int('forever') raises ValueError, must default
        to 24h rather than propagate the exception."""
        mock_call_ai.return_value = 'BLOCK:forever'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'BLOCK', 'ban_hours': 24})

    @patch('smartlayer.utils.call_ai')
    def test_block_with_trailing_colon_defaults_to_24h(self, mock_call_ai):
        """'BLOCK:' — split gives ['BLOCK', ''], int('') raises ValueError."""
        mock_call_ai.return_value = 'BLOCK:'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'BLOCK', 'ban_hours': 24})

    @patch('smartlayer.utils.call_ai')
    def test_block_with_extra_colons_defaults_to_24h(self, mock_call_ai):
        """'BLOCK:24:extra' — parts[1] is '24', so this actually parses fine;
        documents that anything after the second colon is silently ignored."""
        mock_call_ai.return_value = 'BLOCK:24:extra'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'BLOCK', 'ban_hours': 24})

    @patch('smartlayer.utils.call_ai')
    def test_block_with_negative_hours_not_clamped(self, mock_call_ai):
        """Nothing validates that ban_hours is positive — documents current
        (unsafe) behaviour rather than assuming it's handled. A negative
        ban_hours would produce an expires_at in the past, i.e. no ban."""
        mock_call_ai.return_value = 'BLOCK:-5'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'BLOCK', 'ban_hours': -5})

    @patch('smartlayer.utils.call_ai')
    def test_unrecognised_text_treated_as_allow(self, mock_call_ai):
        """Anything not starting with 'BLOCK' falls through to ALLOW — this
        includes garbage, empty strings, or off-script chatter. Fail-open by
        design, but worth asserting explicitly since it's a security default."""
        mock_call_ai.return_value = 'I am not sure, this could go either way'
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'ALLOW', 'ban_hours': None})

    @patch('smartlayer.utils.call_ai')
    def test_empty_response_treated_as_allow(self, mock_call_ai):
        mock_call_ai.return_value = ''
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'ALLOW', 'ban_hours': None})

    @patch('smartlayer.utils.call_ai')
    def test_whitespace_padded_block_is_parsed(self, mock_call_ai):
        """call_ai already strips whitespace, but verify ask_ai_verdict
        doesn't re-introduce a leading/trailing space bug via .upper()."""
        mock_call_ai.return_value = '  block:24  '.strip()
        result = ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)
        self.assertEqual(result, {'verdict': 'BLOCK', 'ban_hours': 24})

    @patch('smartlayer.utils.call_ai')
    def test_payload_is_json_encoded_into_prompt(self, mock_call_ai):
        """Confirm the payload dict actually reaches the prompt sent to the
        AI — a regression here would silently send an empty/wrong payload."""
        mock_call_ai.return_value = 'ALLOW'
        ask_ai_verdict(self.PAYLOAD, VALID_CONFIG)

        sent_prompt = mock_call_ai.call_args[0][0]
        self.assertIn('curl/8.0', sent_prompt)
        self.assertIn('is_authenticated', sent_prompt)


class TestAiCallFailureHandling(TestCase):
    """All three ask_ai_* wrappers call call_ai, which can raise (network
    error, missing config, HTTP error). None of the wrappers catch this
    themselves — by design, that's left to the middleware call sites
    (see AIRequestValidator/AIAnomalyDetector, which wrap calls in
    try/except). These tests document and lock in that contract so a
    future change doesn't silently start swallowing errors at the wrong
    layer (or stop swallowing them at the right one)."""

    @patch('smartlayer.utils.call_ai')
    def test_ask_ai_score_propagates_call_ai_exception(self, mock_call_ai):
        mock_call_ai.side_effect = Exception("network error")
        with self.assertRaises(Exception):
            ask_ai_score('body', VALID_CONFIG, '{body}')

    @patch('smartlayer.utils.call_ai')
    def test_ask_ai_text_propagates_call_ai_exception(self, mock_call_ai):
        mock_call_ai.side_effect = Exception("network error")
        with self.assertRaises(Exception):
            ask_ai_text('prompt', VALID_CONFIG)

    @patch('smartlayer.utils.call_ai')
    def test_ask_ai_verdict_propagates_call_ai_exception(self, mock_call_ai):
        mock_call_ai.side_effect = Exception("network error")
        with self.assertRaises(Exception):
            ask_ai_verdict({'user_agent': 'x'}, VALID_CONFIG)

    @patch('smartlayer.utils.httpx.post')
    def test_call_ai_propagates_value_error_for_missing_config_even_with_mocked_http(self, mock_post):
        """Sanity check: the config validation in call_ai happens before any
        HTTP call is attempted, so this must raise without touching the
        mocked transport at all."""
        with self.assertRaises(ValueError):
            call_ai('prompt', {})
        mock_post.assert_not_called()