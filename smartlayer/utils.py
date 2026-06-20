import httpx

def get_client_ip(request) -> str:
    """
    Returns the real client IP, proxy-aware.
    Set TRUST_PROXY: True in SMART_MIDDLEWARE only when behind Nginx/ALB/Cloudflare.
    Never trust X-Forwarded-For without it - clients can spoof it.
    """
    from django.conf import settings
    cfg         = getattr(settings, 'SMART_MIDDLEWARE', {})
    trust_proxy = cfg.get('TRUST_PROXY', False)

    if trust_proxy:
        # Cloudflare - single trusted IP, no spoofing risk
        cf_ip = request.META.get('HTTP_CF_CONNECTING_IP')
        if cf_ip:
            return cf_ip.strip()

        # Nginx / ALB - leftmost value is original client
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            return xff.split(',')[0].strip()

    return request.META.get('REMOTE_ADDR', '')

def call_ai(prompt: str, config: dict, max_tokens: int = 5, temperature: float = 0.0) -> str:
    """
    Universal AI caller - works with any OpenAI-compatible provider.
    
    Provider URLs:
        Groq:     https://api.groq.com/openai/v1
        OpenAI:   https://api.openai.com/v1
        Gemini:   https://generativelanguage.googleapis.com/v1beta/openai
        Ollama:   http://localhost:11434/v1
    """
    api_key  = config.get('AI_API_KEY')
    base_url = config.get('AI_BASE_URL')
    model    = config.get('AI_MODEL')

    if not all([api_key, base_url, model]):
        raise ValueError("SMART_MIDDLEWARE must have AI_API_KEY, AI_BASE_URL and AI_MODEL")

    response = httpx.post(
        f"{base_url}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        },
        timeout=10.0
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"].strip()


def ask_ai_score(body: str, config: dict, validation_prompt: str) -> int:
    """For AIRequestValidator - returns confidence score 0-100"""
    prompt = validation_prompt.format(body=body[:500])
    result = call_ai(prompt, config, max_tokens=5, temperature=0.0)
    try:
        return int(result)
    except ValueError:
        return 0  # if AI returns something unexpected, treat as safe


def ask_ai_text(prompt: str, config: dict) -> str:
    """For AILogAnalyser - returns plain English text"""
    return call_ai(prompt, config, max_tokens=500, temperature=0.7)


def ask_ai_verdict(payload: dict, config: dict) -> dict:
    """
    For AIAnomalyDetector - returns {'verdict': 'BLOCK'/'ALLOW', 'ban_hours': int|None}

    Ban durations the AI can assign:
        BLOCK:1    - 1 hour   (minor violation, rate limit abuse)
        BLOCK:24   - 24 hours (suspicious pattern, likely bot)
        BLOCK:168  - 7 days   (clear attack, scanner, malicious probe)

    If AI response is malformed, defaults to 24h ban.
    """
    import json
    prompt = """
    You are a security expert. Based on this raw API behaviour data, is this user a bot or attacker?
    Data: {payload}

    Reply with ONLY one of these exact strings (no explanation, no punctuation):
    ALLOW
    BLOCK:1       (ban for 1 hour  - minor violation, rate limit abuse)
    BLOCK:24      (ban for 24 hours - suspicious pattern, likely bot)
    BLOCK:168     (ban for 7 days  - clear attack, scanner, or malicious probe)
    """.format(payload=json.dumps(payload, indent=2))

    result = call_ai(prompt, config, max_tokens=10, temperature=0.0).upper()

    if result.startswith("BLOCK"):
        parts = result.split(":")
        try:
            hours = int(parts[1]) if len(parts) > 1 else 24
        except (ValueError, IndexError):
            hours = 24
        return {"verdict": "BLOCK", "ban_hours": hours}

    return {"verdict": "ALLOW", "ban_hours": None}