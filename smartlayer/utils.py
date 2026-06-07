import httpx

def call_ai(prompt: str, config: dict, max_tokens: int = 5, temperature: float = 0.0) -> str:
    """
    Universal AI caller — works with any OpenAI-compatible provider.
    
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
    """For AIRequestValidator — returns confidence score 0-100"""
    prompt = validation_prompt.format(body=body[:500])
    result = call_ai(prompt, config, max_tokens=5, temperature=0.0)
    try:
        return int(result)
    except ValueError:
        return 0  # if AI returns something unexpected, treat as safe


def ask_ai_text(prompt: str, config: dict) -> str:
    """For AILogAnalyser — returns plain English text"""
    return call_ai(prompt, config, max_tokens=500, temperature=0.7)


def ask_ai_verdict(payload: dict, config: dict) -> str:
    """For AIAnomalyDetector — returns BLOCK or ALLOW"""
    import json
    prompt = """
    You are a security expert. Based on this raw API behaviour data, is this user a bot or attacker?
    Data: {payload}
    Reply with ONLY one word: BLOCK or ALLOW.
    """.format(payload=json.dumps(payload, indent=2))
    
    result = call_ai(prompt, config, max_tokens=5, temperature=0.0)
    return "BLOCK" if "BLOCK" in result.upper() else "ALLOW"