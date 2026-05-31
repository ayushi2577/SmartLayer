import httpx

def call_groq(prompt: str, config: dict, max_tokens: int = 5, temperature: float = 0.0):
    response = httpx.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {config.get('GROQ_API_KEY')}"},
        json={
            "model": "llama3-8b-8192",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        },
        timeout=10.0
    )
    return response.json()["choices"][0]["message"]["content"].strip()

def ask_ai(body: str, config: dict,VALIDATION_PROMPT) -> int:
    """For AIRequestValidator — returns confidence score 0-100"""
    prompt = VALIDATION_PROMPT.format(body=body[:500])
    result = call_groq(prompt, config, max_tokens=5, temperature=0.0)
    return int(result)

def ask_ai_text(prompt: str, config: dict) -> str:
    """For AILogAnalyser — returns plain English text"""
    result = call_groq(prompt, config, max_tokens=500, temperature=0.7)
    return result