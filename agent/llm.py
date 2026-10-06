"""Talk to the local model through Ollama. Every answer is JSON that matches a schema."""
import json
import os
import sys
import urllib.request
from collections import Counter

HOST = "http://localhost:11434"
MODEL = "qwen2.5-coder:7b"
CHARS_PER_TOKEN = 3.3

SEED_OFFSET = int(os.environ.get("AGENT_SEED", "0"))
TEMP_OVERRIDE = os.environ.get("AGENT_TEMP")


class LLMError(Exception):
    pass


def check_ollama():
    try:
        with urllib.request.urlopen(f"{HOST}/api/tags", timeout=5) as resp:
            installed = [m["name"] for m in json.loads(resp.read()).get("models", [])]
    except OSError:
        sys.exit(f"Cannot reach Ollama at {HOST}. Start it with `ollama serve`.")
    if MODEL not in installed:
        sys.exit(f"Model {MODEL} is not installed. Run: ollama pull {MODEL}")


def code_budget(num_ctx, answer_tokens, system):
    """How many characters of code fit next to the system prompt and the answer."""
    return int((num_ctx - answer_tokens) * CHARS_PER_TOKEN) - len(system)


def ask(system, prompt, schema, num_ctx, max_tokens=None, seed=0, temperature=0.0):
    if TEMP_OVERRIDE is not None and temperature == 0.0:
        temperature = float(TEMP_OVERRIDE)
    options = {"temperature": temperature, "num_ctx": num_ctx, "seed": seed + SEED_OFFSET}
    if max_tokens:
        options["num_predict"] = max_tokens
    body = {"model": MODEL, "format": schema, "stream": False, "options": options,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}
    req = urllib.request.Request(f"{HOST}/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=900) as resp:
            content = json.loads(resp.read())["message"]["content"]
        return json.loads(content)
    except (OSError, KeyError, json.JSONDecodeError) as e:
        raise LLMError(str(e))


def vote(system, prompt, schema, votes, num_ctx):
    """Ask several times with different seeds. Returns (verdict, agreement, answer, all verdicts)."""
    temperature = 0.0 if votes == 1 else 0.6
    answers = []
    for seed in range(votes):
        try:
            answers.append(ask(system, prompt, schema, num_ctx, seed=seed, temperature=temperature))
        except LLMError as e:
            answers.append({"verdict": "uncertain", "reason": str(e)})
    verdicts = [a["verdict"] for a in answers]
    counts = Counter(verdicts).most_common()
    verdict = "uncertain" if len(counts) > 1 and counts[0][1] == counts[1][1] else counts[0][0]
    chosen = next((a for a in answers if a["verdict"] == verdict), answers[0])
    return verdict, counts[0][1] / votes, chosen, verdicts
