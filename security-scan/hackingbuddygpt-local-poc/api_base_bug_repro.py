"""Reproduces (twice each, plus a negative control) the dead `api_base` config bug
described in ../hackingbuddygpt-local-backend-notes.md. Requires the mock LLM server
from this directory running on port 8900.

Usage:
    python3 mock_llm_server.py 8900 &
    python3 api_base_bug_repro.py /path/to/hackingbuddygpt/src
"""
import os
import sys

sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else ".")
from hackingBuddyGPT.utils.llm import LiteLLM


def attempt(label, api_base, env_openai_base):
    # isolate env between attempts
    for k in ("OPENAI_API_BASE", "OPENAI_BASE_URL"):
        os.environ.pop(k, None)
    if env_openai_base:
        os.environ["OPENAI_API_BASE"] = env_openai_base

    llm = LiteLLM(api_key="dummy-mock-key", model="openai/mock-model", context_size=8000, api_base=api_base)
    llm.init()
    try:
        result = llm.get_response("ping")
        print(f"[{label}] SUCCESS -> {result.answer!r}")
    except Exception as e:
        print(f"[{label}] FAILED -> {type(e).__name__}: {str(e)[:120]}")


print("=== Run B (x2): api_base=mock, no OPENAI_API_BASE env -> expect FAILED (dead config) ===")
attempt("B-run1", "http://127.0.0.1:8900/v1", None)
attempt("B-run2", "http://127.0.0.1:8900/v1", None)

print()
print("=== Run C (x2): api_base=mock AND OPENAI_API_BASE=mock -> expect SUCCESS (env workaround) ===")
attempt("C-run1", "http://127.0.0.1:8900/v1", "http://127.0.0.1:8900/v1")
attempt("C-run2", "http://127.0.0.1:8900/v1", "http://127.0.0.1:8900/v1")

print()
print("=== Run D (negative control): api_base=mock, OPENAI_API_BASE=unreachable -> expect FAILED, proving the env var (not api_base) is what controls it ===")
attempt("D", "http://127.0.0.1:8900/v1", "http://127.0.0.1:1/v1")
