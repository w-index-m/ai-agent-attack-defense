"""Drives hackingBuddyGPT's LiteLLM wrapper directly against the mock LLM server,
verifying both plain-text completion and tool-calling (capabilities -> OpenAI
function-calling schema -> parsed tool_calls).

IMPORTANT: hackingBuddyGPT's own `api_base` config field is dead code (see
hackingbuddygpt-local-backend-notes.md) — setting it here has no effect. The mock
server must instead be reached via the OPENAI_API_BASE environment variable.

Usage:
    git clone https://github.com/ipa-lab/hackingBuddyGPT /path/to/hackingbuddygpt
    python3 mock_llm_server.py 8900 &
    OPENAI_API_BASE="http://127.0.0.1:8900/v1" python3 drive_tools_smoke_test.py /path/to/hackingbuddygpt/src
"""
import json
import sys

sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else ".")

from hackingBuddyGPT.capabilities.record_note import RecordNote
from hackingBuddyGPT.capability import capabilities_to_tools
from hackingBuddyGPT.utils.llm import LiteLLM

llm = LiteLLM(
    api_key="dummy-mock-key",
    model="openai/mock-model",
    context_size=8000,
    api_base="http://127.0.0.1:8900/v1",  # dead config field, left here deliberately
)
llm.init()

note = RecordNote()
tools = list(capabilities_to_tools({"record_note": note}))
print("tools schema sent to litellm:", json.dumps(tools, indent=2)[:400])

messages = [{"role": "user", "content": "Record a note that port 5000 is open."}]
result = llm.get_response(messages, capabilities={"record_note": note})
print("result.result type:", type(result.result))
print("result.answer:", result.answer)
print("tool_calls:", getattr(result.result, "tool_calls", None))
