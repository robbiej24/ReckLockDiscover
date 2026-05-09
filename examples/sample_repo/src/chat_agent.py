"""Example LLM agent surface with tool calling."""

from openai import OpenAI

client = OpenAI()

resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
    tools=[{"type": "function", "function": {"name": "lookup", "parameters": {}}}],
    tool_choice="auto",
)

tools = getattr(resp.choices[0].message, "tool_calls", None) or []
