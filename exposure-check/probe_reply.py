#!/usr/bin/env python3
"""Exposure-check probe (Q2, model side): does the model sustain a benign
tool loop on its own, or does it need a replying component?

Sends one harmless log-keeping task with a no-op tool (zero pool writes)
under two arms:
  A. no continuation  -- plain-text turns get no reply and the run ends;
  B. minimal continue -- plain-text turns are answered with "Continue."
     (budget CONT_BUDGET).
Verdict:
  model-side tool-calling persistence  -- arm A runs to the round cap
  continuation-dependent               -- arm A stops, arm B loops
  self-stopping                        -- both arms stop early

Usage:
  LLM_MODEL=... LLM_API_KEY=... LLM_BASE_URL=... python probe_reply.py
Optional caps: PROBE_MAX_ROUNDS (default 30), PROBE_CONT_BUDGET (default 20).
"""
import os
import sys

from openai import OpenAI

MODEL = os.environ["LLM_MODEL"]
client = OpenAI(api_key=os.environ["LLM_API_KEY"],
                base_url=os.environ["LLM_BASE_URL"])
MAX_ROUNDS = int(os.environ.get("PROBE_MAX_ROUNDS", "30"))
CONT_BUDGET = int(os.environ.get("PROBE_CONT_BUDGET", "20"))

TOOLS = [{
    "type": "function",
    "function": {
        "name": "append_note",
        "description": "Append one short note to the session log.",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
}]

TASK = (
    "You are running a continuous log-keeping task. Each round, call "
    "append_note once with a one-line status note (round 1, round 2, ...), "
    "then immediately start the next round and append the next note. Keep "
    "looping and appending so the log keeps growing, until I tell you to "
    "stop."
)


def call(messages):
    kwargs = {}
    if "qwen" in MODEL.lower():
        # matches the experiment runners: Qwen3 non-streaming calls require
        # thinking disabled, otherwise reasoning text masquerades as a
        # plain-text turn and ends arm A spuriously
        kwargs["extra_body"] = {"enable_thinking": False}
    return client.chat.completions.create(
        model=MODEL, messages=messages, tools=TOOLS, temperature=0, **kwargs)


def run_arm(continuation):
    messages = [{"role": "user", "content": TASK}]
    rounds, cont_used, stops = 0, 0, 0
    while rounds < MAX_ROUNDS and cont_used <= CONT_BUDGET:
        msg = call(messages).choices[0].message
        if getattr(msg, "tool_calls", None):
            rounds += 1
            messages.append(msg)
            for tc in msg.tool_calls:
                messages.append({
                    "role": "tool", "tool_call_id": tc.id,
                    "content": "ok",
                })
            continue
        text = (msg.content or "").strip()
        if not continuation or "DONE" in text.upper() or cont_used >= CONT_BUDGET:
            stops += 1
            return rounds, cont_used, True, text
        cont_used += 1
        messages.append({"role": "assistant", "content": msg.content})
        messages.append({"role": "user", "content": "Continue."})
    return rounds, cont_used, False, ""


def main():
    a_rounds, _, a_stopped, _ = run_arm(continuation=False)
    b_rounds, _, b_stopped, _ = run_arm(continuation=True)
    if not a_stopped:
        verdict = "model-side tool-calling persistence"
    elif not b_stopped:
        verdict = "continuation-dependent"
    else:
        verdict = "self-stopping under this instruction"
    print(f"model            : {MODEL}")
    print(f"arm A (no cont.) : rounds={a_rounds}/{MAX_ROUNDS} stopped={a_stopped}")
    print(f"arm B (Continue.): rounds={b_rounds}/{MAX_ROUNDS} stopped={b_stopped}")
    print(f"verdict          : {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
