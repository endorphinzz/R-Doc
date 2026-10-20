"""DeepSeek API compatibility patch (thinking-output handling)."""
from __future__ import annotations

import os

from autogen.oai.client import OpenAIWrapper


def _is_deepseek(wrapper) -> bool:
    try:
        for cfg in getattr(wrapper, "_config_list", []):
            if "deepseek" in str(cfg.get("model", "")).lower():
                return True
    except Exception:
        pass
    return False


def _is_qwen(wrapper) -> bool:
    try:
        for cfg in getattr(wrapper, "_config_list", []):
            if "qwen" in str(cfg.get("model", "")).lower():
                return True
    except Exception:
        pass
    return False


def _sanitize(messages: list) -> list:
    out = []
    for m in messages or []:
        if isinstance(m, dict) and m.get("role") == "assistant":
            rc = m.get("reasoning_content", None)
            if rc is None and not m.get("tool_calls"):
                m = dict(m, reasoning_content="")
            elif rc is None:
                m = {k: v for k, v in m.items() if k != "reasoning_content"}
        out.append(m)
    return out


_orig_create = OpenAIWrapper.create


def _patched_create(self, params=None, **kwargs):
    if params is not None:
        merged = dict(params)
        merged.update(kwargs)
        kwargs = merged
    if _is_deepseek(self):
        if isinstance(kwargs.get("messages"), list):
            kwargs = dict(kwargs, messages=_sanitize(kwargs["messages"]))
    elif _is_qwen(self):
        extra = dict(kwargs.get("extra_body") or {})
        extra["enable_thinking"] = False
        kwargs = dict(kwargs, extra_body=extra)
    return _orig_create(self, **kwargs)


OpenAIWrapper.create = _patched_create
