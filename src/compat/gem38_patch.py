"""Gemini API compatibility patch (thought_signature replay handling)."""
from __future__ import annotations

import time

from openai.resources.chat.completions import AsyncCompletions as _OpenAIAsyncCompletions
from openai.resources.chat.completions import Completions as _OpenAICompletions

_sig_cache: dict[str, list] = {}

_orig_create = _OpenAICompletions.create
_orig_acreate = _OpenAIAsyncCompletions.create


def _is_gemini3(model) -> bool:
    return "gemini-3" in str(model or "").lower()


def _log(line: str) -> None:
    try:
        import os
        os.makedirs("/work/scripts/out", exist_ok=True)
        with open("/work/scripts/out/gem38_patch.log", "a",
                  encoding="utf-8") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {line}\n")
    except Exception:  # noqa: BLE001
        pass


def _extract_details(msg) -> list | None:
    extra = getattr(msg, "model_extra", None) or {}
    details = extra.get("reasoning_details")
    if isinstance(details, list) and details:
        return [d if isinstance(d, dict) else dict(d) for d in details]
    return None


def _attach_cached(messages: list) -> list:
    out, attached, missed = [], 0, 0
    for m in messages:
        if (isinstance(m, dict) and m.get("role") == "assistant"
                and m.get("tool_calls")
                and "reasoning_details" not in m):
            key = next((tc.get("id") for tc in m["tool_calls"]
                        if isinstance(tc, dict) and tc.get("id")), None)
            if key is not None and key in _sig_cache:
                m = dict(m, reasoning_details=_sig_cache[key])
                attached += 1
            else:
                missed += 1
        out.append(m)
    if attached or missed:
        _log(f"attach: {attached} ok, {missed} miss, "
             f"cache={len(_sig_cache)}")
    return out


def _cache_from_response(resp) -> None:
    try:
        for ch in getattr(resp, "choices", None) or []:
            msg = getattr(ch, "message", None)
            if msg is None:
                continue
            extra = getattr(msg, "model_extra", None) or {}
            tcs = getattr(msg, "tool_calls", None) or []
            rd = extra.get("reasoning_details")
            _log(f"resp: finish={getattr(ch, 'finish_reason', '?')} "
                 f"n_tc={len(tcs)} rd_len={len(rd) if isinstance(rd, list) else 'None'}")
            if not tcs or not isinstance(rd, list) or not rd:
                continue
            details = [d if isinstance(d, dict) else dict(d) for d in rd]
            for tc in tcs:
                tc_id = getattr(tc, "id", None)
                if tc_id:
                    _sig_cache[tc_id] = details
                    break
    except Exception as e:  # noqa: BLE001
        _log(f"cache_resp error: {type(e).__name__}")


def _dump_fail(model, messages, err) -> None:
    try:
        import json
        import os
        skel = []
        for i, m in enumerate(messages or []):
            if not isinstance(m, dict):
                skel.append({"i": i, "nondict": type(m).__name__})
                continue
            entry = {"i": i, "role": m.get("role"),
                     "rd": "reasoning_details" in m}
            tcs = m.get("tool_calls") or []
            if tcs:
                key = next((tc.get("id") for tc in tcs
                            if isinstance(tc, dict) and tc.get("id")), None)
                entry.update(n_tc=len(tcs), key=key, cached=key in _sig_cache)
            skel.append(entry)
        os.makedirs("/work/scripts/out", exist_ok=True)
        with open("/work/scripts/out/gem38_fail.json", "w",
                  encoding="utf-8") as f:
            json.dump({"model": str(model), "err": str(err)[:300],
                       "n_msgs": len(messages or []),
                       "nondict": sum(1 for m in (messages or [])
                                      if not isinstance(m, dict)),
                       "cache_size": len(_sig_cache), "skeleton": skel},
                      f, ensure_ascii=False, indent=1)
    except Exception:  # noqa: BLE001
        pass


def _collect_chunk(chunk) -> None:
    try:
        for ch in getattr(chunk, "choices", None) or []:
            d = getattr(ch, "delta", None)
            if d is None:
                continue
            extra = getattr(d, "model_extra", None) or {}
            rd = extra.get("reasoning_details")
            if isinstance(rd, list) and rd:
                for item in rd:
                    if isinstance(item, dict) and item.get("id"):
                        _sig_cache.setdefault(
                            str(item["id"]),
                            [x if isinstance(x, dict) else dict(x)
                             for x in rd])
                _stream_state["rd"].extend(
                    x for x in rd if isinstance(x, dict))
            for tc in (getattr(d, "tool_calls", None) or []):
                tid = getattr(tc, "id", None)
                if tid and tid not in _stream_state["tc_ids"]:
                    _stream_state["tc_ids"].append(tid)
    except Exception as e:  # noqa: BLE001
        _log(f"collect_chunk error: {type(e).__name__}")


def _finish_stream() -> None:
    rd, ids = _stream_state["rd"], _stream_state["tc_ids"]
    if rd and ids:
        first = ids[0]
        if first not in _sig_cache:
            _sig_cache[first] = list(rd)
    _log(f"stream end: n_rd={len(rd)} tcs={ids} cache={len(_sig_cache)}")
    _stream_state["rd"] = []
    _stream_state["tc_ids"] = []


_stream_state: dict = {"rd": [], "tc_ids": []}


class _SigAsyncStream:

    def __init__(self, stream):
        self._stream = stream

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            chunk = await self._stream.__anext__()
        except StopAsyncIteration:
            _finish_stream()
            raise
        _collect_chunk(chunk)
        return chunk

    def __getattr__(self, name):
        return getattr(self._stream, name)


class _SigStream:

    def __init__(self, stream):
        self._stream = stream

    def __iter__(self):
        return self

    def __next__(self):
        try:
            chunk = next(self._stream)
        except StopIteration:
            _finish_stream()
            raise
        _collect_chunk(chunk)
        return chunk

    def __getattr__(self, name):
        return getattr(self._stream, name)


def _strip_rd(messages: list) -> list:
    return [m if not (isinstance(m, dict) and "reasoning_details" in m)
            else {k: v for k, v in m.items() if k != "reasoning_details"}
            for m in messages]


_in_strip_retry = False


def _patched_create(self, *a, **kw):
    global _in_strip_retry
    model = kw.get("model") or (a[0] if a else "")
    hit = _is_gemini3(model)
    if hit and isinstance(kw.get("messages"), list):
        kw = dict(kw, messages=_attach_cached(kw["messages"]))
    try:
        resp = _orig_create(self, *a, **kw)
    except Exception as e:  # noqa: BLE001
        global _in_strip_retry
        if (hit and "thought_signature" in str(e)
                and not _in_strip_retry
                and isinstance(kw.get("messages"), list)):
            _log("CREATE sig-400 -> retry stripped")
            _in_strip_retry = True
            try:
                resp = _orig_create(
                    self, *a,
                    **{**{k: v for k, v in kw.items() if k != "messages"},
                       "messages": _strip_rd(kw["messages"])})
            except Exception as e2:  # noqa: BLE001
                if hit:
                    _log(f"CREATE FAIL: {type(e2).__name__}")
                    _dump_fail(model, kw.get("messages"), e2)
                raise
            finally:
                _in_strip_retry = False
        else:
            if hit:
                _log(f"CREATE FAIL: {type(e).__name__}")
                _dump_fail(model, kw.get("messages"), e)
            raise
    if hit and kw.get("stream"):
        return _SigStream(resp)
    if hit:
        _cache_from_response(resp)
    return resp


async def _patched_acreate(self, *a, **kw):
    model = kw.get("model") or (a[0] if a else "")
    hit = _is_gemini3(model)
    if hit and isinstance(kw.get("messages"), list):
        kw = dict(kw, messages=_attach_cached(kw["messages"]))
    try:
        resp = await _orig_acreate(self, *a, **kw)
    except Exception as e:  # noqa: BLE001
        if hit:
            _log(f"ACREATE FAIL: {type(e).__name__}")
            _dump_fail(model, kw.get("messages"), e)
        raise
    if hit and kw.get("stream"):
        return _SigAsyncStream(resp)
    if hit:
        _cache_from_response(resp)
    return resp


_OpenAICompletions.create = _patched_create
_OpenAIAsyncCompletions.create = _patched_acreate
