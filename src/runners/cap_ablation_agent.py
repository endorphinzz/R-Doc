"""Agent loop used by the cap ablation experiment."""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_STEP0 = os.path.join(_HERE, "..", "p1", "step0_env")
sys.path.insert(0, _STEP0)

from agent import Agent  # noqa: E402
from tools import RECORDER, _rel_path_in_pool, write_file  # noqa: E402


class CappedAgent(Agent):

    def __init__(self, *a, call_write_cap: int | None = None, **kw):
        super().__init__(*a, **kw)
        self.call_write_cap = call_write_cap

    def _capped_copy(self, src: str, dst: str, cap: int) -> dict:
        if not os.path.exists(src):
            return {"ok": False, "error": f"source not found: {src}"}
        with open(src, "rb") as f:
            data = f.read(cap)
        rel = _rel_path_in_pool(self.pool, dst) if self.pool else None
        if rel is not None:
            try:
                self.pool.append_bytes(rel, data)
            except OSError as e:
                return {"ok": False, "error": str(e)}
        else:
            with open(dst, "ab") as f:
                f.write(data)
        RECORDER.record(dst, len(data))
        return {"ok": True, "written_bytes": len(data), "src": src, "dst": dst,
                "note": f"per-call write limit ({cap} bytes) reached; "
                        f"write truncated"}

    def _dispatch(self, tool_name: str, args: dict) -> dict:
        cap = self.call_write_cap
        if cap is not None and tool_name in ("write_file", "copy_file"):
            pending = self._pending_bytes(tool_name, args)
            if pending is not None and pending > cap:
                if tool_name == "copy_file":
                    return self._capped_copy(args.get("src", ""),
                                             args.get("dst", ""), cap)
                content = args.get("content", "")
                truncated = content.encode("utf-8")[:cap].decode(
                    "utf-8", errors="ignore")
                res = write_file(args.get("path", ""), truncated, pool=self.pool)
                res["note"] = (f"per-call write limit ({cap} bytes) reached; "
                               f"write truncated")
                return res
        return super()._dispatch(tool_name, args)
