"""Field watchers.

Phase M6.a: polling watcher — periodically re-reads a field in the target
process and fires a callback on value change. Zero impact on the target
JVM; loses rapid transitions that alternate faster than the polling
interval. Adequate for debugging, state dashboards, and tracing slow
state machines.

Phase M6.b (not yet): hardware-assisted watcher for static fields via
VirtualProtectEx(PAGE_READONLY) + AddVectoredExceptionHandler.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any
from collections.abc import Callable

ReadFn = Callable[[], Any]
ChangeCb = Callable[[Any, Any], None]


@dataclass
class FieldWatch:
    name: str
    read: ReadFn
    on_change: ChangeCb
    interval_ms: int = 50
    on_error: Callable[[Exception], None] | None = None


class PollingWatcher:
    """Runs each FieldWatch on its own daemon thread.

    Separate threads per watch so a slow reader for one field doesn't
    starve another, and so each watch keeps its own polling cadence.
    """

    def __init__(self) -> None:
        self._watches: list[FieldWatch] = []
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._started = False

    def watch(self, w: FieldWatch) -> None:
        if self._started:
            raise RuntimeError("cannot add watches after start()")
        self._watches.append(w)

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        for w in self._watches:
            t = threading.Thread(
                target=self._loop, args=(w,), daemon=True,
                name=f"watch:{w.name}")
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()
        self._started = False
        self._stop.clear()

    def run_for(self, seconds: float) -> None:
        self.start()
        try:
            self._stop.wait(seconds)
        finally:
            self.stop()

    def _loop(self, w: FieldWatch) -> None:
        interval = max(0.005, w.interval_ms / 1000.0)
        prev: Any = _MISSING
        while not self._stop.is_set():
            cur: Any
            try:
                cur = w.read()
            except Exception as exc:
                if w.on_error is not None:
                    try:
                        w.on_error(exc)
                    except Exception:
                        pass
                # Skip this tick; don't treat an error as a value change.
                if self._stop.wait(interval):
                    return
                continue

            if prev is _MISSING:
                prev = cur
            elif cur != prev:
                try:
                    w.on_change(prev, cur)
                except Exception as exc:
                    if w.on_error is not None:
                        try:
                            w.on_error(exc)
                        except Exception:
                            pass
                prev = cur

            if self._stop.wait(interval):
                return


_MISSING = object()  # sentinel distinct from any user value
