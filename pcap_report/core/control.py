"""Cooperative pause / resume / cancel support for long-running tasks."""

import threading


class TaskCancelled(Exception):
    """Raised from :meth:`TaskControl.checkpoint` once a task is cancelled."""


class TaskControl:
    """Thread-safe flags a worker polls through :meth:`checkpoint`.

    The controlling thread calls :meth:`pause`, :meth:`resume` or
    :meth:`cancel`; the worker calls :meth:`checkpoint` regularly, which
    blocks while paused and raises :class:`TaskCancelled` when cancelled.
    """

    def __init__(self):
        self._running = threading.Event()
        self._running.set()
        self._cancelled = threading.Event()

    @property
    def is_paused(self):
        return not self._running.is_set()

    @property
    def is_cancelled(self):
        return self._cancelled.is_set()

    def pause(self):
        self._running.clear()

    def resume(self):
        self._running.set()

    def cancel(self):
        self._cancelled.set()
        self._running.set()  # wake a paused worker so it can exit

    def checkpoint(self):
        self._running.wait()
        if self._cancelled.is_set():
            raise TaskCancelled()
