"""Tests for the cooperative pause / cancel control."""

import threading
import time

import pytest

from pcap_report.core.control import TaskCancelled, TaskControl


def test_checkpoint_passes_when_running():
    TaskControl().checkpoint()


def test_pause_blocks_until_resume():
    control = TaskControl()
    control.pause()
    passed = threading.Event()

    def worker():
        control.checkpoint()
        passed.set()

    thread = threading.Thread(target=worker)
    thread.start()
    time.sleep(0.05)
    assert not passed.is_set()
    control.resume()
    thread.join(1)
    assert passed.is_set()


def test_cancel_wakes_paused_worker():
    control = TaskControl()
    control.pause()
    control.cancel()
    assert control.is_cancelled and not control.is_paused
    with pytest.raises(TaskCancelled):
        control.checkpoint()
