"""Background workers that keep the GUI responsive."""

import traceback

from PyQt5.QtCore import QObject, QThread, pyqtSignal

from pcap_report.core.control import TaskCancelled, TaskControl


class Worker(QObject):
    """Runs ``func(progress=..., control=..., log=...)`` in a QThread.

    Signals
    -------
    progress(int)      percentage 0-100
    message(str)       free-form status text
    succeeded(object)  return value of *func*
    failed(str)        error description (with traceback)
    cancelled()
    done()             emitted last, whatever the outcome
    """

    progress = pyqtSignal(int)
    message = pyqtSignal(str)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()
    done = pyqtSignal()

    def __init__(self, func):
        super().__init__()
        self._func = func
        self.control = TaskControl()

    def run(self):
        try:
            result = self._func(progress=self.progress.emit, control=self.control,
                                log=self.message.emit)
        except TaskCancelled:
            self.cancelled.emit()
        except Exception as exc:  # report every failure to the UI
            self.failed.emit(f"{exc}\n{traceback.format_exc()}")
        else:
            self.succeeded.emit(result)
        finally:
            self.done.emit()


def create_worker(func, parent):
    """Create a :class:`Worker` for *func* bound to a new QThread.

    Connect to the worker's signals first, then call ``worker.start()``;
    starting only afterwards guarantees no signal is missed even when the
    task finishes immediately. Worker and thread clean themselves up.
    """
    thread = QThread(parent)
    worker = Worker(func)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.done.connect(thread.quit)
    worker.done.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)
    worker.thread_ref = thread
    worker.start = thread.start
    return worker
