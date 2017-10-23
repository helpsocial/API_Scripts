

class Dispatcher(object):
    def __init__(self, worker=None):
        self._worker = worker

    def dispatch(self, item):
        if self._worker is None:
            return
        self._worker.handle(item)
