# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

class Dispatcher(object):
    def __init__(self, worker=None):
        self._worker = worker

    def dispatch(self, item):
        if self._worker is None:
            return
        self._worker.handle(item)
