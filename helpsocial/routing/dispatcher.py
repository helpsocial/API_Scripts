# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details


class Dispatcher(object):
    """TODO

    """

    def __init__(self, worker=None):
        self._worker = worker

    def dispatch(self, item):
        """TODO

        :param item:
        :return:
        """

        if self._worker is None:
            return
        self._worker.handle(item)
