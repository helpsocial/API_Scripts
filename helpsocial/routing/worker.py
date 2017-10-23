
import json
import os


class Worker(object):
    """
    TODO
    """
    def __init__(self, name=None):
        if name is None:
            name = 'Worker-' + os.urandom().hex()
        self.name = name

    def handle(self, item):
        """
        TODO
        :param item:
        :return:
        """
        pass


class ConsolePrintWorker(Worker):
    """
    TODO
    """
    def __init__(self):
        super().__init__()

    def handle(self, item):
        if not item:
            return
        print('[{}]\n{}'.format(self.name, json.dumps(item)))
