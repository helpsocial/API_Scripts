#!/usr/bin/env python3

# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import multiprocessing as mp
import os
import re
import sys
import webbrowser

try:
    import ujson as json
except ImportError:
    import json

from argparse import ArgumentParser
from multiprocessing import Queue
from time import time, sleep
from urllib.parse import ParseResult, urlsplit, urlunsplit, parse_qs, urlencode

# add the helpsocial directory to the path
# so that we can import it more cleanly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helpsocial import RestConnectClient
from helpsocial.auth import UserAuth
from helpsocial.hooks import RequestPrinter, ResponsePrinter
from helpsocial.utils import data_get


class Worker(object):
    def __init__(self, client, template_url, token):
        self.name = 'Worker-' + os.urandom(4).hex()
        self.pid = None
        self.template_url = template_url
        self.client = client
        self.auth = UserAuth(client.auth_scope, client.api_key, token)

    def handle(self, manager, conversation_id):
        self.pid = str(mp.current_process().pid)
        self._log('handling conversation {}', conversation_id)
        url = re.sub('{conversation_id}', conversation_id, self.template_url)
        try:
            authed_url = self._authenticate(url, self._get_single_use_token())
            self._log('opening conversation spa [{}]...', authed_url)
            if webbrowser.open_new(authed_url):
                self._log('opened conversation spa.')
            else:
                self._log('failed to open conversation spa.')
        except Exception as e:
            self._log('{} opening conversation {} spa.', e, conversation_id)
        finally:
            manager.work_complete(self)
            self.pid = None

    def _get_single_use_token(self):
        """Retrieve an single use token for the authenticated user.
        This allows the client to relatively safely authenticate their user through
        the query string, as is required when accessing a page via an iFrame, where
        headers cannot be set.
        """

        self._log('Retrieving single use token.')
        response = self.client.get('tokens/exchange', auth=self.auth, http_errors=True)
        if response.status_code != 200:
            raise Exception(response.json())
        return data_get(response.json(), 'data.token')

    def _authenticate(self, url, token):
        self._log('Authenticating spa request [{}].', url)
        parsed = urlsplit(url)
        query = {} if not parsed.query else parse_qs(parsed.query)
        query.update({
            'scope': token['scope'],
            'token': token['value']
        })
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                           urlencode(query, doseq=True), parsed.fragment,))

    def _log(self, message, *args, **kwargs):
        print('[{},{}] {}'.format(self.name, self.pid, message.format(*args, **kwargs)))


class Manager(object):
    def __init__(self, workers=-1):
        self.cancelled = False
        self._workers = Queue(workers)
        self._queue = Queue()
        self._processes = []
        self._thread = mp.Process(target=self._run)

    def add_worker(self, worker):
        if self._workers.full():
            raise Exception('Worker pool full')
        self._workers.put_nowait(worker)

    def queue(self, conversation):
        self._queue.put(conversation)

    def has_pending(self):
        return not self._queue.empty()

    def start(self):
        self._thread.start()

    def stop(self):
        self.cancelled = True
        for process in self._processes:
            process.terminate()

        start = time()
        while self._thread.is_alive():
            if (time() - start) > 30:
                self._thread.terminate()
                break
            sleep(1)

    def work_complete(self, worker):
        self._workers.put_nowait(worker)

    def _run(self):
        while True:
            if self.cancelled:
                break
            try:
                worker = self._workers.get_nowait()
            except:
                print('No worker available.')
                sleep(1)
                break
            try:
                job = self._queue.get_nowait()
            except:
                print('No job available.')
                self._workers.put(worker)
                sleep(1)
                break

            process = mp.Process(target=worker.handle, args=(self, job,))
            self._processes.append(process)
            process.start()


def read_config(path):
    """Read the json configuration

    :type path: string
    :param path:
    :return:
    """
    if not os.path.exists(path):
        raise IOError('{} does not exist.', path)
    with open(path, 'r') as file_:
        return json.load(file_)


def single(conversation_id, config_path):
    config = read_config(config_path)

    client = RestConnectClient(
        data_get(config, 'auth.auth_scope'),
        data_get(config, 'auth.api_key'),
        host=data_get(config, 'api.host'),
        ssl=data_get(config, 'api.ssl'),
        request_hooks=[RequestPrinter()],
        response_hooks=[ResponsePrinter()]
    )

    manager = Manager()
    manager.add_worker(Worker(client,
                              data_get(config, 'launch_conversation.spa_url'),
                              data_get(config, 'launch_conversation.user_token')))

    manager.queue(conversation_id)

    manager.start()
    while manager.has_pending():
        sleep(1)
    manager.stop()


if __name__ == '__main__':
    parser = ArgumentParser()

    sub = parser.add_subparsers()

    single_cmd = sub.add_parser('single')
    single_cmd.add_argument('conversation_id', help='Conversation id to open.')
    single_cmd.add_argument('--config', dest='config_path', default=os.path.join(os.path.abspath(os.path.dirname(__file__)), '.config.json'))
    single_cmd.set_defaults(func=single)

    args = vars(parser.parse_args())
    func = args['func']
    del args['func']

    func(**args)
