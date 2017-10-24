#!/usr/bin/env python3

# Author: Robert Collazo <rob@helpsocial.com>
# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import getpass
import os
import json
import sys

from argparse import ArgumentParser
from os.path import abspath, dirname, join

# add the helpsocial directory to the path
# so that we can import it more cleanly
sys.path.insert(0, dirname(dirname(abspath(__file__))))

from helpsocial import RestConnectClient, StreamingConnectClient
from helpsocial.hooks import RequestPrinter, ResponsePrinter
from helpsocial.utils import data_get
from helpsocial.routing.dispatcher import Dispatcher
from helpsocial.routing.worker import ConsolePrintWorker


def read_config(path):
    """Parse the json configuration file found at `path` into
    a python dictionary.

    :param path: Absolute path to the configuration file.
    :rtype: dict
    :return: The configuration file parsed into a dictionary.
    """

    if not os.path.exists(path):
        raise IOError('{} does not exist.', path)

    with open(path, 'r') as file_:
        return json.load(file_)


def authenticate(config):
    """Use the provided configuration to retrieve
    the users auth token.

    :param config: a dictionary configuration object.
    :rtype: string:
    :return: the specified user's auth token.
    """

    if data_get(config, 'auth.user_token') is not None:
        return data_get(config, 'auth.user_token')
    client = RestConnectClient(
        data_get(config, 'auth.auth_scope'),
        data_get(config, 'auth.api_key')
    )
    username = data_get(config, 'stream.username', input('username: '))
    password = data_get(config,
                        'stream.password',
                        getpass.getpass('password: '))
    token = client.authenticate(username, password)
    return data_get(token, 'value')


def sse_stream(config):
    """Basic demo reading from a stream of server sent events. The events
    are printed to the console using a `ConsolePrintWorker`. The demo can
    be completed killed issuing a keyboard interrupt or any other
    kill sig.

    :param config:
    :return:
    """

    config = read_config(config)
    dispatcher = Dispatcher(ConsolePrintWorker())
    user_token = data_get(config, 'auth.user_token', authenticate(config))

    client = StreamingConnectClient(
            data_get(config, 'auth.auth_scope'),
            data_get(config, 'auth.api_key'),
            dispatcher,
            user_token=user_token,
            host=data_get(config, 'api.host'),
            ssl=data_get(config, 'api.ssl'),
            request_hooks=[RequestPrinter()],
            response_hooks=[ResponsePrinter(True)]
    )

    client.sse(client.get_sse_authorization(), async=True)

    try:
        while True:
            pass
    except KeyboardInterrupt:
        pass


def json_stream(stream, config):
    """Basic demo reading from a json stream. Each json entity is
    printed to the console using a `ConsolePrintWorker`. The demo can
    be completed killed issuing a keyboard interrupt or any other
    kill sig.

    :param stream:
    :param config:
    :return:
    """

    config = read_config(config)
    dispatcher = Dispatcher(ConsolePrintWorker())
    user_token = data_get(config, 'auth.user_token', authenticate(config))
    client = StreamingConnectClient(
        data_get(config, 'auth.auth_scope'),
        data_get(config, 'auth.api_key'),
        dispatcher,
        user_token=user_token,
        host=data_get(config, 'api.host'),
        ssl=data_get(config, 'api.ssl'),
        request_hooks=[RequestPrinter()],
        response_hooks=[ResponsePrinter(True)]
    )

    def default_stream(*args, **kwargs):
        raise RuntimeError('Invalid stream option.')
    streams = {
        'activity': client.activities,
        'conversation': client.conversations,
        'events': client.events,
    }

    stream = streams.get(stream, default_stream)
    stream(async=True)

    try:
        while True:
            pass
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    parser = ArgumentParser(
        prog='stream',
        description='Begin streaming the specified stream.'
    )

    parser.add_argument('--config',
                        help='Path to json configuration file.',
                        default=join(dirname(abspath(__file__)),
                                     '.config.json')
                        )

    subparsers = parser.add_subparsers(description='Select the desired '
                                                   'stream.')

    sse = subparsers.add_parser('sse',
                                description='Stream Server Sent Events.')
    sse.set_defaults(func=sse_stream)

    events = subparsers.add_parser('events',
                                   description='Stream event json.')
    events.set_defaults(func=json_stream, stream='events')

    activities = subparsers.add_parser('activities',
                                       description='Stream activity json.')
    activities.set_defaults(func=json_stream, stream='activity')

    conversations = subparsers.add_parser(
        'conversations',
        description='Stream conversation json.')
    conversations.set_defaults(func=json_stream, stream='conversation')

    args = vars(parser.parse_args())

    func = args['func']
    del args['func']

    func(**args)

