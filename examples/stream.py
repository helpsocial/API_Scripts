#!/usr/bin/env python3

# Author: Robert Collazo <rob@helpsocial.com>
# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import getpass
import os
import sys

try:
    import ujson as json
except ImportError:
    import json

from argparse import ArgumentParser
from os.path import abspath, dirname, join as path_join
from time import time

# add the helpsocial directory to the path
# so that we can import it more cleanly
sys.path.insert(0, dirname(dirname(abspath(__file__))))

from helpsocial import RestConnectClient, StreamingConnectClient
from helpsocial.exceptions import ApiException
from helpsocial.hooks import RequestPrinter, ResponsePrinter, StreamResponsePrinter
from helpsocial.utils import data_get
from helpsocial.routing.dispatcher import Dispatcher
from helpsocial.routing.worker import ConsolePrintWorker


def read_config(path):
    """Parse the json configuration file found at `path` into
    a python dictionary.

    :type path: string
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

    :type config: dict
    :param config: a dictionary configuration object.

    :rtype: string:
    :return: the specified user's auth token.
    """

    if data_get(config, 'stream.user_token') is not None:
        return data_get(config, 'stream.user_token')

    client = RestConnectClient(
        data_get(config, 'auth.auth_scope'),
        data_get(config, 'auth.api_key')
    )

    username = data_get(config, 'stream.username')
    if username is None:
        username = input('username: ')
    password = data_get(config, 'stream.password')
    if password is None:
        password = getpass.getpass('password: ')

    return data_get(client.authenticate(username, password), 'value')


def authorize_sse_stream(config_path):
    """Demo the retrieval of a SSE Stream authorization code.

    :type config_path: string
    :param config_path:
    """

    config = read_config(config_path)
    user_token = authenticate(config)

    client = RestConnectClient(
        data_get(config, 'auth.auth_scope'),
        data_get(config, 'auth.api_key'),
        user_token=user_token,
        request_hooks=[RequestPrinter()],
        response_hooks=[ResponsePrinter()]
    )

    authorization = client.get_sse_authorization()
    print('\n\nRetrieved authorization token for user.')
    print('Authorization: ' + authorization)


def sse_stream(config_path, authorization=None, ttl=None,
               last_event_id=None, event_types=None):
    """Demo reading from a stream of server sent events. The events
    are printed to the console using a `ConsolePrintWorker`. The demo can
    be completed killed issuing a keyboard interrupt or any other
    kill sig.

    :type config_path: string
    :param config_path:

    :type authorization: string
    :param authorization: SSE authorization token.

    :type ttl: int
    :param ttl: the stream time to live, after which it will disconnect automatically

    :type last_event_id: int
    :param last_event_id: Last event processed

    :type event_types: list
    :param event_types: event types to stream.
    """

    config = read_config(config_path)
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
            response_hooks=[StreamResponsePrinter()]
    )

    params = {
        'last_event_id': last_event_id,
        'event_types': event_types
    }

    try:
        if authorization is None:
            authorization = RestConnectClient(
                data_get(config, 'auth.auth_scope'),
                data_get(config, 'auth.api_key'),
                user_token=user_token
            ).get_sse_authorization()

        start = time()
        client.sse(authorization, params=params, async=True)

        forever = ttl < 0
        while client.is_alive():
            if not forever and time() > (start + ttl):
                break
    except ApiException:
        pass
    except KeyboardInterrupt:
        # We ignore the keyboard interrupt - The user sent it,
        # and knows they sent it
        pass
    finally:
        # Tell the client to stop the underlying
        # stream thread.
        client.shutdown()


def activity_stream(client, async=True, from_=None, to=None,
                    posted_by=None, type_id=None, network_id=None):
    """Open the activity JSON stream.

    :type client: StreamingConnectClient
    :param client:

    :type async: bool
    :param async:

    :type from_: string
    :param from_:

    :type to: string
    :param to:

    :type posted_by: int
    :param posted_by:

    :type type_id: int
    :param type_id:

    :type network_id: int
    :param network_id:
    """

    params = {
        'from': from_,
        'to': to,
        'posted_by': posted_by,
        'type_id': type_id,
        'network_id': network_id,
    }

    return client.activities(params=params, async=async)


def conversation_stream(client, async=True, from_=None, to=None,
                        last_conversation_id=None, with_closed=None):
    """Open the conversation JSON stream.

    :type client: StreamingConnectClient
    :param client:

    :type async: bool
    :param async:

    :type from_: string
    :param from_:

    :type to: string
    :param to:

    :type last_conversation_id: int
    :param last_conversation_id:

    :type with_closed: bool
    :param with_closed:
    """

    params = {
        'from': from_,
        'to': to,
        'last_conversation_id': last_conversation_id,
        'with_closed': with_closed
    }

    return client.conversations(params=params, async=async)


def event_stream(client, async=True, from_=None, to=None,
                 last_event_id=None, event_types=None):
    """Open the event JSON stream.

    :type client: StreamingConnectClient
    :param client:

    :type async: bool
    :param async:

    :type from_: string
    :param from_:

    :type to: string
    :param to:

    :type last_event_id: int
    :param last_event_id: Last event processed

    :type event_types: list
    :param event_types: event types to stream (only available when selecting the events stream)
    """

    params = {
        'from': from_,
        'to': to,
        'last_event_id': last_event_id,
        'event_types': event_types
    }

    return client.events(params=params, async=async)


def json_stream(stream, config_path, ttl=None, **kwargs):
    """Demo reading from a json stream. Each json entity is
    printed to the console using a `ConsolePrintWorker`. The demo can
    be completed killed issuing a keyboard interrupt or any other
    kill sig.

    :type stream: string
    :param stream:

    :type config_path: string
    :param config_path:

    :type ttl: int
    :param ttl: the stream time to live, after which it will disconnect automatically
    """

    config = read_config(config_path)
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
        response_hooks=[StreamResponsePrinter()]
    )

    def default_stream(*args, **kwargs):
        raise RuntimeError('Invalid stream option.')
    streams = {
        'activity': activity_stream,
        'conversation': conversation_stream,
        'events': event_stream,
    }

    try:
        stream = streams.get(stream, default_stream)
        start = time()
        stream(client, async=True, **kwargs)

        forever = ttl < 0
        while client.is_alive():
            if not forever and time() > (start + ttl):
                break
    except ApiException:
        pass
    except KeyboardInterrupt:
        pass
    finally:
        # Tell the client to stop the underlying
        # stream thread.
        client.shutdown()


class Command(object):
    """Wraps the command line argument parser, handling the stream example
    command options.

    usage:

    .. code-bloc:: python

        command = Command()
        command(sys.argv[1:])

    """
    def __init__(self):
        self._parser = ArgumentParser(
            prog='stream',
            description='Begin streaming the specified stream.'
        )
        self._configure()

    def __call__(self, options):
        args = vars(self._parser.parse_args(options))
        func = args['func']
        del args['func']

        if 'from' in args:
            args['from_'] = args['from']
            del args['from']

        func(**args)

    def _configure(self):
        self._subparsers = self._parser.add_subparsers(description='select stream command.')

        self._activities_subparser()
        self._conversations_subparser()
        self._events_subparser()
        self._sse_stream_subparser()
        self._sse_authorization_subparser()

    @staticmethod
    def _add_ttl_option(parser):
        """Add the time time live option.

        :type parser: argparse.ArgumentParser
        :param parser:
        """

        parser.add_argument('--ttl',
                            help='Control the length of time the stream will '
                                 'run for in seconds. By default it will run '
                                 'until cancelled.)',
                            type=int,
                            default=-1)

    @staticmethod
    def _add_config_option(parser):
        """Add the config option

        :type parser: argparse.ArgumentParser
        :param parser:
        """

        parser.add_argument('--config',
                            dest='config_path',
                            help='Path to configuration file.',
                            default=path_join(dirname(abspath(__file__)), '.config.json'))

    @staticmethod
    def _add_default_stream_opts(parser):
        Command._add_ttl_option(parser)
        Command._add_config_option(parser)

    @staticmethod
    def _add_bounded_stream_opts(parser):
        parser = parser.add_subparsers().add_parser(
                'bounded',
                description='Create a stream bounded between two points in time. [FROM, TO]'
        )

        parser.add_argument('from', metavar='FROM', help='Stream start (inclusive).')
        parser.add_argument('to', metavar='TO', help='Stream stop (exclusive).')

    def _sse_authorization_subparser(self):
        parser = self._subparsers.add_parser('authorize-sse-stream',
                                             description='Get authorization code for sse stream.')
        Command._add_config_option(parser)
        parser.set_defaults(func=authorize_sse_stream)

    def _sse_stream_subparser(self):
        parser = self._subparsers.add_parser('sse',
                                             description='Stream Server Sent Events.')
        Command._add_default_stream_opts(parser)
        parser.add_argument('--authorization', help='SSE stream authorization code.')
        parser.add_argument('--last-event-id',
                            type=int,
                            help='The id of the last event processed.')
        parser.add_argument('--event-types',
                            nargs='*',
                            type=int,
                            help='Filter to specific event type(s).')
        parser.set_defaults(func=sse_stream)

    def _activities_subparser(self):
        parser = self._subparsers.add_parser('activities',
                                             description='Stream activity json.')
        Command._add_default_stream_opts(parser)
        Command._add_bounded_stream_opts(parser)
        parser.set_defaults(func=json_stream, stream='activity')

    def _conversations_subparser(self):
        parser = self._subparsers.add_parser('conversations',
                                             description='Stream conversation json.')
        Command._add_default_stream_opts(parser)
        Command._add_bounded_stream_opts(parser)
        parser.set_defaults(func=json_stream, stream='conversation')

    def _events_subparser(self):
        parser = self._subparsers.add_parser('events',
                                             description='Stream event json.')
        Command._add_default_stream_opts(parser)
        Command._add_bounded_stream_opts(parser)
        parser.add_argument('--last-event-id',
                            type=int,
                            help='The id of the last event processed.')
        parser.add_argument('--event-types',
                            nargs='*',
                            type=int,
                            help='Filter to specific event type(s).')
        parser.set_defaults(func=json_stream, stream='events')


if __name__ == '__main__':
    cmd = Command()
    cmd(sys.argv[1:])
