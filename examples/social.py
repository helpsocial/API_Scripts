#!/usr/bin/env python3

# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import getpass
import sys

try:
    import ujson as json
except ImportError:
    import json

from argparse import ArgumentParser
from os.path import abspath, dirname, exists as path_exists, join as path_join

# add the helpsocial directory to the path
# so that we can import it more cleanly
sys.path.insert(0, dirname(dirname(abspath(__file__))))

import helpsocial

from helpsocial import RestConnectClient
from helpsocial.auth import UserAuth
from helpsocial.hooks import RequestPrinter, ResponsePrinter
from helpsocial.utils import data_get


NETWORKS = {
    1: 'Twitter',
    2: 'Facebook',
    3: 'Instagram',
}


def read_config(path):
    """Parse the json configuration file found at `path` into
    a python dictionary.

    :type path: string
    :param path: Absolute path to the configuration file.

    :rtype: dict
    :return: The configuration file parsed into a dictionary.
    """

    if not path_exists(path):
        raise IOError('{} does not exist.', path)
    with open(path, 'r') as file_:
        return json.load(file_)


def get_client(config):
    client = RestConnectClient(
        data_get(config, 'auth.auth_scope'),
        data_get(config, 'auth.api_key'),
        host=data_get(config, 'api.host', helpsocial.API_HOST),
        ssl=data_get(config, 'api.ssl'),
        request_hooks=[RequestPrinter()],
        response_hooks=[ResponsePrinter()]
    )

    if data_get(config, 'social.user_token') is not None:
        client.set_user_token(data_get(config, 'social.user_token'))
        return client
    if data_get(config, 'auth.user_token') is not None:
        client.set_user_token(data_get(config, 'auth.user_token'))
        return client

    username = data_get(config, 'social.username')
    if username is None:
        username = input('username: ')
    password = data_get(config, 'social.password')
    if password is None:
        password = getpass.getpass('password: ')

    user_token = data_get(client.authenticate(username, password), 'value')
    client.set_user_token(user_token)
    return client


def post(network_id, as_profile, text, config, **kwargs):
    data = {
        'network': NETWORKS[network_id],
        'as': as_profile,
        'text': text
    }
    client = get_client(config)
    auth = UserAuth(client.auth_scope, client.api_key, client.user_token)
    client.post('activities', auth=auth, json=data, **kwargs)


def reply(activity_id, as_profile, text, config, **kwargs):
    data = {
        'as': as_profile,
        'text': text,
        'in_reply_to': activity_id
    }
    client = get_client(config)
    auth = UserAuth(client.auth_scope, client.api_key, client.user_token)
    client.post('activities', auth=auth, json=data, **kwargs)


def share(activity_id, as_profile, config, text=None, **kwargs):
    data = {
        'as': as_profile,
        'share_of': activity_id,
    }
    if text:
        data['text'] = text
    client = get_client(config)
    auth = UserAuth(client.auth_scope, client.api_key, client.user_token)
    client.post('activities', auth=auth, json=data, **kwargs)


class CommandLine(object):
    def __init__(self):
        self.parser = ArgumentParser()
        self.subparsers = self.parser.add_subparsers()
        self._configure()

    def exec(self, options):
        args = vars(self.parser.parse_args(options))
        func = args['func']
        args['config'] = read_config(args['config_path'])

        del args['func']
        del args['config_path']

        func(**args)

    @staticmethod
    def with_config_option(parser):
        """

        :type parser: argparse.ArgumentParser
        :param parser:

        :rtype: argparse.ArgumentParser
        :return:
        """
        parser.add_argument('--config',
                            dest='config_path',
                            help='Path to configuration file',
                            default=path_join(dirname(abspath(__file__)), '.config.json'))
        return parser

    def _add_post_subparser(self, network_id, subparsers):
        parser = subparsers.add_parser('post')
        parser.add_argument('as_profile')
        parser.add_argument('text')
        parser.set_defaults(func=post, network_id=network_id)
        self.with_config_option(parser)

    def _add_reply_subparser(self, subparsers):
        parser = subparsers.add_parser('reply')
        parser.add_argument('activity_id')
        parser.add_argument('as_profile')
        parser.add_argument('text')
        parser.set_defaults(func=reply)
        self.with_config_option(parser)

    def _add_share_subparser(self, subparsers, text=True):
        parser = subparsers.add_parser('share')
        parser.add_argument('activity_id')
        parser.add_argument('as_profile')
        if text:
            parser.add_argument('--text')
        parser.set_defaults(func=share)
        self.with_config_option(parser)

    def _configure(self):
        twitter_parser = self.subparsers.add_parser('twitter')
        twitter_subparsers = twitter_parser.add_subparsers()
        self._add_post_subparser(1, twitter_subparsers)
        self._add_reply_subparser(twitter_subparsers)
        self._add_share_subparser(twitter_subparsers)

        fb_parser = self.subparsers.add_parser('facebook')
        fb_subparsers = fb_parser.add_subparsers()
        self._add_post_subparser(2, fb_subparsers)
        self._add_reply_subparser(fb_subparsers)
        self._add_share_subparser(fb_subparsers)

        ig_parser = self.subparsers.add_parser('instagram')
        ig_subparsers = ig_parser.add_subparsers()
        self._add_post_subparser(3, ig_subparsers)
        self._add_reply_subparser(ig_subparsers)
        self._add_share_subparser(ig_subparsers)


if __name__ == '__main__':
    commandline = CommandLine()
    commandline.exec(sys.argv[1:])
