#!/usr/bin/env python3

# Author: Robert Collazo <rob@helpsocial.com>
# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import os
import getpass
import json
import sys

from argparse import ArgumentParser
from os.path import abspath, dirname, join

# add the helpsocial directory to the path
# so that we can import it more cleanly
sys.path.insert(0, dirname(dirname(abspath(__file__))))

from helpsocial import RestConnectClient
from helpsocial.auth import ApplicationAuth
from helpsocial.exceptions import ApiException
from helpsocial.hooks import RequestPrinter, ResponsePrinter
from helpsocial.utils import data_get


def main(username, config=None):
    if not os.path.exists(config):
        raise IOError('{} does not exist.', config)

    # read the configuration file
    # it doesn't have to json, you just have
    # to be able to parse it.
    with open(config, 'r') as file_:
        config = json.load(file_)

    # create an instance of the RestConnectionClient
    # using the application authentication
    # parameters.
    #
    # We're also add a request and response hook
    # so that we can echo the raw request and
    # response data to the console.
    #
    # The host, version, and ssl options are not required
    # and default to helpsocial.API_HOST, helpsocial.API_VERSION, and True.
    client = RestConnectClient(
        data_get(config, 'auth.auth_scope'),
        data_get(config, 'auth.api_key'),
        host=data_get(config, 'api.host'),
        ssl=data_get(config, 'api.ssl'),
        request_hooks=[RequestPrinter()],
        response_hooks=[ResponsePrinter()]
    )

    # Request the password for the user
    # but don't show it (because it's a password)
    # though we are printing the request/response bodies so ...
    password = getpass.getpass('Password for {}: '.format(username))

    print('\n\n')

    try:
        # Create our request body as a dictionary
        # The helpsocial will handle serializing the
        # dictionary to the proper json.
        body = {
            'username': username,
            'password': password
        }

        # Call the helpsocial.post method directly
        # passing the path to the authentication resource ('tokens'),
        # the authentication provider,
        # and the json body.
        #
        # In the short hand helpers methods, such as helpsocial.authenticate
        # the helpsocial will handle setting up the default authentication.
        # The default authentication may still be overridden using
        # the auth parameter.
        response = client.post('tokens',
                               json=body,
                               auth=ApplicationAuth(
                                   data_get(config, 'auth.auth_scope'),
                                   data_get(config, 'auth.api_key')
                               ))

        # Retrieve the user's authentication token
        # from the json response.
        value = data_get(response.json(), 'data.token.value')

        print('\n\nPulled user authentication token'
              'from data.token.value.')
        print('TOKEN: {}'.format(value))
    except ApiException as ex:
        print('\n\n{} - {}'.format(
            ex.__class__.__name__,
            ex.message,
        ))


if __name__ == '__main__':
    parser = ArgumentParser(
        prog='auth',
        description='Performs the authentication requests for the '
                    'specified user. '
    )

    parser.add_argument(
        'username',
        help='The username for the user to authenticate.'
    )

    parser.add_argument(
        '--config',
        help='Path to json configuration file.',
        default=join(dirname(abspath(__file__)), '.config.json')
    )

    args = vars(parser.parse_args())

    username = args['username']
    del args['username']

    main(username, **args)

