# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import json

from functools import reduce
from requests import Timeout
from ssl import SSLError


def data_get(values, key=None, default=None):
    """TODO

    :param values:
    :param key:
    :param default:
    :return:
    """

    if values is None:
        raise ValueError('values must be dict')

    if key is None:
        return values

    try:
        value = reduce(dict.get, key.split('.'), values)
    except AttributeError:
        return default

    if value is None:
        return default
    return value


def print_request(request):
    """TODO

    :param request:
    :return:
    """

    print('{}\n> {} {}\n{}\n>\n{}'.format(
            '----------START----------',
            request.method,
            request.url,
            _format_headers(request.headers, '> '),
            _format_json(json.loads(request.body), 2, '> ')
    ))


def print_response(response, with_body=True):
    """TODO

    :param with_body:
    :param response:
    :return:
    """

    body = _format_json(response.json(), 2, '< ') if with_body else None
    print('< Status: {}\n{}\n<\n{}\n{}'.format(
        response.status_code,
        _format_headers(response.headers, '< '),
        body,
        '----------END----------'
    ))


def is_timeout(exc):
    """TODO

    :param exc:
    :return:
    """

    if isinstance(exc, Timeout):
        return True
    if not isinstance(exc, SSLError):
        return False
    return exc.args and 'time out' in exc.args[0]


def _format_json(data, indent=None, prefix=None):
    """TODO

    :param data:
    :param indent:
    :param prefix:
    :return:
    """

    if prefix is None:
        return json.dumps(data, indent=indent)

    return '\n'.join('{}{}'.format(prefix, line)
                     for line
                     in json.dumps(data, indent=indent).splitlines())


def _format_headers(headers, prefix=None):
    """TODO

    :param headers:
    :param prefix:
    :return:
    """

    return '\n'.join('{}{}: {}'.format(prefix, k, v)
                     for k, v
                     in headers.items())
