# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import json

from functools import reduce
from requests import Timeout
from ssl import SSLError


def data_get(values, key=None, default=None):
    """Retrieve the key from the ``values`` dictionary
    using a "dot notation" key string.

    :type values: dict
    :param values: the values dict containing the key

    :type key: string
    :param key: a dot notation key string used to access the dict

    :param default: the default value for the key if not found

    :return: the key value or ``default`` if not found
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
    """Print the details of the request in a human readable
    form to the console.

    :type request: requests.PreparedRequest
    :param request: :class:`PreparedRequest <PreparedRequest>` object to print
    """

    print('{}\n> {} {}\n{}\n>\n{}'.format(
            '----------START----------',
            request.method,
            request.url,
            _format_headers(request.headers, '> '),
            _format_json(json.loads(request.body), 2, '> ')
    ))


def print_response(response, with_body=True):
    """Print the details of the response in a human readable
    form to the console. If the response is streaming the body
    the ``with_body`` flag should be set to False. If not, then
    this call will block until the entire response body is read.

    :type response: requests.Response
    :param response: :class:`Response <Response>` object to print

    :type with_body: bool
    :param with_body: print the response body, this flag SHOULD be set when
    the initial request is streaming the response.
    """

    body = _format_json(response.json(), 2, '< ') if with_body else None
    print('< Status: {}\n{}\n<\n{}\n{}'.format(
        response.status_code,
        _format_headers(response.headers, '< '),
        body,
        '----------END----------'
    ))


def is_timeout(exc):
    """Checks if the exception is a known request timeout exception.

    :type exc: BaseException
    :param exc: the exception to verify type of

    :rtype: bool
    :return:
    """

    if isinstance(exc, Timeout):
        return True
    if not isinstance(exc, SSLError):
        return False
    return exc.args and 'time out' in exc.args[0]


def _format_json(data, indent=None, line_prefix=None):
    """Format the json data applying a prefix to each line if defined.

    :type data: dict
    :param data:

    :type indent: int
    :param indent:

    :type line_prefix: string
    :param line_prefix:

    :rtype: string
    :return:
    """

    if line_prefix is None:
        return json.dumps(data, indent=indent)

    return '\n'.join('{}{}'.format(line_prefix, line)
                     for line
                     in json.dumps(data, indent=indent).splitlines())


def _format_headers(headers, line_prefix=None):
    """Create a human readable formatted string of headers.

    :type headers: dict
    :param headers:

    :type line_prefix: string
    :param line_prefix:

    :rtype: string
    :return:
    """

    return '\n'.join('{}{}: {}'.format(line_prefix, k, v)
                     for k, v
                     in headers.items())
