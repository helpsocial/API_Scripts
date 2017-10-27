# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

try:
    import ujson as json
except ImportError:
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


def join(sequence, join_char=''):
    """Implodes a sequence of string into a single string

    :type sequence: iterable
    :param sequence:

    :type join_char: string
    :param join_char:
    """
    return reduce(lambda x, y: x + join_char + y, sequence)


def is_json(request):
    if 'Content-Type' not in request.headers:
        return False
    return request.headers['Content-Type'][:-5] in ['/json', '+json']


def print_request(request):
    """Print the details of the request in a human readable
    form to the console.

    :type request: requests.PreparedRequest
    :param request: request object to print
    """

    body = '' if not is_json(request) else _format_json(json.loads(request.body), 2, '> ')

    print('{}\n> {} {}\n{}\n>\n{}'.format(
            '----------START----------',
            request.method,
            request.url,
            _format_headers(request.headers, '> '),
            body
    ))


def print_response(response, streaming=False):
    """Print the details of the response in a human readable
    form to the console. If the response is streaming the body
    the ``with_body`` flag should be set to False. If not, then
    this call will block until the entire response body is read.

    :type response: requests.Response
    :param response: response object to print

    :type streaming: bool
    :param streaming: Flags if the initial request expects a streamed response.
    """

    complete = not streaming or not response.ok
    body = '' if not complete else _format_json(response.json(), 2, '< ')
    print('< Status: {}\n{}\n<\n{}'.format(
        response.status_code,
        _format_headers(response.headers, '< '),
        body,
    ))
    if complete:
        print('----------END----------')


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

    if not data:
        return ''

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
