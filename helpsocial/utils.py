
from functools import reduce
import json


def data_get(values, key=None, default=None):
    """
    TODO
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
    """
    TODO
    :param request:
    :return:
    """
    print('{}\n> {} {}\n{}\n>\n{}\n'.format(
            '----------START----------',
            request.method,
            request.url,
            _format_headers(request.headers, '> '),
            _format_json(json.loads(request.body), 2, '> ')
    ))


def print_response(response):
    """
    TODO
    :param response:
    :return:
    """
    print('< Status: {}\n{}\n<\n{}\n{}'.format(
        response.status_code,
        _format_headers(response.headers, '< '),
        _format_json(response.json(), 2, '< '),
        '----------END----------'
    ))


def _format_json(data, indent=None, prefix=None):
    """
    TODO
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
    """
    TODO
    :param headers:
    :param prefix:
    :return:
    """
    return '\n'.join('{}{}: {}'.format(prefix, k, v)
                     for k, v
                     in headers.items())
