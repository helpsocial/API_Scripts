# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

def require_auth(fn):
    """
    TODO
    :param fn:
    :return:
    """
    def wrapper(*args, **kwargs):
        if 'auth' not in kwargs:
            raise RuntimeError('auth required.')
        return fn(*args, **kwargs)
    return wrapper


def authenticate(fn):
    """
    TODO
    :param fn:
    :return:
    """
    def wrapper(instance, *args, **kwargs):
        if 'auth' not in kwargs or kwargs['auth'] is None:
            kwargs['auth'] = instance.get_auth()
        return fn(instance, *args, **kwargs)
    return wrapper

