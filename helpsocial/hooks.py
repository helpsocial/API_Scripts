# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

from .utils import print_request, print_response


class Hook:
    """TODO

    """

    pass


class RequestHook(Hook):
    """TODO

    """

    def __call__(self, request):
        """TODO

        :param request:
        :return:
        """

        pass


class RequestPrinter(RequestHook):
    """TODO

    """

    def __call__(self, request):
        """TODO

        :param request:
        :return:
        """

        print_request(request)


class ResponseHook(Hook):
    """TODO

    """

    def __call__(self, request, response):
        """TODO

        :param request:
        :param response:
        :return:
        """

        pass


class ResponsePrinter(ResponseHook):
    """TODO

    """

    def __init__(self, streaming=False):
        self._streaming = streaming

    def __call__(self, request, response):
        """TODO

        :param request:
        :param response:
        :return:
        """

        print_response(response, not self._streaming)
