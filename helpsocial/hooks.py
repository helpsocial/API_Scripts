# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

from .utils import print_request, print_response


class Hook:
    """Base Hook class which all http request hooks should extend"""

    def __call__(self, *args, **kwargs):
        raise NotImplementedError('Http hooks must be callable.')


class RequestHook(Hook):
    """The RequestHook is called before the request is sent through the
    requests Http transport layer, giving the developer access to the
    request in order to log or make modifications to the request.
    """

    def __call__(self, request):
        """Modify or inspect the PreparedRequest instance before it is sent.

        :type request: requests.PreparedRequest
        :param request: A :class:`requests.PreparedRequest <requests.PreparedRequest>` instance.
        """

        pass


class RequestPrinter(RequestHook):
    """Request console print hook."""

    def __call__(self, request):
        """Prints the request to the console.

        :type request: requests.PreparedRequest
        :param request:

        :rtype: requests.PreparedRequest
        :return:
        """

        print_request(request)
        return request


class ResponseHook(Hook):
    """The ResponseHook is called after the request has returned from the server
    but before it is passed back from the client. This lets the developer
    perform modifications or inspections of the response.
    """

    def __call__(self, request, response):
        """Inspect the request and modify or inspect the response after
        the request has returned from the server.

        :type request: requests.PreparedRequest
        :param request: The :class:`requests.PreparedRequest <requests.PreparedRequest> instance
        that generated the response.

        :type response: requests.Response
        :param response: The :class:`requests.Response <requests.Response> returned
        by the server.
        """

        pass


class ResponsePrinter(ResponseHook):
    """Response console print hook."""

    def __call__(self, request, response):
        """Prints the response to the console.

        :type request: requests.PreparedRequest
        :param request: The :class:`requests.PreparedRequest <requests.PreparedRequest> instance
        that generated the response.

        :type response: requests.Response
        :param response: The :class:`requests.Response <requests.Response> returned
        by the server.
        """

        print_response(response)


class StreamResponsePrinter(ResponseHook):
    """Streaming request response print hook."""

    def __call__(self, request, response):
        """Prints only the immediately available response data to the console.

        :type request: requests.PreparedRequest
        :param request: The :class:`requests.PreparedRequest <requests.PreparedRequest> instance
        that generated the response.

        :type response: requests.Response
        :param response: The :class:`requests.Response <requests.Response> returned
        by the server.
        """

        print_response(response, streaming=True)
