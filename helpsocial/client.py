# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

from requests import Request, Session
from sseclient import SSEClient

from .auth import ApplicationAuth, UserAuth, SSEAuth
from .exceptions import ApiException
from .utils import data_get

from .decorators import authenticate, require_auth

API_HOST = 'api.helpsocial.com'
API_VERSION = '2.0'


class Api(object):
    """
    TODO
    """
    def __init__(self,
                 auth_scope, api_key,
                 user_token=None,
                 host=None, ssl=None, version=None,
                 request_hooks=None, response_hooks=None):
        # set defaults
        host = API_HOST if host is None else host
        version = API_VERSION if version is None else version
        ssl = True if ssl is None else ssl
        request_hooks = [] if request_hooks is None else request_hooks
        response_hooks = [] if response_hooks is None else response_hooks

        self.api_key = api_key
        self.auth_scope = auth_scope
        self.user_token = user_token

        self._http = Session()
        self._api_host = host
        self._api_version = version
        self._ssl = ssl
        self._request_hooks = request_hooks
        self._response_hooks = response_hooks

    def set_user_token(self, token):
        """
        TODO
        :param token:
        """
        self.user_token = token

    def register_event_hook(self, event, hook):
        """
        TODO
        :param event:
        :param hook:
        """
        if not hasattr(hook, '__call__') or not callable(hook):
            raise ValueError('callable required.')

        if event == 'request':
            self._response_hooks.append(hook)
        elif event == 'response:':
            self._response_hooks.append(hook)
        else:
            raise ValueError('event must be request or response')

    @require_auth
    def get(self, path, params=None, auth=None, **requests_kwargs):
        """
        TODO
        :param path:
        :param params:
        :param auth:
        :param requests_kwargs:
        :return: :class:`Response <Response>` object
        :rtype: requests.Response
        :raises ApiException:
        """
        uri = self.get_request_uri(path)
        return self.__execute(
            Request('GET', uri, params=params, auth=auth),
            **requests_kwargs
        )

    @require_auth
    def put(self, path, params=None, json=None,
            auth=None, **requests_kwargs):
        """TODO:
        :param path:
        :param params:
        :param json:
        :param auth:
        :param requests_kwargs:
        :return: :class:`Response <Response>` object
        :rtype: requests.Response
        :raises ApiException:
        """
        uri = self.get_request_uri(path)
        return self.__execute(
                Request('PUT', uri, params=params, json=json, auth=auth),
                **requests_kwargs
        )

    @require_auth
    def post(self, path, params=None, json=None,
             auth=None, **requests_kwargs):
        """
        TODO
        :param path:
        :param params:
        :param json:
        :param auth:
        :param requests_kwargs:
        :return: :class:`Response <Response>` object
        :rtype: requests.Response
        :raises ApiException:
        """
        uri = self.get_request_uri(path)
        return self.__execute(
                Request('POST', uri, params=params, json=json, auth=auth),
                **requests_kwargs
        )

    @require_auth
    def delete(self, path, params=None, json=None,
               auth=None, **requests_kwargs):
        """
        TODO
        :param path:
        :param params:
        :param json:
        :param auth:
        :param requests_kwargs:
        :return: :class:`Response <Response>` object
        :rtype: requests.Response
        :raises ApiException:
        """
        uri = self.get_request_uri(path)
        return self.__execute(
                Request('DELETE', uri, params=params, json=json, auth=auth),
                **requests_kwargs
        )

    def get_request_uri(self, path):
        """
        TODO
        :param path:
        :return string:
        :raises ApiException:
        """
        scheme = 'https' if self._ssl else 'http'
        return '{scheme}://{host}/{version}/{path}'.format(
            scheme=scheme,
            host=self._api_host,
            version=self._api_version,
            path=path.lstrip('/')
        )

    def get_auth(self):
        """
        TODO
        :return: :class:`BaseAuth <BaseAuth>` object
        :rtype: requests.BaseAuth
        """
        if self.user_token is None:
            return ApplicationAuth(self.auth_scope, self.api_key)
        return UserAuth(self.auth_scope,self.api_key, self.user_token)

    def __execute(self, request, **requests_kwargs):
        """
        TODO
        :param request:
        :param requests_kwargs:
        :return: :class:`Response <Response>` object
        :rtype: requests.Response
        :raises ApiException:
        """
        prepared = request.prepare()
        try:
            for hook in self._request_hooks:
                hook(prepared)
        finally:
            response = self._http.send(prepared, **requests_kwargs)

        try:
            for hook in self._response_hooks:
                hook(prepared, response)
        finally:
            if response.status_code >= 400:
                raise ApiException.make(response)
            return response


class RestConnectClient(Api):
    """
    TODO
    """
    def authenticate(self, username, password):
        """
        TODO
        :param username:
        :param password:
        :return:
        :rtype: dict
        """
        auth = ApplicationAuth(self.auth_scope, self.api_key)
        body = {
            'username': username,
            'password': password,
        }

        response = self.post('tokens', json=body, auth=auth)

        return data_get(response.json(), 'data.token')


class StreamingConnectClient(RestConnectClient):
    """
    TODO
    """
    _stream_kwargs = {'stream': True}

    def __init__(self,
                 auth_scope, api_key, user_token, dispatcher,
                 host=None, ssl=None, version=None,
                 request_hooks=None, response_hooks=None):
        # setup helpsocial with call to parent
        super().__init__(auth_scope, api_key, user_token=user_token,
                         host=host, ssl=ssl, version=version,
                         request_hooks=request_hooks,
                         response_hooks=response_hooks)
        self._dispatcher = dispatcher

    @authenticate
    def get_sse_authentication(self, auth=None):
        """
        TODO
        :param auth:
        :return:
        """
        response = self.__open_stream('streams/sse/authorization', auth=auth)
        self.__stream(response)

    @authenticate
    def conversations(self, params=None, auth=None):
        """
        TODO
        :param params:
        :param auth:
        :return:
        """
        response = self.__open_stream('streams/conversation', params=params, auth=auth)
        self.__stream(response)

    @authenticate
    def activities(self, params=None, auth=None):
        """
        TODO
        :param params:
        :param auth:
        :return:
        """
        response = self.__open_stream('streams/activity', params=params, auth=auth)
        self.__stream(response)

    @authenticate
    def events(self, params=None, auth=None):
        """
        TODO
        :param params:
        :param auth:
        :return:
        """
        response = self.__open_stream('streams/event', params=params, auth=auth)
        self.__stream(response)

    def sse(self, authorization, params=None):
        """
        TODO
        :param params:
        :return:
        """
        auth = SSEAuth(self.auth_scope, self.api_key, authorization)
        response = self.__open_stream('streams/sse', params=params, auth=auth)
        sse = SSEClient(response)
        try:
            for event in sse.events():
                self._dispatcher.dispatch(event)
        finally:
            sse.close()

    def __open_stream(self, path, params=None, auth=None):
        """
        TODO
        :param path:
        :param params:
        :param auth:
        :return:
        """
        response = self.get(path, params, auth, **self._stream_kwargs)
        if response.status_code != 200:
            raise ApiException(
                'Failed to start stream',
                response.status_code,
                data_get(response.json(), 'data.errors')
            )
        if response.encoding is None:
            response.encoding = 'utf-8'
        return response

    def __stream(self, response):
        """
        TODO
        :param response:
        :return:
        """
        for line in response.iter_lines(decode_unicode=True):
            self._dispatcher.dispatch(line)
