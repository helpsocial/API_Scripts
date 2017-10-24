# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

try:
    import ujson as json
except ImportError:
    import json

from requests import Request, Session
from sseclient import SSEClient
from threading import Thread
from time import sleep

from .auth import ApplicationAuth, UserAuth, SSEAuth
from .decorators import authenticate, require_auth
from .exceptions import ApiException, AuthenticationException, BadRequestException, ForbiddenException
from .utils import data_get, is_timeout

API_HOST = 'api.helpsocial.com'
API_VERSION = '2.0'


class Api(object):
    """TODO

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
        """TODO

        :param token:
        """

        self.user_token = token

    def register_event_hook(self, event, hook):
        """TODO

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
        """TODO

        :param path:
        :param params:
        :param auth:
        :param requests_kwargs:
        :rtype: requests.Response
        :return: :class:`Response <Response>` object
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
        :rtype: requests.Response
        :return: :class:`Response <Response>` object
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
        """TODO

        :param path:
        :param params:
        :param json:
        :param auth:
        :param requests_kwargs:
        :rtype: requests.Response
        :return: :class:`Response <Response>` object
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
        """TODO

        :param path:
        :param params:
        :param json:
        :param auth:
        :param requests_kwargs:
        :rtype: requests.Response
        :return: :class:`Response <Response>` object
        :raises ApiException:
        """

        uri = self.get_request_uri(path)
        return self.__execute(
                Request('DELETE', uri, params=params, json=json, auth=auth),
                **requests_kwargs
        )

    def get_request_uri(self, path):
        """TODO

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
        """TODO

        :return: :class:`BaseAuth <BaseAuth>` object
        :rtype: requests.BaseAuth
        """

        if self.user_token is None:
            return ApplicationAuth(self.auth_scope, self.api_key)
        return UserAuth(self.auth_scope,self.api_key, self.user_token)

    def __execute(self, request, **requests_kwargs):
        """TODO

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
    """TODO

    """

    def authenticate(self, username, password):
        """TODO

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


class StreamingConnectClient(Api):
    """TODO

    """

    def __init__(self,
                 auth_scope, api_key, dispatcher,
                 user_token=None,
                 host=None, ssl=None, version=None,
                 request_hooks=None, response_hooks=None):
        # initialize api
        super().__init__(auth_scope, api_key, user_token=user_token,
                         host=host, ssl=ssl, version=version,
                         request_hooks=request_hooks,
                         response_hooks=response_hooks)
        # ensure a dispatcher has been defined
        # for the client
        self._dispatchers = [dispatcher]
        self.running = False

    # def add_dispatcher(self, dispatcher):
    #     pass
    #
    # def remove_dispatcher(self, dispatcher):
    #     pass
    #
    # def add_connection_event_listener(self, listener):
    #     pass

    @authenticate
    def get_sse_authorization(self, auth=None, user=None):
        """TODO

        :param user:
        :param auth:
        :return:
        """

        params = None if user is None else {'user': user}
        response = self.get('streams/sse/authorization',
                            params=params,
                            auth=auth)
        return data_get(response.json(), 'data.authorization')

    @authenticate
    def conversations(self, params=None, auth=None, async=False):
        """TODO

        :param async:
        :param params:
        :param auth:
        :return:
        """

        if self.running:
            raise RuntimeError('stream already running')
        self._start('streams/conversations',
                    auth,
                    params=params,
                    async=async,
                    sse=False)

    @authenticate
    def activities(self, params=None, auth=None, async=False):
        """TODO

        :param async:
        :param params:
        :param auth:
        :return:
        """

        if self.running:
            raise RuntimeError('stream already running')
        self._start('streams/activity',
                    auth,
                    params=params,
                    async=async,
                    sse=False)

    @authenticate
    def events(self, params=None, auth=None, async=False):
        """TODO

        :param async:
        :param params:
        :param auth:
        :return:
        """

        if self.running:
            raise RuntimeError('stream already running')
        self._start('streams/activity',
                    auth,
                    params=params,
                    async=async,
                    sse=False)

    def sse(self, authorization, params=None, async=False):
        """TODO

        :param async:
        :param authorization:
        :param params:
        :return:
        """

        if self.running:
            raise RuntimeError('stream already running')
        self._start('streams/sse',
                    SSEAuth(self.auth_scope, self.api_key, authorization),
                    params=params,
                    async=async,
                    sse=True)

    def _start(self, path, auth, params=None, async=False, sse=False):
        """TODO

        :param path:
        :param auth:
        :param params:
        :param async:
        :param sse:
        :return:
        """

        self.running = True
        if async:
            self._thread = Thread(target=self._run,
                                  args=(path, auth,),
                                  kwargs={'params': params, 'sse': sse})
            self._thread.start()
        else:
            self._run(path, auth, params=params, sse=sse)

    def _run(self, path, auth, params=None, sse=False):
        """TODO


        :param path:
        :param auth:
        :param params:
        :param sse:
        :return:
        """

        connection = None
        initial_connection = True
        disconnect_counter = 0
        backoff_limit_seconds = 300

        try:
            while self.running:
                try:
                    connection = self.__open_stream(path, auth, params=params)
                    initial_connection = False
                    disconnect_counter = 0
                except (AuthenticationException,
                        ForbiddenException,
                        BadRequestException) as ex:
                    # If we encounter any of these exceptions there
                    # is no way that we will be able to make the
                    # connection making the request as is.
                    raise ex
                except Exception as ex:
                    if initial_connection:
                        # The initial attempt to connect to stream
                        # has failed for some reason.
                        raise ex
                    # The stream has been interrupted
                    # and we should attempt to reconnect. We apply
                    # an exponential back off to not overload the
                    # server and allow it time to heal.
                    if not self.running:
                        break
                    disconnect_counter += 1
                    sleep(min(2 ** disconnect_counter, backoff_limit_seconds))
                    continue

                if not self.running:
                    break

                try:
                    if sse:
                        self.__stream_sse(connection)
                    else:
                        self.__stream_json(connection)
                except Exception as ex:
                    if not is_timeout(ex):
                        # a fatal exception has occurred
                        raise ex
                    disconnect_counter += 1
                    sleep(min(2 ** disconnect_counter, backoff_limit_seconds))
        finally:
            # clean up the allocated connection object
            # and make sure we've flagged that we're no longer
            # running
            self.running = False
            if connection:
                connection.close()

    def __open_stream(self, path, auth, params=None):
        """TODO

        :param path:
        :param params:
        :param auth:
        :return:
        """

        response = self.get(path, params, auth, stream=True)
        if response.status_code != 200:
            errors = data_get(response.json(), 'data.errors')
            status = response.status_code
            raise ApiException('Failed to start stream', status, errors)

        if response.encoding is None:
            response.encoding = 'utf-8'
        return response

    def __stream_sse(self, connection):
        """TODO

        :param connection:
        :return:
        """

        for event in SSEClient(connection):
            if not self.running:
                break
            self.__dispatch(event)

    def __stream_json(self, connection):
        """TODO

        :param connection:
        :return:
        """

        for line in connection.iter_lines(decode_unicode=True):
            if not self.running:
                break
            self.__dispatch(line)
            decoded = json.loads(line)
            if 'complete' in decoded:
                # The bounded stream has completed
                break

    def __dispatch(self, data):
        """
        TODO

        :param data:
        :return:
        """

        for dispatcher in self._dispatchers:
            dispatcher.dispatch(data)
