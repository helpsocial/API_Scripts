# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import json

# from multiprocessing import Process
from requests import Request, Session
from sseclient import SSEClient
from threading import Thread
from time import sleep, time

from .auth import ApplicationAuth, UserAuth, SSEAuth
from .decorators import set_auth, require_auth
from .exceptions import ApiException, AuthenticationException, BadRequestException, ForbiddenException
from .utils import data_get, is_timeout

API_HOST = 'api.helpsocial.com'
API_VERSION = '2.0'


class Api(object):
    """Base Api class wraps the http transport layer with decorators for
    interaction with the HelpSocial Connect Api.

    It is possible to use this class directly, however it is advised that the
    RestConnectClient be used for the convenience methods it supplies.

    :type auth_scope: string
    :param auth_scope: the client auth scope to be used in authentication.

    :type api_key: string
    :param api_key: the api key to be used by the client in order to authenticate requests.

    :type user_token: string
    :param user_token: the user's auth token that should be used to authenticate a request.

    :type host: string
    :param host: the api host to connect to. default ``API_HOST``.

    :type ssl: bool
    :param ssl: should the client connect over ssl. default True.

    :type version: string
    :param version: the api version. default ``2.0``

    :type request_hooks: list
    :param request_hooks: a list of callable request hooks that should be called before the request executes.

    :type response_hooks: list
    :param response_hooks: a list of callabke response hooks that should be called after the request completes.
    """

    def __init__(self,
                 auth_scope, api_key,
                 user_token=None,
                 host=None, ssl=True, version=None,
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
        """Set the default user token for the client."""

        self.user_token = token

    def register_event_hook(self, event, hook):
        """Register a new event hook.

        :type event: string
        :param event: the event [request, or response] to register the hook for.

        :type hook: callable
        :param hook: the action to call on the specified event.
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
        """Perform a Http GET request on the api at the specified path.

        :param path:
        :param params:
        :param auth:
        :param requests_kwargs:
        :rtype: requests.Response
        :return: :class:`Response <Response>` object
        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        kwargs = Api._pull_request_kwargs(requests_kwargs)
        return self.__execute(
            Request('GET', self.get_request_uri(path), params=params, auth=auth, **kwargs),
            **requests_kwargs
        )

    @require_auth
    def put(self, path, params=None, json=None,
            auth=None, **requests_kwargs):
        """Perform a Http PUT request on the api at the specified path.

        :param path:
        :param params:
        :param json:
        :param auth:
        :param requests_kwargs:
        :rtype: requests.Response
        :return: :class:`Response <Response>` object
        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        kwargs = Api._pull_request_kwargs(requests_kwargs)
        return self.__execute(
                Request('PUT', self.get_request_uri(path), params=params, json=json, auth=auth, **kwargs),
                **requests_kwargs
        )

    @require_auth
    def post(self, path, params=None, json=None,
             auth=None, **requests_kwargs):
        """Perform a Http POST request on the api at the specified path.

        :param path:
        :param params:
        :param json:
        :param auth:
        :param requests_kwargs:
        :rtype: requests.Response
        :return: :class:`Response <Response>` object
        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        kwargs = Api._pull_request_kwargs(requests_kwargs)
        return self.__execute(
                Request('POST', self.get_request_uri(path), params=params, json=json, auth=auth, **kwargs),
                **requests_kwargs
        )

    @require_auth
    def delete(self, path, params=None, json=None,
               auth=None, **requests_kwargs):
        """Perform a Http DELETE request on the api at the specified path.

        :param path:
        :param params:
        :param json:
        :param auth:
        :param requests_kwargs:
        :rtype: requests.Response
        :return: :class:`Response <Response>` object
        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        kwargs = Api._pull_request_kwargs(requests_kwargs)
        return self.__execute(
                Request('DELETE', self.get_request_uri(path), params=params, json=json, auth=auth, **kwargs),
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

    @staticmethod
    def has_accept_header(headers):
        """Check if the headers contain an accept header.

        :type headers: dict
        :param headers:
        """

        for key in headers.keys():
            if key.lower() == 'accept':
                return True
        return False

    @staticmethod
    def _pull_request_kwargs(requests_kwargs):
        """Remove non server request keyword arguments from the arguments list.

        :type requests_kwargs: dict
        :param requests_kwargs:
        :return:
        """

        keys = ['headers', 'files', 'data', 'cookies', 'hooks']
        kwargs = {}
        for key in keys:
            if key in requests_kwargs:
                kwargs[key] = requests_kwargs[key]
                del requests_kwargs[key]
        return kwargs

    def __execute(self, request, **requests_kwargs):
        """TODO

        :param request:
        :param requests_kwargs:
        :return: :class:`Response <Response>` object
        :rtype: requests.Response
        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        if 'headers' not in request.headers.keys():
            request.headers = {'Accept': 'application/json'}
        elif not Api.has_accept_header(requests_kwargs['headers']):
            request.headers['Accept'] = 'application/json'

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
    """HelpSocial Connect Api rest client. Provides convenience methods for
    available api actions on top of the default http transport methods
    defined by :class:`Api <Api>`.
    """

    def authenticate(self, username, password):
        """TODO

        :param username:
        :param password:
        :return:
        :rtype: dict
        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        auth = ApplicationAuth(self.auth_scope, self.api_key)
        body = {
            'username': username,
            'password': password,
        }

        response = self.post('tokens', json=body, auth=auth)

        return data_get(response.json(), 'data.token')

    @set_auth
    def get_sse_authorization(self, auth=None):
        """TODO
        :type auth: requests.BaseAuth
        :param auth:

        :rtype: string
        :return: authorization code

        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        return data_get(
            self.get('streams/sse/authorization', auth=auth).json(),
            'data.authorization'
        )


class StreamingConnectClient(Api):
    """HelpSocial Connect Api streaming client. Provides convenience methods
    for the available streams produced by the Connection Api.

    :type auth_scope: string
    :param auth_scope: the client auth scope to be used in authentication.

    :type api_key: string
    :param api_key: the api key to be used by the client in order to authenticate requests.

    :type dispatcher: Dispatcher
    :param dispatcher: the dispatcher is responsible for handling each stream event.

    :type user_token: string
    :param user_token: the user's auth token that should be used to authenticate a request.

    :type host: string
    :param host: the api host to connect to. default ``API_HOST``.

    :type ssl: bool
    :param ssl: should the client connect over ssl. default True.

    :type version: string
    :param version: the api version. default ``2.0``

    :type request_hooks: list
    :param request_hooks: a list of callable request hooks that should be called before the request executes.

    :type response_hooks: list
    :param response_hooks: a list of callabke response hooks that should be called after the request completes.
    """

    _sse_stream_headers = {'Accept': 'text/event-stream'}

    _json_stream_headers = {'Accept:' 'application/x-json-stream'}

    def __init__(self,
                 auth_scope, api_key, dispatcher,
                 user_token=None,
                 host=None, ssl=True, version=None,
                 request_hooks=None, response_hooks=None):
        # initialize api
        super().__init__(auth_scope, api_key, user_token=user_token,
                         host=host, ssl=ssl, version=version,
                         request_hooks=request_hooks,
                         response_hooks=response_hooks)
        # ensure a dispatcher has been defined
        # for the client
        self._dispatchers = [dispatcher]
        self._running = False

    @set_auth
    def conversations(self, params=None, auth=None, async=False):
        """TODO

        :param async:
        :param params:
        :param auth:
        :return:
        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        if self._running:
            raise RuntimeError('stream already running')
        self._start('streams/conversations',
                    auth,
                    params=params,
                    headers=self._json_stream_headers,
                    async=async,
                    sse=False)

    @set_auth
    def activities(self, params=None, auth=None, async=False):
        """TODO

        :param async:
        :param params:
        :param auth:
        :return:
        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        if self._running:
            raise RuntimeError('stream already running')
        self._start('streams/activity',
                    auth,
                    params=params,
                    headers=self._json_stream_headers,
                    async=async,
                    sse=False)

    @set_auth
    def events(self, params=None, auth=None, async=False):
        """TODO

        :param async:
        :param params:
        :param auth:
        :return:
        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        if self._running:
            raise RuntimeError('stream already running')
        self._start('streams/activity',
                    auth,
                    params=params,
                    headers=self._json_stream_headers,
                    async=async,
                    sse=False)

    def sse(self, authorization, params=None, async=False):
        """TODO

        :param async:
        :param authorization:
        :param params:
        :return:
        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        if self._running:
            raise RuntimeError('stream already running')
        self._start('streams/sse',
                    SSEAuth(authorization),
                    params=params,
                    headers=self._sse_stream_headers,
                    async=async,
                    sse=True)

    def is_alive(self):
        return self._running

    def shutdown(self):
        if not self._running:
            return
        self._running = False

        if hasattr(self, '_sse') and self._sse:
            self._sse.close()

        if hasattr(self, '_thread') and self._thread:
            start = time()
            while self._thread.is_alive():
                if 30 < (time() - start):
                    break
                sleep(1)

    def _start(self, path, auth, params=None, headers=None, async=False, sse=False):
        """TODO

        :param path:
        :param auth:
        :param params:
        :param async:
        :param sse:
        :return:
        """

        self._running = True
        if async:
            self._thread = Thread(target=self._run,
                                  args=(path, auth,),
                                  kwargs={'headers': headers, 'params': params, 'sse': sse})
            self._thread.start()
        else:
            self._run(path, auth, params=params, sse=sse)

    def _run(self, path, auth, params=None, headers=None, sse=False):
        """Run the desired stream.

        :type path: string
        :param path: the path to the streaming resource.

        :type auth: requests.AuthBase
        :param auth: the authentication required for the streaming resource.

        :type params: dict
        :param params: request parameters

        :type sse: bool
        :param sse: is this a stream of server sent events
        """

        connection = None
        initial_connection = True
        disconnect_counter = 0
        backoff_limit_seconds = 300

        try:
            while self._running:
                try:
                    connection = self._open_stream(path, auth, params=params, headers=headers)
                    initial_connection = False
                    disconnect_counter = 0
                except (AuthenticationException,
                        ForbiddenException,
                        BadRequestException) as ex:
                    # If we encounter any of these exceptions there
                    # is no way that we will be able to make the
                    # connection making the request as is.
                    raise ex
                except KeyboardInterrupt:
                    # User terminated console app
                    break
                except Exception as ex:
                    if initial_connection:
                        # The initial attempt to connect to stream
                        # has failed for some reason.
                        raise ex
                    # The stream has been interrupted
                    # and we should attempt to reconnect. We apply
                    # an exponential back off to not overload the
                    # server and allow it time to heal.
                    if not self._running:
                        break
                    disconnect_counter += 1
                    sleep(min(2 ** disconnect_counter, backoff_limit_seconds))
                    continue

                if not self._running:
                    break

                try:
                    if sse:
                        self._stream_sse(connection)
                    else:
                        self._stream_json(connection)
                except KeyboardInterrupt:
                    # User terminated console app
                    break
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
            self._running = False
            if connection:
                connection.close()

    def _open_stream(self, path, auth, params=None, headers=None):
        """Open the streaming connection.

        :type path: string
        :param path:

        :type auth: requests.AuthBase
        :param auth:

        :type params: dict
        :param params:

        :rtype: requests.Response
        :return: the connected request response
        :raises ApiException:
        """

        response = self.get(path, params=params, auth=auth, stream=True, headers=headers)
        if response.status_code != 200:
            errors = data_get(response.json(), 'data.errors')
            status = response.status_code
            raise ApiException('Failed to start stream', status, errors)

        if response.encoding is None:
            response.encoding = 'utf-8'
        return response

    def _stream_sse(self, connection):
        """Handle (parse) a stream of Server Sent Events

        :type connection: requests.Response
        :param connection:
        """

        self._sse = None
        try:
            self._sse = SSEClient(connection)
            for event in self._sse.events():
                if not self._running:
                    break
                self._dispatch(event.data)
        except AttributeError as exc:
            # if not running then we caused the except by closing the
            # underlying http connection. The SSEClient event looping
            # does not allow for arbitrary closures between any read, since
            # an event is only yielded when data is received.
            if self._running:
                raise exc
        finally:
            if self._sse:
                self._sse.close()

    def _stream_json(self, connection):
        """Handle (parse) a stream of newline delimited json objects.

        :type connection: requests.Response
        :param connection:
        """

        for line in connection.iter_lines(decode_unicode=True):
            if not self._running:
                break
            self._dispatch(line)
            decoded = json.loads(line)
            if 'complete' in decoded:
                # The bounded stream has completed
                break

    def _dispatch(self, data):
        """Dispatch the stream data using each registered dispatcher.

        :param data:
        """

        for dispatcher in self._dispatchers:
            dispatcher.dispatch(data)
