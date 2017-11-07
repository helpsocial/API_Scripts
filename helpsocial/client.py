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
from time import sleep, time

from .auth import ApplicationAuth, UserAuth, SSEAuth
from .decorators import require_auth, Authenticate
from .exceptions import ApiException, AuthenticationException, \
                        BadRequestException, ForbiddenException, \
                        NotFoundException
from .utils import data_get, is_timeout, join

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

    @staticmethod
    def process_params(params, csv_keys=None):
        """Filter the params keyword argument passed to the function.

        :type params dict
        :param params:

        :type csv_keys: list
        :param csv_keys:

        :rtype: dict
        :return: the filtered parameters
        """
        if params is None:
            return None

        csv_keys = [] if csv_keys is None else csv_keys
        filtered = params.copy()

        for (key, value) in params.items():
            if value is None:
                del filtered[key]
            elif key in csv_keys:
                filtered[key] = join(value, ',') if isinstance(value, list) else str(value)
            elif isinstance(value, bool):
                filtered[key] = int(value)
        return filtered

    def set_user_token(self, token):
        """Set the default user token for the client."""

        self.user_token = token

    def get_user_token(self):
        """

        :rtype: string
        :return:
        """
        return self.user_token

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

        :type path: string
        :param path:

        :type params: dict
        :param params:

        :type auth: requests.AuthBase
        :param auth:

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

        :type path: string
        :param path:

        :type params: dict
        :param params:

        :type json: dict
        :param json:

        :type auth: requests.AuthBase
        :param auth:

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

        :type path: string
        :param path:

        :type params: dict
        :param params:

        :type json: dict
        :param json:

        :type auth: requests.AuthBase
        :param auth:

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

        :type path: string
        :param path:

        :type params: dict
        :param params:

        :type json: dict
        :param json:

        :type auth: requests.AuthBase
        :param auth:

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
        """Retrieve the full url for the api request using the ``path``.

        :type path: string
        :param path: resource path

        :rtype: string
        :return: the full url

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
        """Auth factory for the client.

        :rtype: requests.AuthBase
        :return: :class:`AuthBase <AuthBase>` object
        """

        if self.user_token is None:
            return ApplicationAuth(self.auth_scope, self.api_key)
        return UserAuth(self.auth_scope,self.api_key, self.user_token)

    @staticmethod
    def has_accept_header(headers):
        """Check if the headers contain an accept header.

        :type headers: dict
        :param headers:

        :rtype: bool
        :return:
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

        :rtype: dict
        :return: the keyword arguments for a request instance
        """

        keys = ['headers', 'files', 'data', 'cookies', 'hooks']
        kwargs = {}
        for key in keys:
            if key in requests_kwargs:
                kwargs[key] = requests_kwargs[key]
                del requests_kwargs[key]
        return kwargs

    def __execute(self, request, **transport_kwargs):
        """Wrap the requests module send method in order to call
        any request (response) hooks defined.

        :type request: requests.Request
        :param request: :class:`requests.Request <requests.Request>` instance.

        :type transport_kwargs: dict
        :param transport_kwargs: keyword arguments for the transport layer

        :rtype: requests.Response
        :return: :class:`Response <Response>` object

        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        if 'headers' not in request.headers.keys():
            request.headers = {'Accept': 'application/json'}
        elif not Api.has_accept_header(transport_kwargs['headers']):
            request.headers['Accept'] = 'application/json'

        prepared = request.prepare()
        for hook in self._request_hooks:
            hook(prepared)

        http_error_exception = not transport_kwargs.get('http_errors', False)
        if 'http_errors' in transport_kwargs:
            del transport_kwargs['http_errors']

        response = self._http.send(prepared, **transport_kwargs)
        for hook in self._response_hooks:
            hook(prepared, response)

        if response.status_code >= 400 and http_error_exception:
            raise ApiException.make(response)
        return response


class RestConnectClient(Api):
    """HelpSocial Connect Api rest client. Provides convenience methods for
    available api actions on top of the default http transport methods
    defined by :class:`Api <Api>`.
    """

    def authenticate(self, username, password):
        """Authenticate the user.

        :type username: string
        :param username: the user's username

        :type password: string
        :param password: the user's password

        :rtype: dict
        :return: the token object

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

    @Authenticate(Api.get_auth)
    def list_profiles(self, auth=None, managed=None, limit=25):
        query = {
            'managed': managed,
            'limit': limit
        }

        response = self.get('network_profiles',
                            params=self.process_params(query),
                            auth=auth)
        return data_get(response.json(), 'data.accounts')

    @Authenticate(Api.get_auth)
    def get_sse_authorization(self, auth=None):
        """Retrieve an SSE authorization token for the authenticated user.

        :type auth: auth.UserAuth
        :param auth: :class:`auth.UserAuth <auth.UserAuth>` object

        :rtype: string
        :return: the authorization code

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
    :param response_hooks: a list of callable response hooks that should be called after the request completes.
    """

    _sse_stream_headers = {'Accept': 'text/event-stream'}

    _json_stream_headers = {'Accept': 'application/x-json-stream'}

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

    @staticmethod
    def stream_complete(data):
        """Check if a bounded stream is complete."""

        try:
            return 'complete' in json.loads(data)
        except json.decoder.JSONDecodeError:
            pass
        return False

    @Authenticate(Api.get_auth)
    def conversations(self, params=None, auth=None, async=False):
        """Stream conversation json.

        :type async:
        :param async: run request asynchronously

        :type params: dict
        :param params: request parameters

        :type auth: auth.TokenAuth
        :param auth: request authentication method

        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        if self._running:
            raise RuntimeError('stream already running')
        self._start('streams/conversation',
                    auth,
                    params=Api.process_params(params),
                    headers=self._json_stream_headers,
                    async=async,
                    sse=False)

    @Authenticate(Api.get_auth)
    def activities(self, params=None, auth=None, async=False):
        """Stream activity json.

        :type async:
        :param async: run request asynchronously

        :type params: dict
        :param params: request parameters

        :type auth: auth.TokenAuth
        :param auth: request authentication method

        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        if self._running:
            raise RuntimeError('stream already running')
        self._start('streams/activity',
                    auth,
                    params=Api.process_params(params),
                    headers=self._json_stream_headers,
                    async=async,
                    sse=False)

    @Authenticate(Api.get_auth)
    def events(self, params=None, auth=None, async=False):
        """Stream event json.

        :type async:
        :param async: run request asynchronously

        :type params: dict
        :param params: request parameters

        :type auth: auth.TokenAuth
        :param auth: request authentication method

        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        if self._running:
            raise RuntimeError('stream already running')
        self._start('streams/event',
                    auth,
                    params=Api.process_params(params, csv_keys=['event_types']),
                    headers=self._json_stream_headers,
                    async=async,
                    sse=False)

    def sse(self, authorization, params=None, async=False):
        """Stream server sent events.

        :type async: bool
        :param async: run request asynchronously

        :type authorization: string
        :param authorization: sse stream authorization code

        :type params: dict
        :param params:

        :raises ApiException:
        :raises requests.RequestException:
        :raises ssl.SSLError:
        """

        if self._running:
            raise RuntimeError('stream already running')
        self._start('streams/sse',
                    SSEAuth(authorization),
                    params=Api.process_params(params, csv_keys=['event_types']),
                    headers=self._sse_stream_headers,
                    async=async,
                    sse=True)

    def is_alive(self):
        """Check if the stream is alive."""

        return self._running

    def shutdown(self):
        """Shutdown the running stream."""

        if not self._running:
            return
        self._running = False

        if self._sse:
            # We cannot manually trigger a shutdown of the underlying thread,
            # and due to the implementation of the SSEClient event loop
            # we cannot quickly discover the call to shutdown and exit
            # the event loop. In order to shutdown the SSEClient in a timely
            # manner we forcefully close the connection, in order to trigger
            # and except within the package. We then catch the exception and
            # continue the shutdown process.
            self._sse.close()

        if self._async:
            # Allow the underlying thread time to shut down gracefully.
            start = time()
            while self._thread.is_alive():
                if 30 < (time() - start):
                    break
                sleep(1)

    def _start(self, path, auth, params=None, headers=None, async=False, sse=False):
        """Start the stream on a new thread if asynchronous.

        :type path: string
        :param path: streaming resource path

        :type auth: requests.AuthBase
        :param auth: request authentication method

        :type params: dict
        :param params: request parameters

        :type async: bool
        :param async: run request asynchronously

        :type sse: bool
        :param sse: is this a stream of server sent events
        """

        self._running = True
        self._async = async
        self._sse = None

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
        :param auth: request authentication method

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
                        BadRequestException,
                        NotFoundException) as ex:
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

        if response.encoding is None:
            response.encoding = 'utf-8'
        return response

    def _stream_sse(self, connection):
        """Handle (parse) a stream of Server Sent Events

        :type connection: requests.Response
        :param connection:
        """

        try:
            self._sse = SSEClient(connection)
            for event in self._sse.events():
                if not self._running:
                    break
                self._dispatch(json.loads(event.data))
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
            if not line:
                continue
            decoded = json.loads(line)
            self._dispatch(decoded)

            if StreamingConnectClient.stream_complete(line):
                self._running = False
                break

    def _dispatch(self, data):
        """Dispatch the stream data using each registered dispatcher.

        :param data:
        """

        for dispatcher in self._dispatchers:
            dispatcher.dispatch(data)
