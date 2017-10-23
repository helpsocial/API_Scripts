HelpSocial API Python Client
==========

A simple client for the HelpSocial API.

# Usage

A simple rest client can be created with or without an authenticated
user.

The client handles authenticating the requests using the most permissive
authentication available. This can be overridden by using your own
auth provider.

The RestConnectionClient gives you access direct access to the http
verb methods (get, post, put, and delete) which can be used to make
any available rest connect api call. Some of the more common tasks
are also exposed through simple helper methods.


## Without User

```python
from client import RestConnectClient

client = RestConnectClient('<your auth_scope>', '<your api_key>')

client.get('<path>')
client.post('<path>')
client.put('<path>')
client.delete('<path>')

```

## With User

```python
from client import RestConnectClient

client = RestConnectClient('<your auth_scope>',
                           '<your api_key>',
                           user_token='<user token>')

client.get('<path>')
client.post('<path>')
client.put('<path>')
client.delete('<path>')

```

For advanced usage see the `examples/` directory.

### Examples


| Name | Description |
| ---- | ----------- |
| auth.py | Performs the steps to necessary to authenticate a user. |
| ssestream.py | Script to open a connection to the HelpSocial API SSE endpoint. |
| get_profiles.py | Script to retrieve available network profiles for the authenticated user. |
