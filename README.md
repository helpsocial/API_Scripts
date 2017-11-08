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

## Examples

| Name | Description |
| ---- | ----------- |
| auth.py | Authenticates a user. |
| stream.py | Open realtime and historical stream. Available streams: sse, activities, conversations, events  |
| get_profiles.py | Script to retrieve available network profiles for the authenticated user. |
| social.py | Engage with activities through the HelpSocial Connect API. |
| launch_conversation.py | Launch the conversation single page application. |


## Authentication

### User Auth

**file:** auth.py
**usage:**
```bash
python3 auth.py USERNAME
```

## Streaming

### SSE Stream

**file:** stream.py
**usage:**
```bash
python3 stream.py sse
```

### Activity Stream

**file:** stream.py
**usage:**
```bash
python3 stream.py activities
python3 stream.py activities bounded 20171024T140000  20171024T200000
```

### Conversation Stream

**file:** stream.py
**usage:**
```bash
python3 stream.py conversations
python3 stream.py conversations bounded 20171024T140000  20171024T200000
```

### Event Stream

**file:** stream.py
**usage:**
```bash
python3 stream.py events
python3 stream.py events bounded 20171024T140000  20171024T200000
```

## Social

### Activity Reply

**file:** social.py
**usage:**
```bash
python3 stream.py {facebook|instagram|twitter} reply [ ... ]

### Activity Share

**file:** social.py
**usage:**
```bash
python3 stream.py {facebook|instagram|twitter} share [ ... ]

### Activity Create

**file:** stream.py
**usage:**
```bash
python3 stream.py {facebook|twitter} create [ ... ]

## Conversation

### Lanuch Conversation SPA

**file:** launch_conversation.py
**usage:**
```bash
python3 launch_conversation.py single 1
```


