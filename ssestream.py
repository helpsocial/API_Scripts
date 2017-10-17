#!/usr/bin/env python3

# Author: Robert Collazo <rob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import auth
import json
import configparser
from sseclient import SSEClient

parser = configparser.SafeConfigParser()

parser.read('config.ini')

username = parser.get('account', 'username')
password = parser.get('account', 'password')

body = {
    'username': username,
    'password': password
}

scope = parser.get('account', 'scope')
key = parser.get('account', 'key')

url = auth.base_url()
sse_token = auth.sse_auth(username, password, key, scope)

messages = SSEClient(url + "/2.0/streams/sse?authorization=" + sse_token)

for msg in messages:
    print(msg)
