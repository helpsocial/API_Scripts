#!/usr/bin/env python3

# Author: Robert Collazo <rob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import auth
import json
from sseclient import SSEClient

url = auth.base_url()
sse_token = auth.sse_auth()

messages = SSEClient(url + "/2.0/streams/sse?authorization=" + sse_token)

for msg in messages:
    print(msg)
