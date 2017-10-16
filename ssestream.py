#!/usr/bin/env python3

# Author: Robert Collazo <rob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import auth
import json
from sseclient import SSEClient

url = auth.baseurl()
sseToken = auth.sseAuth()

messages = SSEClient(url + "/2.0/streams/sse?authorization=" + sseToken)

for msg in messages:
    print(msg)
