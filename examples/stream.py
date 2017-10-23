#!/usr/bin/env python3

# Author: Robert Collazo <rob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import configparser
import json

import requests

import auth

parser = configparser.SafeConfigParser()

if not parser.read('config.ini'):
    print("File 'config.ini' seems to not exist.")
    exit(-1)

username = parser.get('account', 'username')
password = parser.get('account', 'password')

body = {
    'username': username,
    'password': password
}

scope = parser.get('account', 'scope')
key = parser.get('account', 'key')

headers = auth.auth(username, password, key, scope)
url = auth.base_url()

open_stream = requests.get(url + "/2.0/streams/activity", headers=headers, stream=True)

if open_stream.encoding is None:
    open_stream.encoding = 'utf-8'

for line in open_stream.iter_lines(decode_unicode=True):
    if line:
        print(json.loads(line))


