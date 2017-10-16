#!/usr/bin/env python3

# Author: Robert Collazo <rob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import configparser
import requests
import json

def base_url():
    return 'https://api.helpsocial.com'

def common_headers():
    parser = configparser.SafeConfigParser()

    parser.read('config.ini')

    scope = parser.get('account', 'scope')
    key = parser.get('account', 'key')

    headers = {
        'x-api-key': key,
        'x-auth-scope': scope,
        'content-type': "application/json"
    }
    return headers

def get_user_token():
    url = base_url()

    parser = configparser.SafeConfigParser()

    parser.read('config.ini')

    username = parser.get('account', 'username')
    password = parser.get('account', 'password')

    body = {
        'username': username,
        'password': password
    }

    headers = common_headers()
    response = requests.post(url + "/2.0/tokens", headers=headers, json=body)

    if response.status_code == 401:
        print('[!] [{0}] Authentication Failed'.format(response.status_code))
    else:
        data = json.loads(response.content.decode('utf-8'))

        token = data['data']['token']['value']
        return token

def auth():
    token = get_user_token()
    headers = common_headers()
    headers['x-auth-token'] = token

    return headers

def sse_auth():
    url = base_url()
    headers = auth()

    response = requests.get(url + "/2.0/streams/sse/authorization", headers=headers)

    if response.status_code == 401:
        print('[!] [{0}] Authentication Failed'.format(response.status_code))
    else:
        data = json.loads(response.content.decode('utf-8'))

        token = data['data']['authorization']
        return token
