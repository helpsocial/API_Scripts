#!/usr/bin/env python3

# Author: Robert Collazo <rob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import requests
import json

def base_url():
    return 'https://api.helpsocial.com'


def common_headers(key, scope):
    headers = {
        'x-api-key': key,
        'x-auth-scope': scope,
        'content-type': "application/json"
    }
    return headers


def get_user_token(username, password, key, scope):
    url = base_url()

    body = {
        'username': username,
        'password': password
    }

    headers = common_headers(key, scope)
    response = requests.post(url + "/2.0/tokens", headers=headers, json=body)

    if response.status_code == 401:
        print('[!] [{0}] Authentication Failed'.format(response.status_code))
    else:
        data = json.loads(response.content.decode('utf-8'))

        token = data['data']['token']['value']
        return token


def auth(username, password, key, scope):
    token = get_user_token(username, password, key, scope)
    headers = common_headers(key, scope)
    headers['x-auth-token'] = token

    return headers


def sse_auth(username, password, key, scope):
    url = base_url()
    headers = auth(username, password, key, scope)

    response = requests.get(url + "/2.0/streams/sse/authorization", headers=headers)

    if response.status_code == 401:
        print('[!] [{0}] Authentication Failed'.format(response.status_code))
    else:
        data = json.loads(response.content.decode('utf-8'))

        token = data['data']['authorization']
        return token

