#!/usr/bin/python

# Author: Robert Collazo <rob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import configparser
import requests
import json

def baseurl():
    return 'https://api.helpsocial.com'

def auth():
    parser = configparser.SafeConfigParser()

    parser.read('config.ini')

    scope = parser.get('account', 'scope')
    key = parser.get('account', 'key')
    username = parser.get('account', 'username')
    password = parser.get('account', 'password')

    url = 'https://api.helpsocial.com'

    body = {
        'username': username,
        'password': password
    }

    headers = {
        'x-api-key': key,
        'x-auth-scope': scope,
        'content-type': "application/json"
    }

    response = requests.post(url + "/2.0/tokens", headers=headers, json=body)

    if response.status_code == 401:
        print('[!] [{0}] Authentication Failed'.format(response.status_code))
    else:
        data = json.loads(response.content.decode('utf-8'))

        token = data['data']['token']['value']
        headers['token'] = token

        return headers
    
