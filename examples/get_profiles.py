#!/usr/bin/env python3

# Author: Robert Collazo <rob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import configparser
import os
import sys

try:
    import ujson as json
except ImportError:
    import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helpsocial import RestConnectClient
from helpsocial.hooks import RequestPrinter
from helpsocial.utils import data_get


config_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '.config.ini'
)

if not os.path.exists(config_path):
    print("File '.config.ini' seems to not exist.")
    exit(-1)

parser = configparser.ConfigParser()
if not parser.read(config_path):
    print('Failed to read config file.')
    exit(-1)

client = RestConnectClient(
    parser.get('account', 'scope'),
    parser.get('account', 'key'),
    request_hooks=[RequestPrinter()]
)

if parser.get('account', 'user_token', fallback=None) is not None:
    client.set_user_token(parser.get('account', 'user_token'))
else:
    username = parser.get('account', 'username')
    password = parser.get('account', 'password')
    user_token = data_get(client.authenticate(username, password), 'value')
    client.set_user_token(user_token)

query = {
    'managed': True
    # 'accessible': True
    # 'network': 'twitter'
}


response = client.get('network_profiles',
                      auth=client.get_auth(),
                      params=query,
                      http_errors=True)

if response.status_code == 401:
    print('[!] [{0}] Authentication Failed'.format(response.status_code))
    exit(-1)

results = json.loads(response.content.decode('utf-8'))

if not results:
    print('No network profiles found.')
    exit(-1)

accounts = []
for account in results['data']['accounts']:
    account_details = {
        'id': account['id'],
        'username': account['username'],
        'display_name': account['display_name'],
        'network_id': account['network']['id'],
        'network': account['network']['name']
    }
    accounts.append(account_details)


print('{:<12} {:<30} {:<30} {:<10} {:<10}'.format('ID', 'Username', 'Display Name', 'Network ID', 'Network'))
for account in accounts:
    print('{:<12} {:<30} {:<30} {:<10} {:<10}'.format(account['id'], account['username'], account['display_name'], account['network_id'], account['network']))
