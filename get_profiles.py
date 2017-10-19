#!/usr/bin/env python3

# Initial Author: Robert Collazo <rob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

import requests
import json
import auth
import configparser

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

response = requests.get(url + "/2.0/network_profiles?managed=true", headers=headers)

if response.status_code == 401:
    print('[!] [{0}] Authentication Failed'.format(response.status_code))
else:
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
