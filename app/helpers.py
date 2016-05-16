from . import app
import requests
import json
from flask import session


def register(user, password):
    payload = {'user': user, 'password': password}
    call = api_call('login', payload, '')
    return call['sid']


def api_call(command, json_payload, sid):
    url = 'https://' + app.config['SERVER'] + ':' + app.config['PORT'] + \
        '/web_api/' + command
    if 'sid' in session:
        request_headers = {
            'Content-Type': 'application/json',
            'X-chkp-sid': session['sid']
            }
    else:
        request_headers = {'Content-Type': 'application/json'}
    r = requests.post(
        url,
        data=json.dumps(json_payload),
        headers=request_headers,
        verify=app.config['VERIFY']
        )
    return r.json()


def redirect_url(default='home'):
    return request.args.get('next') or request.referrer or url_for(default)