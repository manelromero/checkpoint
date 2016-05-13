import requests, json

def api_call(ip_addr, port, command, json_payload, sid):
    url = 'https://' + ip_addr + ':' + port + '/web_api/' + command
    if sid == '':
        request_headers = {'Content-Type' : 'application/json'}
    else:
        request_headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}
    r = requests.post(url,data=json.dumps(json_payload), headers=request_headers)
    return r.json()


def login(user, password):
    request_headers = {'Content-Type': 'application/json'}
    payload = {'user': user, 'password': password}
    r = requests.post('https://192.168.1.10:443/web_api/login', data=json.dumps(payload), headers=request_headers)
    response = r.json()
    return response["sid"]

sid = login('admin', 'developer2016')

print("session id: " + sid)

# new_host_data = {'name':'new host name', 'ip-address':'192.168.1.1'}
# new_host_result = api_call('192.168.1.10', '443','add-host', new_host_data ,sid)
# print(json.dumps(new_host_result))

# publish_result = api_call('192.168.65.2', '443',"publish", {},sid)
# print("publish result: " + json.dumps(publish_result))

# logout_result = api_call('192.168.65.2', '443',"logout", {},sid)
# print("logout result: " + json.dumps(logout_result))