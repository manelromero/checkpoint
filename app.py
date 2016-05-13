import requests, json
from time import strftime
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from models import Host
from forms import HostForm
import jinja2


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


app = Flask(__name__)
app.config.from_object('config')


sid = ''
user = ''
changes = 0

@app.route('/')
def home():
    return render_template('home.html', sid=sid, changes=changes, user=user)


# login
@app.route('/login')
def register():
    global sid, user
    sid = login(app.config['USER'], app.config['PASSWORD'])
    data = {}
    call = api_call('show-session', data, sid)
    user = call['user-name']
    flash('User logged in!')
    return redirect(url_for('home'))


#logout
@app.route('/logout')
def logout():
    global sid, user
    data = {}
    call = api_call('logout', data, sid)
    if call['message'] == 'OK':
        sid = ''
        user = ''
    flash('User logged out!')
    return redirect(url_for('home'))


# add host
@app.route('/add-host', methods=['GET', 'POST'])
def addHost():
    form = HostForm(request.form)
    if request.method == 'POST' and form.validate():
        data = {
            'name': form.name.data,
            'ip-address': form.ip_address.data
            }
        call = api_call('add-host', data, sid)
        flash('Host added!')
        global changes
        changes += 1
        return redirect(url_for('showHosts'))
    else:
        return render_template('new-host.html', user=user, form=form, changes=changes)


# show hosts
@app.route('/show-hosts', methods=['GET', 'POST'])
def showHosts():
    hosts = []
    data = {}
    call = api_call('show-hosts', data, sid)
    for object in call['objects']:
        data = {'uid': object['uid']}
        call = api_call('show-host', data, sid)
        host = {
            'uid': call['uid'],
            'name': call['name'],
            'ip_address': call['ipv4-address'],
            'last_modify_time': call['meta-info']['last-modify-time']['posix']
            }
        hosts.append(host)
    return render_template('show-hosts.html', user=user, hosts=hosts, changes=changes)


# edit host
@app.route('/edit-host/<host_uid>', methods=['GET', 'POST'])
def editHost(host_uid):
    data = {'uid': host_uid}
    call = api_call('show-host', data, sid)
    host = {
        'uid': call['uid'],
        'name': call['name'],
        'ip_address': call['ipv4-address']
        }
    form = HostForm(request.form)
    if request.method == 'POST':
        print '\nForm errors: ', form.errors, form.validate()
        data = {
            'uid': host['uid'],
            'ip-address': form.ip_address.data
            }
        call = api_call('set-host', data, sid)
        flash('Host edited!')
        global changes
        changes += 1
        return redirect(url_for('showHosts'))
    else:
        return render_template('edit-host.html', user=user, form=form, host=host, changes=changes)


# delete host
@app.route('/delete-host/<host_uid>', methods=['GET', 'POST'])
def deleteHost(host_uid):
    data = {'uid': host_uid}
    call = api_call('show-host', data, sid)
    host = {
        'uid': call['uid'],
        'name': call['name'],
        'ip_address': call['ipv4-address']
        }
    if request.method == 'POST':
        call = api_call('delete-host', data, sid)
        flash('Host deleted')
        global changes
        changes += 1
        return redirect(url_for('showHosts'))
    else:
        return render_template('delete-host.html', user=user, host=host, changes=changes)


# publish
@app.route('/publish')
def publish():
    data = {}
    call = api_call('publish', data, sid)
    flash('Changes published!')
    global changes
    changes = 0
    return redirect(url_for('home'))


# discard
@app.route('/discard')
def discard():
    data = {}
    call = api_call('discard', data, sid)
    flash('Changes discarded!')
    global changes
    changes = 0
    return redirect(url_for('home'))


@app.route('/smartview')
def smartview():
    url = 'https://192.168.1.10/smartview'
    data = {
        'user': app.config['USER'],
        'password': app.config['PASSWORD']
    }
    r = requests.get(url, verify=False)
    return r


def login(user, password):
    payload = {'user': user, 'password': password}
    response = api_call('login', payload, '')
    return response['sid']


def api_call(command, json_payload, sid):
    url = 'https://' + app.config['SERVER'] + ':' + app.config['PORT'] + \
        '/web_api/' + command
    if sid == '':
        request_headers = {'Content-Type': 'application/json'}
    else:
        request_headers = {'Content-Type': 'application/json', 'X-chkp-sid': sid}
    r = requests.post(url, data=json.dumps(json_payload), headers=request_headers, verify=False)
    return r.json()


def datetimeformat(value, format='%d/%m/%Y %H:%M'):
    return datetime.fromtimestamp(int(value)/1000).strftime(format)


jinja2.filters.FILTERS['datetimeformat'] = datetimeformat

if __name__ == '__main__':
    app.run()
