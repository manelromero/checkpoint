import requests, json
from time import strftime
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, UserMixin
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from models import User, Host
from forms import HostForm
import jinja2

# to avoid request warning of using verify=false
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


app = Flask(__name__)
app.config.from_object('config')

# initiate the login manager
login_manager = LoginManager()
login_manager.init_app(app)


# login manager
@login_manager.user_loader
def load_user(user_id):
    user = User(uid=session['sid'], username=session['username'])
    return User.get(user)


# home
@app.route('/')
def home():
    return render_template('home.html')


# login
@app.route('/login')
def login():
    if 'logged_in' in session:
        return 'Already logged!'
    try:
        session['sid'] = register(app.config['USER'], app.config['PASSWORD'])
        data = {}
        call = api_call('show-session', data, session['sid'])
        session['username'] = call['user-name']
        user = User(uid=session['sid'], username=session['username'])
        session['logged_in'] = True
        session['changes'] = 0
        login_user(user)
        flash('User logged in!')
        return redirect(url_for('home'))
    except Exception,e: print str(e)


# login page
@app.route('/login_page')
def login_page():
    return 'Login page'


# logout
@app.route('/logout')
@login_required
def logout():
    data = {}

    # session.clear()

    call = api_call('logout', data, session['sid'])
    if call['message'] == 'OK':
        session.clear()
        flash('User logged out!')
        return redirect(url_for('home'))
    return redirect(url_for('home'))


# add host
@app.route('/add-host', methods=['GET', 'POST'])
@login_required
def addHost():
    form = HostForm(request.form)
    if request.method == 'POST' and form.validate():
        data = {
            'name': form.name.data,
            'ip-address': form.ip_address.data
            }
        call = api_call('add-host', data, session['sid'])
        flash('Host added!')
        session['changes'] += 1
        return redirect(url_for('showHosts'))
    else:
        return render_template('new-host.html', form=form)


# show hosts
@app.route('/show-hosts', methods=['GET', 'POST'])
@login_required
def showHosts():
    hosts = []
    data = {}
    call = api_call('show-hosts', data, session['sid'])
    for object in call['objects']:
        data = {'uid': object['uid']}
        call = api_call('show-host', data, session['sid'])
        host = {
            'uid': call['uid'],
            'name': call['name'],
            'ip_address': call['ipv4-address'],
            'last_modify_time': call['meta-info']['last-modify-time']['posix']
            }
        hosts.append(host)
    return render_template('show-hosts.html', hosts=hosts)


# edit host
@app.route('/edit-host/<host_uid>', methods=['GET', 'POST'])
@login_required
def editHost(host_uid):
    data = {'uid': host_uid}
    call = api_call('show-host', data, session['sid'])
    host = {
        'uid': call['uid'],
        'name': call['name'],
        'ip_address': call['ipv4-address']
        }
    form = HostForm(request.form)
    if request.method == 'POST':
        data = {
            'uid': host['uid'],
            'ip-address': form.ip_address.data
            }
        call = api_call('set-host', data, session['sid'])
        flash('Host edited!')
        session['changes'] += 1
        return redirect(url_for('showHosts'))
    else:
        return render_template('edit-host.html', form=form, host=host)


# delete host
@app.route('/delete-host/<host_uid>', methods=['GET', 'POST'])
@login_required
def deleteHost(host_uid):
    data = {'uid': host_uid}
    call = api_call('show-host', data, session['sid'])
    host = {
        'uid': call['uid'],
        'name': call['name'],
        'ip_address': call['ipv4-address']
        }
    if request.method == 'POST':
        call = api_call('delete-host', data, session['sid'])
        flash('Host deleted')
        session['changes'] += 1
        return redirect(url_for('showHosts'))
    else:
        return render_template('delete-host.html', host=host)


# publish
@app.route('/publish')
@login_required
def publish():
    data = {}
    call = api_call('publish', data, session['sid'])
    flash('Changes published!')
    session['changes'] = 0
    return redirect(url_for('home'))


# discard
@app.route('/discard')
@login_required
def discard():
    data = {}
    call = api_call('discard', data, session['sid'])
    flash('Changes discarded!')
    session['changes'] = 0
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


def register(user, password):
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


def redirect_url(default='home'):
    return request.args.get('next') or request.referrer or url_for(default)


def datetimeformat(value, format='%d/%m/%Y %H:%M'):
    return datetime.fromtimestamp(int(value)/1000).strftime(format)


jinja2.filters.FILTERS['datetimeformat'] = datetimeformat

if __name__ == '__main__':
    app.run()
