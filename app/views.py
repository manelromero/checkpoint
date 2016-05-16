# -*- coding: utf-8 -*-

from . import app
from helpers import register, api_call
from flask import request, render_template, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required
from models import User
from forms import HostForm, ApplicationSiteForm

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


@app.route('/clear')
def sessionClear():
    session.clear()
    return redirect(url_for('home'))


# login
@app.route('/login')
def login():
    if 'logged_in' in session:
        return 'Already logged!'
    session['sid'] = register(app.config['USER'], app.config['PASSWORD'])
    data = {}
    call = api_call('show-session', data, session['sid'])
    session['username'] = call['user-name']
    user = User(uid=session['sid'], username=session['username'])
    session['logged_in'] = True
    session['changes'] = 0
    login_user(user)
    flash('Usuari registrat!')
    return redirect(url_for('home'))


# login page
@app.route('/login_page')
def login_page():
    return 'Login page'


# logout
@app.route('/logout')
@login_required
def logout():
    data = {}
    call = api_call('logout', data, session['sid'])
    if call['message'] == 'OK':
        session.clear()
        flash('Usuari desconnectat!')
        return redirect(url_for('home'))
    return redirect(url_for('home'))


# publish
@app.route('/publish')
@login_required
def publish():
    data = {}
    call = api_call('publish', data, session['sid'])
    flash('Canvis publicats!')
    session['changes'] = 0
    return redirect(url_for('home'))


# discard
@app.route('/discard')
@login_required
def discard():
    data = {}
    call = api_call('discard', data, session['sid'])
    flash('Canvis descartats!')
    session['changes'] = 0
    return redirect(url_for('home'))


# HOST CRUD
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
        flash('Host afegit!')
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
        flash('Host editat!')
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
        flash('Host esborrat')
        session['changes'] += 1
        return redirect(url_for('showHosts'))
    else:
        return render_template('delete-host.html', host=host)


# APPLICATION SITE CRUD
# add application site
@app.route('/add-application-site', methods=['GET', 'POST'])
@login_required
def addApplicationSite():
    form = ApplicationSiteForm(request.form)
    if request.method == 'POST' and form.validate():
        data = {
            'name': form.name.data,
            'description': form.description.data
            }
        call = api_call('add-application-site', data, session['sid'])
        flash('Aplicacio afegida!')
        session['changes'] += 1
        return redirect(url_for('showApplicationSites'))
    else:
        return render_template('new-application-site.html', form=form)


# show application sites
@app.route('/show-application-sites', methods=['GET', 'POST'])
@login_required
def showApplicationSites():
    apps = []
    data = {}
    call = api_call('show-application-sites', data, session['sid'])
    for object in call['objects']:
        data = {'uid': object['uid']}
        call = api_call('show-application-site', data, session['sid'])
        app = {
            'uid': call['uid'],
            'name': call['name'],
            'description': call['description']
            }
        apps.append(app)
    return render_template('show-application-sites.html', apps=apps)


# edit application site
@app.route('/edit-application-site', methods=['GET', 'POST'])
@login_required
def editApplicationSite():
    return 'edit'


# delete application site
@app.route('/delete-application-site', methods=['GET', 'POST'])
@login_required
def deleteApplicationSite():
    return 'delete'
