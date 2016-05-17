# -*- coding: utf-8 -*-

from . import app
from helpers import register, apiCall
from flask import request, render_template, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required
from models import *
from forms import HostForm, ApplicationSiteForm
import json

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
    flash('Session cleared!')
    return redirect(url_for('home'))


# login
@app.route('/login')
def login():
    if 'logged_in' in session:
        return 'Already logged!'
    session['sid'] = register(app.config['USER'], app.config['PASSWORD'])
    data = {}
    call = apiCall('show-session', data, session['sid'])
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
    call = apiCall('logout', data, session['sid'])
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
    call = apiCall('publish', data, session['sid'])
    flash('Canvis publicats!')
    session['changes'] = 0
    return redirect(url_for('home'))


# discard
@app.route('/discard')
@login_required
def discard():
    data = {}
    call = apiCall('discard', data, session['sid'])
    flash('Canvis descartats!')
    session['changes'] = 0
    return redirect(url_for('home'))


# Add
@app.route('/add/<action>/<className>', methods=['GET', 'POST'])
@login_required
def add(action, className):
    form_to_instantiate = globals()[className+'Form']
    form = form_to_instantiate(request.form)
    object_to_instantiate = globals()[className]
    object = object_to_instantiate()
    if request.method == 'POST' and form.validate():
        data = {}
        for element in form:
            data[element.short_name.replace('_', '-')] = element.data
        call = apiCall(action, data, session['sid'])
        flash('Host afegit!')
        session['changes'] += 1
        return redirect(url_for(
            'show',
            action='show-'+action[4:]+'s',
            className=className
            ))
    else:
        return render_template(
            'new.html',
            action=action,
            className=className,
            form=form)


# Show
@app.route('/show/<action>/<className>')
@login_required
def show(action, className):
    objects = []
    object_to_instantiate = globals()[className]
    call = apiCall(action, {}, session['sid'])
    for element in call['objects']:
        data = {'uid': element['uid']}
        call = apiCall(action[:-1], data, session['sid'])
        object = object_to_instantiate()
        for attr, value in object.__dict__.items():
            setattr(object, attr, call[attr.replace('_', '-')])
        objects.append(object)
    object = className + 's'
    return render_template('show.html', objects=objects, object=object, sample=call)


# edit host
@app.route('/edit-host/<host_uid>', methods=['GET', 'POST'])
@login_required
def editHost(host_uid):
    data = {'uid': host_uid}
    call = apiCall('show-host', data, session['sid'])
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
        call = apiCall('set-host', data, session['sid'])
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
    call = apiCall('show-host', data, session['sid'])
    host = {
        'uid': call['uid'],
        'name': call['name'],
        'ip_address': call['ipv4-address']
        }
    if request.method == 'POST':
        call = apiCall('delete-host', data, session['sid'])
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
        call = apiCall('add-application-site', data, session['sid'])
        flash('Aplicacio afegida!')
        session['changes'] += 1
        return redirect(url_for('showApplicationSites'))
    else:
        return render_template('new-application-site.html', form=form)


