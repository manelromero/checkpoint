# -*- coding: utf-8 -*-

from . import app
from helpers import *
from flask import request, render_template, redirect, url_for, flash, session, abort
from flask_login import LoginManager, login_user, login_required


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


# login page
@app.route('/login_page')
def login_page():
    return 'Login page'


@app.route('/clear')
def sessionClear():
    session.clear()
    flash('Session cleared!')
    return redirect(url_for('home'))


# login
@app.route('/login')
def login():
    session['sid'] = register(app.config['USER'], app.config['PASSWORD'])
    call = apiCall('show-session', {}, session['sid'])
    session['username'] = call['user-name']
    user = User(uid=session['sid'], username=session['username'])
    session['logged_in'] = True
    session['changes'] = 0
    login_user(user)
    flash('Usuari registrat!')
    return redirect(url_for('home'))



# logout
@app.route('/logout')
@login_required
def logout():
    call = apiCall('logout', {}, session['sid'])
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
@app.route('/add/<className>/<action>', methods=['GET', 'POST'])
@login_required
def add(className, action):
    # form_to_instantiate = globals()[className+'Form']
    # form = form_to_instantiate(request.form)
    form = instantiateForm(className, request.form)
    object = instantiateObject(className)
    if request.method == 'POST' and form.validate():
        data = {}
        for element in form:
            data[element.short_name.replace('_', '-')] = element.data
        call = apiCall(action, data, session['sid'])
        flash('Element afegit!')
        session['changes'] += 1
        return redirect(url_for(
            'show',
            action='show'+action[3:]+'s',
            className=className
            ))
    else:
        return render_template(
            'new.html',
            action=action,
            className=className,
            form=form
            )


# Show
@app.route('/show/<className>/<action>')
@login_required
def show(className, action):
    objects = []
    call = apiCall(action, {}, session['sid'])
    for element in call['objects']:
        data = {'uid': element['uid']}
        call = apiCall(action[:-1], data, session['sid'])
        object = instantiateObject(className)
        for attr, value in object.__dict__.items():
            setattr(object, attr, call[attr.replace('_', '-')])
        objects.append(object)
    return render_template(
        'show.html',
        objects=objects,
        action=action,
        className=className,
        sample=call
        )


# Edit
@app.route('/edit/<className>/<action>/<object_uid>', methods=['GET', 'POST'])
@login_required
def edit(className, action, object_uid):
    form = instantiateForm(className, request.form)
    object = instantiateObject(className)
    data = {'uid': object_uid}
    call = apiCall('show'+action[3:], data, session['sid'])
    for attr, value in object.__dict__.items():
        setattr(object, attr, call[attr.replace('_', '-')])
    if request.method == 'POST' and form.validate():
        data = {}
        for element in form:
            data[element.short_name.replace('_', '-')] = element.data
        call = apiCall(action, data, session['sid'])
        flash('Element afegit!')
        session['changes'] += 1
        return redirect(url_for(
            'show',
            action='show'+action[3:]+'s',
            className=className
            ))
    else:
        return render_template(
            'edit.html',
            object=object,
            action=action,
            className=className,
            form=form
            )


# Delete
@app.route(
    '/delete/<className>/<action>/<object_uid>',
    methods=['GET', 'POST']
    )
@login_required
def delete(className, action, object_uid):
    data = {'uid': object_uid}
    call = apiCall('show'+action[6:], data, session['sid'])
    object = instantiateObject(className)
    for attr, value in object.__dict__.items():
        setattr(object, attr, call[attr.replace('_', '-')])
    if request.method == 'POST':
        call = apiCall(action, data, session['sid'])
        flash('Element esborrat')
        session['changes'] += 1
        return redirect(url_for(
            'show',
            action='show'+action[6:]+'s',
            className=className
            ))
    else:
        return render_template(
            'delete.html',
            object=object,
            action=action,
            className=className
            )


@app.errorhandler(401)
def custom_401(error):
    return render_template('401.html')


