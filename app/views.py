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
    if session['changes'] > 0:
        return render_template('logout.html')
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
    if session['changes'] == 0:
        flash('No hi ha canvis')
        return redirect(url_for('home'))
    data = {}
    call = apiCall('publish', data, session['sid'])
    flash('Canvis publicats!')
    session['changes'] = 0
    return redirect(url_for('home'))


# discard
@app.route('/discard')
@login_required
def discard():
    if session['changes'] == 0:
        flash('No hi ha canvis')
        return redirect(url_for('home'))
    data = {}
    call = apiCall('discard', data, session['sid'])
    flash('Canvis descartats!')
    session['changes'] = 0
    return redirect(url_for('home'))


#####################
# CRUD APPLICATIONS #
#####################

# Add application
@app.route('/add-application-site', methods=['GET', 'POST'])
@login_required
def addApplicationSite():
    form = ApplicationSiteForm(request.form)
    if request.method == 'POST' and form.validate():
        data = {
            'name': form.name.data,
            'url-list': form.url_list.data,
            'description': form.description.data,
            'primary-category': 'Custom_Application_Site'
        }
        call = apiCall('add-application-site', data, session['sid'])
        flash('Aplicacio afegida!')
        session['changes'] += 1
        return redirect(url_for('showApplicationSites'))
    else:
        return render_template('new-application-site.html', form=form)


# Show applications
@app.route('/show-application-sites')
@login_required
def showApplicationSites():
    objects = []
    data = {'limit': 10}
    call = apiCall('show-application-sites', data, session['sid'])
    for element in call['objects']:
        data = {'uid': element['uid']}
        call = apiCall('show-application-site', data, session['sid'])
        object = {
            'uid': call['uid'],
            'Nom': call['name'],
            u'Descripció': call['description']
        }
        objects.append(object)
    return render_template('show-application-sites.html', objects=objects, sample=call)


# Edit application
@app.route('/set-application-site/<object_uid>', methods=['GET', 'POST'])
@login_required
def setApplicationSite(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-application-site', data, session['sid'])
    form = ApplicationSiteForm(request.form)
    object = {
        'uid': object_uid,
        'Nom': call['name'],
        u'Descripció': call['description']
        }
    if request.method == 'POST' and form.validate():
        data = {'uid': object_uid}
        call = apiCall('set-application-site', data, session['sid'])
        flash(u'Aplicació modificada!')
        session['changes'] += 1
        return redirect(url_for('showApplicationSites'))
    else:
        return render_template(
            'edit-application-site.html',
            object=object,
            form=form
            )


# Delete application
@app.route('/delete-application-site/<object_uid>', methods=['GET', 'POST'])
@login_required
def deleteApplicationSite(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-application-site', data, session['sid'])
    object = {
        'uid': call['uid'],
        'Nom': call['name'],
        u'Descripció': call['description']
        }
    if request.method == 'POST':
        print 'DATA =>', data
        call = apiCall('delete-application-site', data, session['sid'])
        flash('Element esborrat')
        session['changes'] += 1
        return redirect(url_for('showApplicationSites'))
    else:
        return render_template('delete-application-site.html', object=object)


##############
# CRUD HOSTS #
##############

# Add host
@app.route('/add-host', methods=['GET', 'POST'])
@login_required
def addHost():
    form = HostForm(request.form)
    if request.method == 'POST' and form.validate():
        data = {
            'name': form.name.data,
            'ipv4-address': form.ipv4_address.data,
        }
        call = apiCall('add-host', data, session['sid'])
        flash('Host afegit!')
        session['changes'] += 1
        return redirect(url_for('showHosts'))
    else:
        return render_template('new-host.html', form=form)


# Show hosts
@app.route('/show-hosts')
@login_required
def showHosts():
    objects = []
    data = {}
    call = apiCall('show-hosts', data, session['sid'])
    for element in call['objects']:
        data = {'uid': element['uid']}
        call = apiCall('show-host', data, session['sid'])
        object = {
            'uid': call['uid'],
            'Nom': call['name'],
            u'Adreça IPv4': call['ipv4-address']
        }
        objects.append(object)
    return render_template('show-hosts.html', objects=objects, sample=call)


# Edit host
@app.route('/set-host/<object_uid>', methods=['GET', 'POST'])
@login_required
def setHost(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-host', data, session['sid'])
    form = HostForm(request.form)
    object = {
        'uid': object_uid,
        'Nom': call['name'],
        u'Adreça IPv4': call['ipv4-address']
        }
    if request.method == 'POST' and form.validate():
        data = {
            'uid': object_uid,
            'new-name': form.name.data,
            'ipv4-address': form.ipv4_address.data
            }
        call = apiCall('set-host', data, session['sid'])
        flash('Host editat!')
        session['changes'] += 1
        return redirect(url_for('showHosts'))
    else:
        return render_template('edit-host.html', object=object, form=form)


# Delete application
@app.route('/delete-host/<object_uid>', methods=['GET', 'POST'])
@login_required
def deleteHost(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-host', data, session['sid'])
    object = {
        'uid': call['uid'],
        'Nom': call['name'],
        u'Adreça IPv4': call['ipv4-address']
        }
    if request.method == 'POST':
        call = apiCall('delete-host', data, session['sid'])
        flash('Host esborrat')
        session['changes'] += 1
        return redirect(url_for('showHosts'))
    else:
        return render_template('delete-host.html', object=object)


#################
# CRUD NETWORKS #
#################

# Add network
@app.route('/add-network', methods=['GET', 'POST'])
@login_required
def addNetwork():
    form = NetworkForm(request.form)
    if request.method == 'POST' and form.validate():
        data = {
            'name': form.name.data,
            'subnet4': form.subnet4.data,
            'subnet-mask': form.subnet_mask.data
        }
        call = apiCall('add-network', data, session['sid'])
        flash('Xarxa afegida!')
        session['changes'] += 1
        return redirect(url_for('showNetworks'))
    else:
        return render_template('new-network.html', form=form)


# Show networks
@app.route('/show-networks')
@login_required
def showNetworks():
    objects = []
    data = {}
    call = apiCall('show-networks', data, session['sid'])
    for element in call['objects']:
        data = {'uid': element['uid']}
        call = apiCall('show-network', data, session['sid'])
        object = {
            'uid': call['uid'],
            'Nom': call['name'],
            u'IPv4 de la xarxa': call['subnet4'],
            u'Màscara de xarxa': call['subnet-mask']
            }
        objects.append(object)
    return render_template('show-networks.html', objects=objects, sample=call)


# Edit network
@app.route('/set-network/<object_uid>', methods=['GET', 'POST'])
@login_required
def setNetwork(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-network', data, session['sid'])
    form = NetworkForm(request.form)
    object = {
        'uid': object_uid,
        'Nom': call['name'],
        u'IPv4 de la xarxa': call['subnet4'],
        u'Màscara de xarxa': call['subnet-mask']
        }
    if request.method == 'POST' and form.validate():
        data = {
            'uid': object_uid,
            'new-name': form.name.data,
            'subnet4': form.subnet4.data,
            'subnet-mask': form.subnet_mask.data
            }
        call = apiCall('set-network', data, session['sid'])
        flash('Xarxa editada!')
        session['changes'] += 1
        return redirect(url_for('showNetworks'))
    else:
        return render_template('edit-network.html', object=object, form=form)


# Delete network
@app.route('/delete-network/<object_uid>', methods=['GET', 'POST'])
@login_required
def deleteNetwork(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-network', data, session['sid'])
    object = {
        'uid': object_uid,
        'Nom': call['name'],
        u'IPv4 de la xarxa': call['subnet4'],
        u'Màscara de xarxa': call['subnet-mask']
        }
    if request.method == 'POST':
        call = apiCall('delete-network', data, session['sid'])
        flash('Xarxa esborrada!')
        session['changes'] += 1
        return redirect(url_for('showNetworks'))
    else:
        return render_template('delete-network.html', object=object)


####################
# Errors
@app.errorhandler(401)
def custom_401(error):
    return render_template('401.html')





