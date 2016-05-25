# -*- coding: utf-8 -*-

from . import app
from models import User
from helpers import *
from flask import request, render_template, redirect, url_for, flash, session,\
    abort
from flask_login import LoginManager, UserMixin, login_user, login_required


# initiate the login manager
login_manager = LoginManager()
login_manager.init_app(app)


# login manager
@login_manager.user_loader
def load_user(sid):
    call = apiCall('show-session', {}, sid)
    # check if session has expired
    if 'user-name' in call:
        user = User(
            sid=sid,
            username=call['user-name']
            )
        return user
    return None


# login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        # store the uid in session so @login_manager can use it
        session['sid'] = register(form.username.data, form.password.data)
        # check if login is correct
        if session['sid']:
            user = User(
                sid=session['sid'],
                username=form.username.data
                )
            # store the username in session so can be shown in header
            session['username'] = form.username.data
            # initiate changes to 0
            session['changes'] = 0
            login_user(user)
            flash('Usuari registrat')
            return render_template(
                'publish-correct.html',
                after_publish='home'
                )
        flash(u"Error d'inici de sessió, torneu a intentar-ho.")
        return render_template('publish-error.html', after_publish='login')
    return render_template('login.html', form=form)


# logout
@app.route('/logout')
@login_required
def logout():
    if session['changes'] > 0:
        return render_template('logout.html')
    call = apiCall('logout', {}, session['sid'])
    if call['message'] == 'OK':
        session.clear()
        flash('Usuari desconnectat')
        return render_template(
            'publish-correct.html',
            after_publish='home'
            )
    return redirect(url_for('home'))


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
    return redirect(url_for('home'))


# publish
@app.route('/publish/<after_publish>')
@login_required
def publish(after_publish):
    if session['changes'] == 0:
        return redirect(url_for('home'))
    data = {}
    call = apiCall('publish', data, session['sid'])
    print '\n\nPUBLISH ANSWER:', call
    if call['task-id']:
        session['changes'] = 0
        return render_template(
            'publish-correct.html',
            after_publish=after_publish
            )
    else:
        return render_template(
            'publish-error.html',
            after_publish=after_publish
            )


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


##############
# CRUD RULES #
##############

# Add rule
@app.route('/add-rule', methods=['GET', 'POST'])
@login_required
def addAccessRule():
    form = AccessRuleForm(request.form)

    # call hosts
    hosts = []
    data = {}
    call = apiCall('show-groups', data, session['sid'])
    for element in call['objects']:
        hosts.append((element['uid'], element['name']))

    # add options
    form.source.choices = hosts

    # call hosts
    app_groups = []
    data = {}
    call = apiCall('show-application-site-groups', data, session['sid'])
    for element in call['objects']:
        app_groups.append((element['uid'], element['name']))

    # add options
    form.service.choices = app_groups

    if request.method == 'POST' and form.validate():
        data = {
            'layer': app.config['LAYER'],
            'position': 'top',
            'action': 'Accept',
            'enabled': True,
            'name': form.name.data,
            'source': form.source.data,
            'service': form.service.data
            }
        call = apiCall('add-access-rule', data, session['sid'])
        flash('Regla afegida!')
        session['changes'] += 1
        return redirect(url_for('publish', after_publish='showAccessRules'))
    else:
        return render_template('new-access-rule.html', form=form)


# Show rules
@app.route('/show-access-rulebase')
@login_required
def showAccessRules():
    objects = []
    data = {'name': app.config['LAYER']}
    call = apiCall('show-access-rulebase', data, session['sid'])
    for element in call['rulebase']:
        data = {
            'uid': element['uid'],
            'layer': app.config['LAYER']
            }
        call = apiCall('show-access-rule', data, session['sid'])
        object = {
            'uid': call['uid'],
            'Nom': call['name'],
            'Origen': call['source'][0]['name'],
            u'Destinació': call['destination'][0]['name'],
            }
        objects.append(object)
    return render_template('show-access-rules.html', objects=objects)


# Edit rule
@app.route('/set-rule/<object_uid>', methods=['GET', 'POST'])
@login_required
def setAccessRule(object_uid):
    form = AccessRuleForm(request.form)

    # call hosts
    objects = []
    data = {}
    call = apiCall('show-hosts', data, session['sid'])
    for element in call['objects']:
        objects.append((element['uid'], element['name']))

    # call networks
    call = apiCall('show-networks', data, session['sid'])
    for element in call['objects']:
        objects.append((element['uid'], element['name']))

    # call groups
    call = apiCall('show-groups', data, session['sid'])
    for element in call['objects']:
        objects.append((element['uid'], element['name']))

    # add options
    form.source.choices = objects
    form.destination.choices = objects

    data = {
        'uid': object_uid,
        'layer': app.config['LAYER']
        }
    call = apiCall('show-access-rule', data, session['sid'])
    object = {
        'uid': object_uid,
        'Nom': call['name'],
        }
    if request.method == 'POST' and form.validate():
        data = {
            'uid': object_uid,
            'layer': app.config['LAYER'],
            'new-name': form.name.data,
            'source': form.source.data,
            'destination': form.destination.data
            }
        call = apiCall('set-access-rule', data, session['sid'])
        flash('Regla editada!')
        session['changes'] += 1
        return redirect(url_for('showAccessRules'))
    else:
        return render_template(
            'edit-access-rule.html',
            object=object,
            form=form
            )


# Delete rule
@app.route('/delete-rule/<object_uid>', methods=['GET', 'POST'])
@login_required
def deleteAccessRule(object_uid):
    data = {
        'uid': object_uid,
        'layer': app.config['LAYER']
        }
    call = apiCall('show-access-rule', data, session['sid'])
    object = {
        'uid': object_uid,
        'Nom': call['name']
        }
    if request.method == 'POST':
        call = apiCall('delete-access-rule', data, session['sid'])
        flash('Regla esborrada!')
        session['changes'] += 1
        return redirect(url_for('showAccessRules'))
    else:
        return render_template('delete-access-rule.html', object=object)


# Errors
@app.errorhandler(401)
def custom_401(error):
    return render_template('401.html')


###############
# CRUD GROUPS #
###############

# Add group
@app.route('/add-group', methods=['GET', 'POST'])
@login_required
def addGroup():
    form = GroupForm(request.form)
    if request.method == 'POST' and form.validate():
        data = {
            'name': form.name.data,
            }
        call = apiCall('add-group', data, session['sid'])
        flash('Grup afegit!')
        session['changes'] += 1
        return redirect(url_for('publish', after_publish='showGroups'))
    else:
        return render_template('new-group.html', form=form)


# Show groups
@app.route('/show-groups')
@login_required
def showGroups():
    objects = []
    call = apiCall('show-groups', {}, session['sid'])
    for element in call['objects']:
        data = {'uid': element['uid']}
        call = apiCall('show-group', data, session['sid'])
        object = {
            'uid': call['uid'],
            'Nom': call['name'],
            }
        objects.append(object)
    return render_template('show-groups.html', objects=objects)


# Show group members
@app.route('/show-group-members/<group_id>')
@login_required
def showGroupMembers(group_id):
    hosts, networks = [], []
    form_host = HostForm(request.form)
    form_network = NetworkForm(request.form)
    # call for group members
    data = {'uid': group_id, 'details-level': 'full'}
    call = apiCall('show-group', data, session['sid'])
    for element in call['members']:
        # select the hosts
        if element['type'] == 'host':
            object = {
                'uid': element['uid'],
                'name': element['name'],
                'ipv4_address': element['ipv4-address']
                }
            hosts.append(object)
        # select the networks
        if element['type'] == 'network':
            object = {
                'uid': element['uid'],
                'name': element['name'],
                'subnet4': element['subnet4'],
                'subnet_mask': element['subnet-mask'],
                }
            networks.append(object)
    return render_template(
        'show-group-members.html',
        hosts=hosts,
        networks=networks,
        form_host=form_host,
        form_network=form_network,
        group_id=group_id
        )


# Edit group
@app.route('/set-group/<object_uid>', methods=['GET', 'POST'])
@login_required
def setGroup(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-group', data, session['sid'])
    form = GroupForm(request.form)
    object = {
        'uid': object_uid,
        'Nom': call['name'],
        }
    if request.method == 'POST' and form.validate():
        data = {
            'uid': object_uid,
            'new-name': form.name.data,
            }
        call = apiCall('set-group', data, session['sid'])
        flash('Grup editat!')
        session['changes'] += 1
        return redirect(url_for('publish', after_publish='showGroups'))
    else:
        return render_template('edit-group.html', object=object, form=form)


# Delete group
@app.route('/delete-group/<object_uid>', methods=['GET', 'POST'])
@login_required
def deleteGroup(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-group', data, session['sid'])
    object = {
        'uid': object_uid,
        'Nom': call['name'],
        }
    if request.method == 'POST':
        call = apiCall('delete-group', data, session['sid'])
        flash('Grup esborrat!')
        session['changes'] += 1
        return redirect(url_for('publish', after_publish='showGroups'))
    else:
        return render_template('delete-group.html', object=object)


###################
# CRUD APP GROUPS #
###################

# Add applications group member
@app.route('/add-application-site-group', methods=['GET', 'POST'])
@login_required
def addApplicationSiteGroup():
    form = ApplicationSiteGroupForm(request.form)
    if request.method == 'POST' and form.validate():
        data = {
            'name': form.name.data
        }
        call = apiCall('add-application-site-group', data, session['sid'])
        flash("Grup d'aplicacions afegit!")
        session['changes'] += 1
        return redirect(url_for(
            'publish',
            after_publish='showApplicationSiteGroups'
            ))
    else:
        return render_template('new-application-site-group.html', form=form)


# Show applications groups
@app.route('/show-application-site-groups')
@login_required
def showApplicationSiteGroups():
    objects = []
    call = apiCall('show-application-site-groups', {}, session['sid'])
    for element in call['objects']:
        data = {'uid': element['uid']}
        call = apiCall('show-application-site-group', data, session['sid'])
        object = {
            'uid': call['uid'],
            'Nom': call['name'],
            'Creat': call['meta-info']['creation-time']['posix'],
            'Modificat': call['meta-info']['last-modify-time']['posix']
        }
        objects.append(object)
    return render_template(
        'show-application-site-groups.html',
        objects=objects
        )


# Delete applications group member
@app.route(
    '/delete-application-site-group/<object_uid>',
    methods=['GET', 'POST']
    )
@login_required
def deleteApplicationSiteGroup(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-application-site-group', data, session['sid'])
    object = {
        'uid': call['uid'],
        'name': call['name']
        }
    if request.method == 'POST':
        call = apiCall('delete-application-site-group', data, session['sid'])
        flash('Grup esborrat')
        session['changes'] += 1
        return redirect(url_for(
            'publish',
            after_publish='showApplicationSiteGroups'
            ))
    else:
        return render_template(
            'delete-application-site-group.html',
            object=object
            )


#####################
# CRUD APPLICATIONS #
#####################

# Add applications group member
@app.route('/add-application-site/<group_id>', methods=['POST'])
@login_required
def addApplicationSite(group_id):
    form = ApplicationSiteForm(request.form)
    if form.validate():
        data = {
            'name': 'App ' + form.name.data,
            'url-list': form.url_list.data,
            'description': form.description.data,
            'primary-category': 'Custom_Application_Site',  # required
        }
        # call for adding the application
        call = apiCall('add-application-site', data, session['sid'])
        data = {
            'uid': group_id,
            'members': {
                'add': 'App ' + form.name.data
                }
            }
        # call for adding the application to application group
        call = apiCall('set-application-site-group', data, session['sid'])
        flash(u'Aplicació afegida!')
        session['changes'] += 1
        return redirect(url_for(
            'publish',
            after_publish='showApplicationSiteGroups'
            ))
    else:
        return render_template('new-application-site.html', form=form)


# Show applications group members
@app.route('/show-application-sites/<group_id>')
@login_required
def showApplicationSites(group_id):
    objects = []
    form = ApplicationSiteForm(request.form)
    data = {'uid': group_id, 'details-level': 'full'}
    call = apiCall('show-application-site-group', data, session['sid'])
    # check if there is at least one url in the group
    if call['members']:
        for element in call['members']:
            object = {
                'uid': element['uid'],
                'name': element['name'],
                'url': element['url-list'][0],
                'description': element['description']
            }
            objects.append(object)
    return render_template(
        'show-application-sites.html',
        objects=objects,
        form=form,
        group_id=group_id
        )


# Edit application group member (Pending)
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


# Delete application group member
@app.route(
    '/delete-application-site/<group_id>/<object_uid>',
    methods=['GET', 'POST']
    )
@login_required
def deleteApplicationSite(group_id, object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-application-site', data, session['sid'])
    object = {
        'uid': call['uid'],
        'name': call['name'],
        'url_list': call['url-list'][0],
        }
    if request.method == 'POST':
        # call for removing the application from the application group
        data = {
            'uid': group_id,
            'members': {
                'remove': object['name']
                }
            }
        call = apiCall('set-application-site-group', data, session['sid'])
        # call for deleting the application
        data = {'uid': object_uid}
        call = apiCall('delete-application-site', data, session['sid'])
        flash(u'Aplicació esborrada')
        session['changes'] += 1
        return redirect(url_for(
            'publish',
            after_publish='showApplicationSiteGroups'
            ))
    else:
        return render_template(
            'delete-application-site.html',
            group_id=group_id,
            object=object
            )


##############
# CRUD HOSTS #
##############

# Add host
@app.route('/add-host/<group_id>', methods=['POST'])
@login_required
def addHost(group_id):
    form = HostForm(request.form)
    if form.validate():
        # call for adding the host
        data = {
            'name': 'Host ' + form.name.data,
            'ipv4-address': form.ipv4_address.data
        }
        call = apiCall('add-host', data, session['sid'])
        # call for adding the host to group
        data = {
            'uid': group_id,
            'members': {
                'add': 'Host ' + form.name.data
                }
            }
        call = apiCall('set-group', data, session['sid'])
        flash('Host afegit')
        session['changes'] += 1
        return redirect(url_for(
            'publish',
            after_publish='showGroups'
            ))
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
            'name': call['name'],
            'ipv4_address': call['ipv4-address']
        }
        objects.append(object)
    return render_template('show-hosts.html', objects=objects)


# Edit host
@app.route('/set-host/<object_uid>', methods=['GET', 'POST'])
@login_required
def setHost(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-host', data, session['sid'])
    form = HostForm(request.form)
    object = {
        'uid': object_uid,
        'name': call['name'][5:],
        'ipv4_address': call['ipv4-address']
        }
    if request.method == 'POST' and form.validate():
        data = {
            'uid': object_uid,
            'new-name': 'Host ' + form.name.data,
            'ipv4-address': form.ipv4_address.data
            }
        call = apiCall('set-host', data, session['sid'])
        flash('Host editat!')
        session['changes'] += 1
        return redirect(url_for(
            'publish',
            after_publish='showGroups'
            ))
    else:
        return render_template('edit-host.html', object=object, form=form)


# Delete host
@app.route('/delete-host/<group_id>/<object_uid>', methods=['GET', 'POST'])
@login_required
def deleteHost(group_id, object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-host', data, session['sid'])
    object = {
        'uid': call['uid'],
        'name': call['name'],
        'ipv4_address': call['ipv4-address']
        }
    if request.method == 'POST':
        # call for removing the host from the group
        data = {
            'uid': group_id,
            'members': {
                'remove': object['name']
                }
            }
        call = apiCall('set-group', data, session['sid'])
        # call for deleting the host
        data = {'uid': object_uid}
        call = apiCall('delete-host', data, session['sid'])
        flash('Host esborrat')
        session['changes'] += 1
        return redirect(url_for(
            'publish',
            after_publish='showGroups'
            ))
    else:
        return render_template(
            'delete-host.html',
            group_id=group_id,
            object=object
            )


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
            'name': 'Net ' + form.name.data,
            'subnet4': form.subnet4.data,
            'subnet-mask': form.subnet_mask.data
        }
        call = apiCall('add-network', data, session['sid'])
        flash('Xarxa afegida!')
        session['changes'] += 1
        return redirect(url_for(
            'publish',
            after_publish='showNetworks'
            ))
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
            'name': call['name'],
            'subnet4': call['subnet4'],
            'subnet_mask': call['subnet-mask']
            }
        objects.append(object)
    return render_template('show-networks.html', objects=objects)


# Edit network
@app.route('/set-network/<object_uid>', methods=['GET', 'POST'])
@login_required
def setNetwork(object_uid):
    data = {'uid': object_uid}
    call = apiCall('show-network', data, session['sid'])
    form = NetworkForm(request.form)
    object = {
        'uid': object_uid,
        'name': call['name'],
        'subnet4': call['subnet4'],
        'subnet_mask': call['subnet-mask']
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
        return redirect(url_for(
            'publish',
            after_publish='showNetworks'
            ))
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
        return redirect(url_for(
            'publish',
            after_publish='showNetworks'
            ))
    else:
        return render_template('delete-network.html', object=object)
