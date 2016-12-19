# -*- coding: utf-8 -*-

from flask import request, render_template, redirect, url_for, flash, session
from functools import wraps
from datetime import datetime
import webbrowser

from . import app
from models import api, APIObject, EntityObject
from forms import (
    LoginForm,
    ApplicationSiteForm,
    ApplicationSelectForm,
    HostForm,
    EntityForm)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """login

    Perform a login call to the server, check if any mistake and store username
    in session, also store the SmartView link

    Return: render home page if success or login page if error
    """
    form = LoginForm(request.form)
    # check login is correct
    if request.method == 'POST' and form.validate():
        login = api.login(
            app.config['SERVER'],
            form.username.data,
            form.password.data)
        if 'sid' in login.data:
            # store username in session for header and login_required
            session['username'] = form.username.data
            # link for SmartView
            session['link'] = 'https://' + app.config['SERVER'] +\
                '/smartview/#token=' + login.data['sid'].encode('base64')
            posix = int(login.data['last-login-was-at']['posix']) / 1000
            last_login = datetime.fromtimestamp(posix).strftime(
                'dia %d/%m/%Y a les %H:%M')
            flash(u"La vostra última connexió va ser el %s" % last_login)
            return render_template('home.html', home=True)
        else:
            flash(u"Error d'inici de sessió, torneu a intentar-ho.")
    # login is not correct
    return render_template('login.html', form=form)


def login_required(f):
    """login required

    Wrap the functions that need the user to be logged in to work

    Arguments:
        f - the wrapped function itself

    Return: the function wrapped
    """
    @wraps(f)
    def wrap(*args, **kwargs):
        # if we have a session username
        if 'username' in session:
            # and there is an status-code when we ask to the server
            call = api.api_call('show-login-message')
            if hasattr(call, 'status_code'):
                # and this status_code is 200
                if call.status_code == 200:
                    # then go on
                    return f(*args, **kwargs)
            # either there isn't an status_code but is not 200 or there is not
            # any status_code at all, probably expired, let's clear the session
            session.clear()
            return render_template('session-expired.html')
        # we don't have a session username, so let's get one
        return redirect(url_for('login'))
    return wrap


@app.route('/logout')
def logout():
    """logout

    Perform a logout call to the server and clear the session

    Return: redirect to home
    """
    api.api_call('logout')
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def home():
    """home

    Home page for the application

    Return: render home page
    """
    return render_template('home.html', home=True)


@app.route('/manage-groups')
@login_required
def manageGroups():
    """manage groups

    Show the hosts groups detail and allow create, edit and delete them

    Return: render the manage groups page
    """
    professors = APIObject('GRUP_LlistaEquipsProfessors', 'group').show()
    alumnes = APIObject('GRUP_LlistaEquipsAlumnes', 'group').show()
    return render_template(
        'manage-groups.html',
        professors=professors,
        alumnes=alumnes,
        url_back='manageGroups')


@app.route('/blockIP')
@login_required
def blockIP():
    """block access

    Shows the group and the application-site-group for blocking hosts and URLs

    Return: render the block access page
    """
    group = APIObject('GRUP_LlistaNegraEquips', 'group').show()
    return render_template('block-ip.html', group=group, url_back='blockIP')


@app.route('/show-group-members/<group_name>/<url_back>')
@login_required
def showGroupMembers(group_name, url_back):
    """show group members

    Show the hosts of each group, allow the user to add a new host to the group

    Arguments:
        group_name - the group's name
        url_back - url for redirecting when finished

    Return: render the show group members page
    """
    form = HostForm(request.form)
    members = APIObject(group_name, 'group').show_members()
    return render_template(
        'show-group-members.html',
        members=members,
        form=form,
        group_name=group_name,
        url_back=url_back)


@app.route('/add-host/<group_name>/<url_back>', methods=['GET', 'POST'])
@login_required
def addHost(group_name, url_back):
    """add host
    Add a new host inside a group

    Arguments:
        group_nam - the name of the group where the host has to be added
        url_back - url for redirecting when finished

    Return: if form validates, create the host and add it to the group, if
        doesn't render a page with the errors
    """
    form = HostForm(request.form)
    if request.method == 'POST' and form.validate():
        host = APIObject('HOST_' + form.name.data, 'host')
        add = host.add(ipv4_address=form.ipv4_address.data)
        if not add.success:
            if 'errors' in add.res_obj['data']:
                message = add.res_obj['data']['errors'][0]['message']
                if message[:26] == 'More than one object named':
                    flash('Ja existeix un equip amb aquest nom')
            if 'warnings' in add.res_obj['data']:
                message = add.res_obj['data']['warnings'][0]['message']
                if message[:37] == 'More than one object have the same IP':
                    flash('Ja existeix un equip amb aquesta IP')
        else:
            host.add_to_group('set-group', group_name)
            api.api_call('publish')
            flash('Equip afegit')
        return redirect(url_for(url_back))
    else:
        return render_template(
            'form-errors.html',
            form=form,
            url_back=url_back)


@app.route(
    '/delete-host/<name>/<group_name>/<url_back>',
    methods=['GET', 'POST'])
@login_required
def deleteHost(name, group_name, url_back):
    """delete host

    Delete an existing host

    Arguments:
        name - the name of the host to be deleted
        group_name - the name of the group where the host belongs
        url_back - url for redirecting when finished

    Return: if POST delete the host, if GET render the delete host page
    """
    host = APIObject(name, 'host')
    host_to_delete = host.show()

    if request.method == 'POST':
        host.delete_from_group('set-group', group_name)
        host.delete()

        api.api_call('publish')
        flash('Equip eliminat')
        return redirect(url_for(url_back))

    return render_template(
        'delete-host.html',
        group_name=group_name,
        host_to_delete=host_to_delete,
        url_back=url_back)


@app.route('/set-host/<name>/<url_back>', methods=['GET', 'POST'])
@login_required
def setHost(name, url_back):
    """edit host

    Edit an existing host

    Arguments:
        name - name of the host to be edited
        url_back - url for redirecting when finished

    Return: if form validates edit the host, if doesn't show a page with the
        errors
    """
    form = HostForm(request.form)

    host = APIObject(name, 'host')
    host_to_edit = host.show()

    if request.method == 'POST' and form.validate():
        host.edit(
            new_name=app.config['ID_COLE'] + 'HOST_' + form.name.data,
            ipv4_address=form.ipv4_address.data)
        api.api_call('publish')
        flash('Equip editat')
        return redirect(url_for(url_back))

    return render_template(
        'edit-host.html',
        form=form,
        host_to_edit=host_to_edit,
        url_back=url_back)


@app.route('/blockURL')
@login_required
def blockURL():
    """
    show application-site groups

    show the application-site groups

    return: renders the show application-site groups page
    """
    tots = APIObject(
        'APGR_LlistaNegraURLsTots',
        'application-site-group').show()
    professors = APIObject(
        'APGR_LlistaNegraURLsProfessors',
        'application-site-group').show()
    alumnes = APIObject(
        'APGR_LlistaNegraURLsAlumnes',
        'application-site-group').show()

    return render_template(
        'block-url.html',
        tots=tots,
        professors=professors,
        alumnes=alumnes,
        url_back='blockURL')


@app.route('/show-app-group-members/<name>/<url_back>')
@login_required
def showAppGroupMembers(name, url_back):
    """
    show application-site group content

    shows application group content when selecting a source in the dropdown
    menu while adding a new rule

    argument:
        group_id: the group that's been selected

    return: renders the show application group content page just below the
        select
    """
    form_new_app = ApplicationSiteForm(request.form)
    form_select_app = ApplicationSelectForm(request.form)

    members = APIObject(name, 'application-site-group').show_members()
    choices = APIObject(
        'APGR_GENERAL',
        'application-site-group').show_members()

    options = [('', 'seleccionar')]
    for element in choices:
        already_in_group = False
        for appl in members:
            if element['name'] == appl['name']:
                already_in_group = True
        if not already_in_group:
            options.append((element['name'][5:], element['name'][10:]))
    form_select_app.name.choices = options

    return render_template(
        'show-app-group-members.html',
        form_select_app=form_select_app,
        form_new_app=form_new_app,
        members=members,
        name=name,
        url_back=url_back)


@app.route(
    '/add-existing-application/<group_name>/<url_back>',
    methods=['POST'])
@login_required
def addExistingApplication(group_name, url_back):
    """
    add existing application

    adds an existing host to a group

    arguments:
        host_id: the id of the host to be added to the group
        group_id: the id of the group where the host has to be added

    return: when POST adds the host to the group, if NO renders the
        show groups page
    """
    form = ApplicationSelectForm(request.form)

    appl = APIObject(form.name.data, 'application-site')
    appl.add_to_group('set-application-site-group', group_name)

    api.api_call('publish')
    flash('URL afegida')
    return redirect(url_for(url_back))


@app.route('/add-application-site/<group_name>/<url_back>', methods=['POST'])
@login_required
def addApplicationSite(group_name, url_back):
    """
    add application-site

    add a new application-site inside a group

    arguments:
        group_id: the id number of the application-site groups

    return: renders the show application-sites page
    """
    form = ApplicationSiteForm(request.form)

    if form.validate():

        appl = APIObject('APPL_' + form.name.data, 'application-site')
        appl.add(
            url_list=form.url_list.data,
            primary_category='Custom_Application_Site')  # required
        appl.add_to_group('set-application-site-group', group_name)
        appl.add_to_group('set-application-site-group', 'APGR_GENERAL')
        api.api_call('publish')
        flash('URL afegida')
        return redirect(url_for(url_back))

    # I have to check what to do here
    return redirect(url_for('blockURL'))


@app.route(
    '/delete-application-site/<name>/<group_name>/<url_back>',
    methods=['GET', 'POST'])
@login_required
def deleteApplicationSite(name, group_name, url_back):
    """
    delete application-site

    delete an existing application-site

    arguments:
        app_list: the id number of the application-site groups

    return: renders the show application-sites page
    """
    appl = APIObject(name, 'application-site')
    appl_to_delete = appl.show()

    if request.method == 'POST':

        appl.delete_from_group('set-application-site-group', group_name)

        if appl.where_used() >= 2:
            api.api_call('publish')
            flash(u"La URL pertany a més llistes, no s'elimina totalment")
            return redirect(url_for(url_back))

        appl.delete_from_group('set-application-site-group', 'APGR_GENERAL')

        appl.delete()

        api.api_call('publish')
        flash(u'URL eliminada')
        return redirect(url_for(url_back))

    return render_template(
        'delete-application-site.html',
        group_name=group_name,
        appl_to_delete=appl_to_delete,
        url_back=url_back)


@app.route('/set-application-site/<name>/<url_back>', methods=['GET', 'POST'])
@login_required
def setApplicationSite(name, url_back):
    """
    edit host

    edits an existing host

    arguments:
        object_uid:

    return: renders the show group members page
    """
    form = ApplicationSiteForm(request.form)

    appl = APIObject(name, 'application-site')
    appl_to_edit = appl.show()

    if request.method == 'POST' and form.validate():
        appl.edit(
            new_name=app.config['ID_COLE'] + 'APPL_' + form.name.data,
            url_list=form.url_list.data)
        api.api_call('publish')
        flash('URL editada')
        return redirect(url_for(url_back))

    return render_template(
        'edit-application-site.html',
        form=form,
        appl_to_edit=appl_to_edit,
        url_back=url_back)


@app.route('/block-appl')
@login_required
def blockAppl():
    """
    block access

    shows the group and the application-site-group for blocking hosts and URLs

    return: renders the block access page
    """
    tots = APIObject(
        'APGR_LlistaNegraAplicacionsTots',
        'application-site-group').show()
    professors = APIObject(
        'APGR_LlistaNegraAplicacionsProfessors',
        'application-site-group').show()
    alumnes = APIObject(
        'APGR_LlistaNegraAplicacionsAlumnes',
        'application-site-group').show()

    return render_template(
        'block-appl.html',
        tots=tots,
        professors=professors,
        alumnes=alumnes,
        url_back='blockAppl')


@app.route('/show-appl-group-members/<name>/<url_back>')
@login_required
def showApplGroupMembers(name, url_back):
    """
    show application-site group content

    shows application group content when selecting a source in the dropdown
    menu while adding a new rule

    argument:
        group_id: the group that's been selected

    return: renders the show application group content page just below the
        select
    """
    form_select_app = ApplicationSelectForm(request.form)

    members = APIObject(name, 'application-site-group').show_members()
    choices = APIObject(
        'APGR_APLICACIONS',
        'application-site-group').show_members()

    options = [('', 'seleccionar')]
    for element in choices:
        already_in_group = False
        for appl in members:
            if element['name'] == appl['name']:
                already_in_group = True
        if not already_in_group:
            options.append((element['name'], element['name']))
    form_select_app.name.choices = options

    return render_template(
        'show-appl-group-members.html',
        form_select_app=form_select_app,
        members=members,
        name=name,
        url_back=url_back)


@app.route('/add-existing-appl/<group_name>/<url_back>', methods=['POST'])
@login_required
def addExistingAppl(group_name, url_back):
    """
    add existing application

    adds an existing host to a group

    arguments:
        host_id: the id of the host to be added to the group
        group_id: the id of the group where the host has to be added

    return: when POST adds the host to the group, if NO renders the
        show groups page
    """
    form = ApplicationSelectForm(request.form)

    appl = APIObject(form.name.data, 'application-site')
    appl.name = appl.name[5:]
    appl.add_to_group('set-application-site-group', group_name)

    api.api_call('publish')
    flash(u'Aplicació afegida')
    return redirect(url_for(url_back))


@app.route(
    '/delete-appl/<name>/<group_name>/<url_back>',
    methods=['GET', 'POST'])
@login_required
def deleteAppl(name, group_name, url_back):
    """
    delete application-site

    delete an existing application-site

    arguments:
        app_list: the id number of the application-site groups

    return: renders the show application-sites page
    """
    appl = APIObject(name, 'application-site')
    appl.name = appl.name[5:]
    appl_to_delete = appl.show()

    if request.method == 'POST':

        appl.delete_from_group('set-application-site-group', group_name)

        api.api_call('publish')
        flash(u'Aplicació eliminada')
        return redirect(url_for(url_back))

    return render_template(
        'delete-appl.html',
        group_name=group_name,
        appl_to_delete=appl_to_delete,
        url_back=url_back)


@app.route('/smartview')
@login_required
def smartview():
    """
    edit application-site

    edit an existing application-site

    arguments:
        group_id: the id number of the application-site groups

    return: renders the show application-sites page
    """
    webbrowser.open_new_tab('https://' + app.config['SERVER'] + '/smartview/')
    return redirect(url_for('home'))


@app.route('/create-entity', methods=['GET', 'POST'])
@login_required
def createEntity():
    """
    create entity

    creates all needed groups and application groups for a new entity

    return: renders the show application-sites page
    """
    form = EntityForm(request.form)

    if request.method == 'POST' and form.validate():

        id_entity = form.entity_code.data

        app_groups = [
            'APLICACIONS',
            'GENERAL',
            'LlistaNegraAplicacionsAlumnes',
            'LlistaNegraAplicacionsProfessors',
            'LlistaNegraAplicacionsTots',
            'LlistaNegraURLsAlumnes',
            'LlistaNegraURLsProfessors',
            'LlistaNegraURLsTots']
        groups = [
            'LlistaEquipsAlumnes',
            'LlistaEquipsProfessors',
            'LlistaNegraEquips']

        # create application site groups
        for app_group in app_groups:
            app_group_to_add = EntityObject(
                id_entity + '_APGR_' + app_group,
                'application-site-group')
            app_group_to_add.add()
        # create groups
        for group in groups:
            group_to_add = EntityObject(id_entity + '_GRUP_' + group, 'group')
            group_to_add.add()
        # add-package
        payload = {
            'name': 'Escola_' + id_entity,
            'comments': 'Escola ' + id_entity,
            'color': 'green',
            'threat-prevention': False,
            'access': True}
        api.api_call('add-package', payload)

        # set-access-layer
        payload = {
            'name': 'Escola_' + id_entity + ' Network',
            'applications-and-url-filtering': True,
            'show-parent-rule': False}
        api.api_call('set-access-layer', payload)

        # set-access-rule
        payload = {
            'name': 'Cleanup rule',
            'layer': 'Escola_' + id_entity + ' Network',
            'action': 'Accept',
            'track': 'Log'}
        api.api_call('set-access-rule', payload)

        # add-access-section
        payload = {
            'layer': 'Escola_' + id_entity + ' Network',
            'position': 'top',
            'name': 'Regles definides per escola'}
        api.api_call('add-access-section', payload)

        # add-access-rule
        payload = {
            'layer': 'Escola_' + id_entity + ' Network',
            'position': 1,
            'source': id_entity + '_GRUP_LlistaEquipsProfessors',
            'service': id_entity + '_APGR_LlistaNegraAplicacionsProfessors',
            'destination': 'Any',
            'action': 'Drop',
            'track': 'Log'}
        api.api_call('add-access-rule', payload)

        # add-access-rule
        payload = {
            'layer': 'Escola_' + id_entity + ' Network',
            'position': 1,
            'source': id_entity + '_GRUP_LlistaEquipsAlumnes',
            'service': id_entity + '_APGR_LlistaNegraAplicacionsAlumnes',
            'destination': 'Any',
            'action': 'Drop',
            'track': 'Log'}
        api.api_call('add-access-rule', payload)

        # add-access-rule
        payload = {
            'layer': 'Escola_' + id_entity + ' Network',
            'position': 1,
            'source': id_entity + '_GRUP_LlistaNegraEquips',
            'service': 'Any',
            'destination': 'Any',
            'action': 'Drop',
            'track': 'Log'}
        api.api_call('add-access-rule', payload)

        # add-access-section
        payload = {
            'layer': 'Escola_' + id_entity + ' Network',
            'position': 'bottom',
            'name': 'Regles definides per administradors'}
        api.api_call('add-access-section', payload)

        api.api_call('publish')
        flash(u"Col·legi configurat")

        return redirect(url_for('home', url_back='createEntity'))

    return render_template(
        'create-entity.html',
        form=form,
        url_back='manageGroups')


@app.route('/install-policy')
@login_required
def installPolicy():
    """
    edit application-site

    edit an existing application-site

    arguments:
        group_id: the id number of the application-site groups

    return: renders the show application-sites page
    """
    payload = {
        'access': True,
        'policy-package': 'standard',
        'targets': app.config['TARGETS'],
        'threat-prevention': False}
    api.api_call('install-policy', payload)
    flash(u'Política instal·lada')
    return redirect(url_for('home'))
