# -*- coding: utf-8 -*-

from flask import request, render_template, redirect, url_for, flash, session
from functools import wraps
import webbrowser

from . import app
from models import User
from helpers import *
from cp_mgmt_api import APIClient


# start using CheckpPoint library
api = APIClient()


##########
# MODELS #
##########

class APIObject:

    #
    # initialize class
    #
    def __init__(self, name):
        self.uid = None
        self.name = app.config['ID_COLE'] + name

    def add(self):
        pass

    def show(self):
        payload = {'name': self.name}
        return api.api_call('show' + self.kind, payload).data

    def edit(self):
        pass

    def delete(self):
        pass


class Group(APIObject):

    #
    # initialize class
    #
    def __init__(self):
        self.kind = 'group'


class ApplicationGroup(APIObject):

    #
    # initialize class
    #
    def __init__(self):
        self.kind = 'application-site-group'




    # call for group
    payload = {'name': app.config['ID_COLE'] + 'GRUP_LlistaNegraEquips'}
    group = api.api_call('show-group', payload).data
    # call for application group
    payload = {'name': app.config['ID_COLE'] + 'APGR_LlistaNegraURLs'}
    app_list = api.api_call('show-application-site-group', payload).data




