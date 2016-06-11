# -*- coding: utf-8 -*-

import os
import jinja2
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from flask import Flask
from flask_login import LoginManager
from time import strftime
from datetime import datetime


# to avoid request warning of using verify=false
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

app = Flask(__name__)
# config file for development
app.config.from_object('config')

# config file por production
# app.instance_path = os.path.abspath(os.path.join(os.path.dirname(__file__), \
# 	'..'))
# config_file_path = app.instance_path + '/instance/config.py'
# app.config.from_pyfile(config_file_path)


import views


def datetimeformat(value, format='%d/%m/%Y %H:%M'):
    return datetime.fromtimestamp(int(value)/1000).strftime(format)


jinja2.filters.FILTERS['datetimeformat'] = datetimeformat
