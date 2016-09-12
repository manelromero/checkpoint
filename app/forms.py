# -*- coding: utf-8 -*-

from wtforms import Form, StringField, SelectField, PasswordField, validators


class LoginForm(Form):
    username = StringField('Usuari', [
        validators.InputRequired(
            message="Heu d'introduir un usuari"),
        validators.Length(
            max=16,
            message=u"L'usuari no pot tenir més de 16 caràcters")])
    password = PasswordField('Contrasenya', [
        validators.InputRequired(
            message="Heu d'introduir una contrasenya"),
        validators.Length(
            min=4,
            max=16,
            message=u"La contrasenya ha de tenir entre 4 i 16 caràcters")])


class ApplicationSiteGroupForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"),
        validators.Length(
            max=20,
            message=u'El nom no pot tenir més de 20 caràcters')])


class ApplicationSiteForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"),
        validators.Length(
            max=35,
            message=u'El nom no pot tenir més de 35 lletres')])
    url_list = StringField(u'URL', [
        validators.InputRequired(
            message=u"Heu d'introduir una URL"),
        validators.Length(
            max=35,
            message=u'La URL no pot tenir més de 35 caràcters')])


class ApplicationSelectForm(Form):
    name = SelectField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom")])


class HostForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message=u"Heu d'introduir un nom per l'equip"),
        validators.Length(
            max=35,
            message=u"El nom de l'equip no pot tenir més de 35 caràcters")])
    ipv4_address = StringField(u'Adreça IPv4', [
        validators.InputRequired(
            message=u"Heu d'introduir una adreça IPv4"),
        validators.IPAddress(
            ipv4=True,
            ipv6=False,
            message=u"Heu d'introduir una adreça IPv4 vàlida")])


class HostSelectForm(Form):
    name = SelectField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom")])


class GroupForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"),
        validators.Length(
            max=25,
            message=u'El nom no pot tenir més de 25 caràcters')])


class EntityForm(Form):
    entity_code = StringField('Codi', [
        validators.InputRequired(
            message="Heu d'introduir un codi"),
        validators.Length(
            max=4,
            message=u'El nom no pot tenir més de 4 caràcters')])
