# -*- coding: utf-8 -*-

from wtforms import Form, StringField, IntegerField, SelectField, \
    PasswordField, validators


class LoginForm(Form):
    username = StringField('Usuari', [
        validators.InputRequired(
            message="Heu d'introduir un usuari"
            ),
        validators.Length(
            max=8,
            message=u"L'usuari no pot tenir més de 8 caràcters"
            )
        ])

    password = PasswordField('Contrasenya', [
        validators.InputRequired(
            message="Heu d'introduir una contrasenya"
            ),
        validators.Length(
            min=4,
            max=16,
            message=u"La contrasenya ha de tenir entre 4 i 16 caràcters"
            )
        ])


class ApplicationSiteGroupForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=20,
            message=u'El nom no pot tenir més de 20 caràcters'
            )
        ])


class ApplicationSiteForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=25,
            message=u'El nom no pot tenir més de 25 lletres'
            )
        ])

    url_list = StringField(u'URL', [
        validators.InputRequired(
            message=u"Heu d'introduir una descripció"
            ),
        validators.Length(
            max=25,
            message=u'La descripció no pot tenir més de 25 caràcters'
            )
        ])

    description = StringField(u'Descripció', [
        validators.InputRequired(
            message=u"Heu d'introduir una descripció"
            ),
        validators.Length(
            max=25,
            message=u'La descripció no pot tenir més de 25 caràcters'
            )
        ])


class ApplicationSelectForm(Form):
    name = SelectField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            )
        ])


class HostForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=20,
            message=u'El nom no pot tenir més de 20 caràcters'
            )
        ])

    ipv4_address = StringField(u'Adreça IPv4', [
        validators.InputRequired(
            message=u"Heu d'introduir una adreça IPv4"
            ),
        validators.IPAddress(
            ipv4=True,
            ipv6=False,
            message=u"Heu d'introduir una adreça IPv4 vàlida"
            )
        ])


class HostSelectForm(Form):
    name = SelectField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            )
        ])


class NetworkForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=20,
            message=u'El nom no pot tenir més de 20 caràcters'
            )
        ])

    subnet4 = StringField('Subnet IPv4', [
        validators.InputRequired(
            message=u"Heu d'introduir una adreça IPv4"
            ),
        validators.IPAddress(
            ipv4=True,
            ipv6=False,
            message=u"Heu d'introduir una adreça IPv4 vàlida"
            )
        ])

    subnet_mask = StringField(u'Màscara de xarxa', [
        validators.InputRequired(
            message=u"Heu d'introduir una adreça IPv4"
            ),
        validators.IPAddress(
            ipv4=True,
            ipv6=False,
            message=u"Heu d'introduir una adreça IPv4 vàlida"
            )
        ])


class NetworkSelectForm(Form):
    name = SelectField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            )
        ])


class GroupForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=25,
            message=u'El nom no pot tenir més de 25 caràcters'
            )
        ])


class AccessRuleForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=25,
            message=u'El nom no pot tenir més de 25 caràcters'
            )
        ])

    source = SelectField('Origen', [
        validators.InputRequired(
            message=u'Heu de seleccionar una opció'
            )
        ])

    service = SelectField(u'Aplicació', [
        validators.InputRequired(
            message=u'Heu de seleccionar una opció'
            )
        ])

    action = SelectField(u'Acció', [
        validators.InputRequired(
            message=u'Heu de seleccionar una opció'
            )
        ])
