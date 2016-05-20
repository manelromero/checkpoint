# -*- coding: utf-8 -*-

from wtforms import Form, StringField, IntegerField, SelectField, validators


class ApplicationSiteForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=20,
            message=u'El nom no pot tenir més de 20 lletres'
            )
        ])

    url_list = StringField("Llista d'URLs", [
        validators.InputRequired(
            message="Heu d'introduir una URL"
            ),
        validators.Length(
            max=30,
            message=u"La llista d'URLs no pot tenir més de 30 lletres"
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


class HostForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=10,
            message=u'El nom no pot tenir més de 10 caràcters'
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


class NetworkForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=15,
            message=u'El nom no pot tenir més de 10 caràcters'
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


class GroupForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=15,
            message=u'El nom no pot tenir més de 10 caràcters'
            )
        ])


class AccessRuleForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=15,
            message=u'El nom no pot tenir més de 10 caràcters'
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

class ApplicationSiteGroup(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=15,
            message=u'El nom no pot tenir més de 10 caràcters'
            )
        ])

    creation_time = SelectField('Creat', [
        validators.InputRequired(
            message=u'Heu de seleccionar una opció'
            )
        ])

    last_modify_time = SelectField('Modificat', [
        validators.InputRequired(
            message=u'Heu de seleccionar una opció'
            )
        ])

