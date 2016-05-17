# -*- coding: utf-8 -*-

from wtforms import Form, StringField, IntegerField, validators


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

    subnet4 = StringField('Subnet', [
        validators.InputRequired(
            message=u"Heu d'introduir una adreça IPv4"
            ),
        validators.IPAddress(
            ipv4=True,
            ipv6=False,
            message=u"Heu d'introduir una adreça IPv4 vàlida"
            )
        ])

    mask_length4 = IntegerField(u'Longitud màscara', [
        validators.InputRequired(
            message=u"Heu d'introduir un número"
            ),
        validators.NumberRange(
            min=1,
            max=100,
            message=u"Heu d'introduir un número entre 1 i 100"
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

    description = StringField(u'Descripció', [
        validators.InputRequired(
            message=u"Heu d'introduir una descripció"
            ),
        validators.Length(
            max=25,
            message=u'La descripció no pot tenir més de 25 caràcters'
            )
        ])
