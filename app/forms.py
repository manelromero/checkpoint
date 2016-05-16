# -*- coding: utf-8 -*-

from wtforms import Form, StringField, validators


class HostForm(Form):
    name = StringField('Nom', [
        validators.InputRequired(
            message="Heu d'introduir un nom"
            ),
        validators.Length(
            max=10,
            message='El nom no pot tenir més de 10 caràcters'
            )
        ])

    ip_address = StringField(u'Adreça IP', [
        validators.InputRequired(
            message=u"Heu d'introduir una adreça IP"
            ),
        validators.IPAddress(
            ipv4=True,
            ipv6=False,
            message=u"Heu d'introduir una adreça IP vàlida"
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