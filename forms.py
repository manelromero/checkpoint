from wtforms import Form, StringField, validators


class HostForm(Form):
    name = StringField('Name', [
        validators.InputRequired(message =
            'You have to introduce a name'
            ),
        validators.Length( max = 10,
            message='The name cannot be longer than 10 characters'
            )
        ])
    ip_address = StringField('IP address', [
        validators.InputRequired(message =
            'You have to introduce an IP address'
            ),
        validators.IPAddress(ipv4 = True, ipv6 = False,
            message='You have to introduce a valid IP address'
            )
        ])
