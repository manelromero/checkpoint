class User():
    def __init__(self, uid, username):
        self.uid = uid,
        self.username = username

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.uid)

    def get(self):
        return self


class Network():
    def __init__(self, uid=None, name=None, subnet4=None, mask_length4=None):
        self.uid = uid,
        self.name = name,
        self.subnet4 = subnet4,
        self.mask_length4 = mask_length4

    def order(self):
        return ['name', 'subnet4', 'mask_length4']


class Group():
    def __init__(self, uid=None, name=None):
        self.uid = uid,
        self.name = name,

    def order(self):
        return ['name']


class Host():
    def __init__(self, uid=None, name=None, ipv4_address=None):
        self.uid = uid,
        self.name = name,
        self.ipv4_address = ipv4_address

    def order(self):
        return ['name', 'ipv4_address']


class ApplicationSite():
    def __init__(self, uid=None, name=None, description=None):
        self.uid = uid,
        self.name = name,
        self.description = description

    def order(self):
        return ['name', 'description']

