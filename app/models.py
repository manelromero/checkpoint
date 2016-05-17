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


class Host():
    def __init__(self, uid=None, name=None, ipv4_address=None):
        self.uid = uid,
        self.name = name,
        self.ipv4_address = ipv4_address


class ApplicationSite():
    def __init__(self, uid=None, name=None, description=None):
        self.uid = uid,
        self.name = name,
        self.description = description


class Network():
    def __init__(self, uid=None, name=None):
        self.uid = uid,
        self.name = name,


class Group():
    def __init__(self, uid=None, name=None):
        self.uid = uid,
        self.name = name,
