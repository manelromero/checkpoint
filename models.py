class User():
	""" User class """
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
	""" Host class """
	def __init__(self, uid, name, ip_address):
		self.uid = uid,
		self.name = name,
		self.ip_address = ip_address