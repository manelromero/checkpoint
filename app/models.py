from . import app
from cp_mgmt_api import APIClient


# CheckpPoint library
api = APIClient()


# function for replacing '-' with '_' in lists and dictionaries
def underscore(data):
    # if is a list
    if isinstance(data, list):
        for element in data:
            for key, value in element.iteritems():
                element[key.replace('-', '_')] = element.pop(key)
    # if is a dictionary
    if isinstance(data, dict):
        for key, value in data.iteritems():
            data[key.replace('-', '_')] = data.pop(key)
    return data


class APIObject:
    #
    # initialize class
    #
    def __init__(self, name, kind=''):
        self.name = app.config['ID_COLE'] + name
        self.kind = kind
        self.uid = None

    def add(self, **kwargs):
        payload = {'name': self.name}
        for element in kwargs:
            payload[element.replace('_', '-')] = kwargs[element]
        return api.api_call('add-' + self.kind, payload)

    def add_to_group(self, action, group_name):
        payload = {
            'name': app.config['ID_COLE'] + group_name,
            'members': {'add': self.name}}
        return api.api_call(action, payload)

    def show(self, details_level='standard'):
        payload = {'name': self.name, 'details-level': details_level}
        call = api.api_call('show-' + self.kind, payload).data
        return underscore(call)

    def show_members(self):
        call = self.show('full')
        underscore(call['members'])
        return self.order(call['members'])

    def order(self, list, field='name'):
        return sorted(list, key=lambda element: (element[field]))

    def edit(self, **kwargs):
        payload = {'name': self.name}
        for element in kwargs:
            payload[element.replace('_', '-')] = kwargs[element]
        return api.api_call('set-' + self.kind, payload)

    def delete(self):
        payload = {'name': self.name}
        return api.api_call('delete-' + self.kind, payload)

    def delete_from_group(self, action, group_name):
        payload = {
            'name': app.config['ID_COLE'] + group_name,
            'members': {'remove': self.name}}
        return api.api_call(action, payload)

    def where_used(self):
        payload = {'name': self.name}
        call = api.api_call('where-used', payload).data
        return call['used-directly']['total']


class EntityObject(APIObject):
    #
    # initialize class
    #
    def __init__(self, name, kind):
        APIObject.__init__(self, name, kind)
        self.name = name
        self.kind = kind
