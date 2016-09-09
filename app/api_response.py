import json
from httplib import HTTPResponse


class APIResponse:
    def __repr__(self):
        return "cp_mgmt_api::Response"

    def __init__(self, response_object, err_message=""):
        if err_message == "":
            assert isinstance(response_object, HTTPResponse)
            self.status_code = response_object.status
            response_body = response_object.read()

            self.res_obj = {
                "status_code": response_object.status,
                "data": json.loads(response_body)}
            if self.status_code == 200:  # success
                self.data = json.loads(response_body)
                self.success = True
            else:
                self.success = False
                try:
                    self.data = json.loads(response_body)
                    self.error_message = self.data["message"]
                except:
                    self.data = response_body
        else:
            self.success = False
            self.error_message = err_message
            self.res_obj = {}
