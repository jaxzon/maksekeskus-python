""" This file is translated from PHP:
https://github.com/maksekeskus/maksekeskus-php/blob/master/lib/Maksekeskus.php
Half of the code is removed because it was not needed. If you need the other half then translate and add it here"""
import logging
import json
import requests
import hashlib
from requests.auth import HTTPBasicAuth
from collections import OrderedDict

logger = logging.getLogger(__name__)


class MKException(Exception):
    raw_content = ''
    logger.error(Exception)


class Maksekeskus:

    SIGNATURE_TYPE_1 = 'V1'
    SIGNATURE_TYPE_2 = 'V2'
    SIGNATURE_TYPE_MAC = 'MAC'

    # Response object of the last API request
    # var object
    last_api_response = None

    @staticmethod
    def extract_request_data(request):
        if hasattr(request, 'content'):
            return json.loads(request.content)
        elif hasattr(request, 'params'):
            return json.loads(request.params['json'])
        else:
            raise MKException('', "Unable to extract data from request")

    @staticmethod
    def extract_request_mac(request):
        if not request.params['mac']:
            raise MKException('', "Unable to extract mac from kwargs")
        return request.params['mac']

    def get_mac_input(self, data, mac_type):
        # MAC = message authentication code
        if not isinstance(data, list):
            if isinstance(data, object):
                pass
            else:
                data = json.loads(data)

        if mac_type == self.SIGNATURE_TYPE_MAC:
            # Received hash is generated in PHP: PHP json.encode orders object by key name. Should to the same here to
            #  make the hashes match
            def sort_ordered_dict(od):
                res = OrderedDict()
                for k, v in sorted(od.items()):
                    if isinstance(v, dict):
                        res[k] = sort_ordered_dict(v)
                    else:
                        res[k] = v
                return res

            od = OrderedDict(sorted(data.items()))
            od = sort_ordered_dict(od)
            # Defining separators is important because php json.encode doesnt put spaces after colon
            mac_input = json.dumps(od, separators=(',', ':'))
            return mac_input

    def get_secret_key(self):
        return self.env['ir.config_parameter'].sudo().get_param('mk.api_key')

    def get_api_url(self):
        return self.env['ir.config_parameter'].sudo().get_param('mk.api_url')

    def get_shop_id(self):
        return self.env['ir.config_parameter'].sudo().get_param('mk.shop_id')

    def create_mac_hash(self, string):
        string_to_hash = string + self.get_secret_key()
        mac_hash = hashlib.sha512(string_to_hash).hexdigest().upper()
        return mac_hash

    def compose_mac(self, data):
        mac_input = self.get_mac_input(data, self.SIGNATURE_TYPE_MAC)
        logger.debug(mac_input)
        return self.create_mac_hash(mac_input)

    """    Verify the MAC of the received request   """

    def verify_mac(self, request):
        try:
            received = self.extract_request_mac(request)
            expected = self.compose_mac(self.extract_request_data(request))
            if received != expected:
                logger.info('MAC is not valid')
                logger.debug('MAC received : ' + received)
                logger.debug('MAC expected : ' + expected)
            return received == expected
        except MKException:
            return False

    def make_api_request(self, method, endpoint, params=None, body=None):
        api_url = self.get_api_url()
        shop_id = self.get_shop_id()
        secret_key = self.get_secret_key()
        uri = api_url + endpoint
        auth_user = shop_id
        auth_pass = secret_key
        if method == 'GET':
            response = requests.get(uri, auth=HTTPBasicAuth(auth_user, auth_pass))
        elif method == 'POST':
            response = requests.post(uri, json=body, auth=HTTPBasicAuth(auth_user, auth_pass))
        elif method == 'PUT':
            response = requests.put(uri, json=body, auth=HTTPBasicAuth(auth_user, auth_pass))
        else:
            return False
        self.last_api_response = response
        return response

    def make_get_request(self, endpoint, params=None):
        return self.make_api_request('GET', endpoint, params)

    def make_post_request(self, endpoint, body=None):
        return self.make_api_request('POST', endpoint, None, body)

    def get_shop(self):
        response = self.make_get_request("/v1/shop")
        if response.status_code == 200:
            return self.extract_request_data(response)
        else:
            raise MKException('', "Could not get shop data")

    def create_transaction(self, request_body):
        response = self.make_post_request('/v1/transactions', request_body)

        if response.status_code in (200, 201):
            return self.extract_request_data(response)
        else:
            raise MKException('', "Could not get create transaction")

    def get_transaction(self, transaction_id):
        uri = "/v1/transactions/" + str(transaction_id)
        response = self.make_get_request(uri)
        if response.status_code == 200:
            return self.extract_request_data(response)
        else:
            raise MKException('', "Could not get transactions")

    def get_transactions(self, params={}):
        request_params = {}
        if params.get('since'):
            request_params['since'] = params['since']
        if params.get('until'):
            request_params['until'] = params['until']
        if params.get('completed_since'):
            request_params['completed_since'] = params['completed_since']
        if params.get('completed_until'):
            request_params['completed_until'] = params['completed_until']
        if params.get('refunded_since'):
            request_params['refunded_since'] = params['refunded_since']
        if params.get('refunded_until'):
            request_params['refunded_until'] = params['refunded_until']
        if params.get('page'):
            request_params['page'] = int(params['page'])
        if params.get('per_page'):
            request_params['per_page'] = int(params['per_page'])
        response = self.make_get_request("/v1/transactions", request_params)
        return self.extract_request_data(response)
