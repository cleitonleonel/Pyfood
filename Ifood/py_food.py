#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
import os
import sys
import json
import time
import shutil
import requests
from datetime import datetime
from threading import Thread
from optparse import OptionParser

BASE_URL = 'https://pos-api.ifood.com.br'


def resource_path(relative_path):
    try:
        this_file = __file__
    except NameError:
        this_file = sys.argv[0]
    this_file = os.path.abspath(this_file)

    if getattr(sys, 'frozen', False):
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    else:
        base_path = os.path.dirname(this_file)

    return os.path.join(base_path, relative_path)


class Manager:

    def __init__(self):
        self.debug = False
        self.level = 0
        self.branch = '01'

    def write_json_file(self, data, file_name, out_folder_path=None):
        folder = resource_path('tmp')

        if type(data) is list:
            new_dict = {file_name: data}
            data = new_dict
        if out_folder_path:
            folder = out_folder_path
        if not os.path.exists(folder):
            os.mkdir(folder)
        dirt = os.path.join(folder + '/', file_name + '.json')
        try:
            _data = json.dumps(data)
            with open(dirt, 'w') as file:
                file_json = file.write(str(_data))
            shutil.copy(dirt, f'{self.branch}/tmp')
            return file_json
        except ValueError:
            print('Error!!!')

    def debug_log(self, msg, end='\n'):
        if self.debug:
            print(msg, end=end)

    def listen_events(self):
        turns = 0
        while True:
            if turns < 1:
                self.debug_log('Waiting orders...\n')
            if not client.check_token(client.current_token):
                client.get_token()
            events = client.polling_events()
            new_orders = client.get_placed_orders(events)
            if len(new_orders) > 0:
                file_name = new_orders[0]['shortReference']

                # orders = self.extract_data(new_orders)
                # self.write_json_file(orders[0], f'del_{file_name}')

                self.write_json_file(new_orders, f'del_{file_name}')
            self.debug_log(f'\rI RODE {turns} TIMES...', end='')
            time.sleep(30)
            turns += 1

    def extract_data(self, orders):
        order_list = []
        item_list = []
        for index, order in enumerate(orders):
            order_data = {
                'loja': f'{self.branch}',
                'palcnum': 'IFOOD',
                'pclddtped': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
                'pclnnum': orders[index]['shortReference'],
                'cpf_cnpj': orders[index]['customer']['taxPayerIdentificationNumber']
            }

            if orders[index]['deliveryMethod']['mode'] == 'DELIVERY':
                order_type = '1'
            else:
                order_type = '2'

            order_data['deliver_address'] = {
                'formated_address': orders[index]['deliveryAddress']['formattedAddress'],
                'city': orders[index]['deliveryAddress']['city'],
                'neighborhood': orders[index]['deliveryAddress']['neighborhood'],
                'street_name': orders[index]['deliveryAddress']['streetName'],
                'street_number': orders[index]['deliveryAddress']['streetNumber'],
                'postal_code': orders[index]['deliveryAddress']['postalCode'],
                'reference': orders[index]['deliveryAddress']['reference'],
                'complement': orders[index]['deliveryAddress']['complement']
            }

            order_data['pclctp'] = order_type

            online = ['IFOOD_ONLINE', 'ALA', 'ALR', 'AM', 'APL_MC', 'APL_VIS', 'CARNET', 'CHF', 'DNR', 'ELO', 'ELOD', 'GPY_ELO',
                      'GPY_MC', 'GPY_MXMC', 'GPY_MXVIS', 'GPY_VIS', 'HIPER', 'IFE', 'LPCLUB', 'MC', 'MCMA', 'MOVPAY_AM', 'MOVPAY_DNR',
                      'MOVPAY_ELO', 'MOVPAY_HIPER', 'MOVPAY_MC', 'MOVPAY_VIS', 'MPAY', 'MXAM', 'MXMC', 'MXVIS', 'PAY', 'PSE', 'SAP',
                      'SRP', 'TAO', 'TOD', 'TRO', 'VA_ON', 'VIS', 'VISE', 'VRO']

            credit = ['BANRC', 'BANRD', 'BENVVR', 'BON', 'CHE', 'CPRCAR', 'CRE', 'DNREST', 'GER_CC', 'GER_CT', 'GER_DC', 'GOODC',
                      'GRNCAR', 'GRNCPL', 'MEREST', 'NUGO', 'NUTCRD', 'QRC', 'RAM', 'RDREST', 'REC', 'RED', 'RHIP', 'RSELE', 'RSODEX',
                      'TRE', 'TVER', 'VA_OFF', 'VALECA', 'VERDEC', 'VIREST', 'VISAVR', 'VR_SMA', 'VSREST', 'VVREST']

            if orders[index]['payments'][0]['code'] == 'DIN':
                payment_type = '1'
            elif orders[index]['payments'][0]['code'] in credit:
                payment_type = '2'
            else:
                payment_type = '3'

            order_data['cadctpcred'] = payment_type
            order_data['pclcnomcon'] = str(orders[index]['customer']['name']).replace('PEDIDO DE TESTE - ', '')
            order_data['pclchrped'] = datetime.strptime(orders[index]['createdAt'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%d/%m/%y")
            order_data['pclcobs'] = f"PRECO TOTAL: {float(orders[index]['totalPrice'])}, TAXA DE ENTREGA: {float(orders[index]['deliveryFee'])}"
            order_data['pclnvalor'] = float(orders[index]['subTotal'])
            order_data['pclnqtdit'] = str(len(orders[index]['items']))

            for cont, item in enumerate(orders[index]['items']):
                item_dict = {
                    'pclnitem': orders[index]['items'][cont]['index'],
                    'proncod': orders[index]['items'][cont]['externalCode'],
                    'pclnqtd': orders[index]['items'][cont]['quantity'],
                    'pclnpreco': orders[index]['items'][cont]['price'],
                    'pclcpenden': str(orders[index]['items'][cont]['name'])
                }

                item_list.append(item_dict)

            order_data['items'] = item_list

            order_list.append(order_data)

        return order_list

    def save_credentials(self):
        with open(f'{self.branch}/ifood_client.json', 'w') as file:
            credentials = {
                'id': input('Entry your client_id: '),
                'secret': input('Entry your client_secret: '),
                'username': input('Entry your client_username: '),
                'password': input('Entry your client_password: '),
                'merchant': input('Entry your id_merchant: ')
            }
            file.write(json.dumps(credentials))

        return credentials


class IFood:

    def __init__(self):
        self.client_id = None
        self.client_secret = None
        self.username = None
        self.password = None
        self.current_token = None
        self.token_expires = None
        self.merchant_uuid = None
        self.categories_id = None
        self.merchant_id = None
        self.confirmed_list = []
        self.manager = Manager()
        self.session = requests.Session()

    def headers(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) GestordePedidos/6.0.1 Chrome/76.0.3809.146 Electron/6.0.12 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cache-Control": "no-cache"
        }
        return headers

    def send_request(self, method, url, **kwargs):
        try:
            response = self.session.request(method, url, **kwargs)
        except:
            return None
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                return []
        else:
            return response

    def auth(self, client_id, client_secret, username, password):
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password

        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "password",
            "username": self.username,
            "password": self.password
        }

        with self.session as s:
            response = s.post(f'{BASE_URL}/oauth/token', data=payload, headers=self.headers())

        if response.status_code == 200:
            response = response.json()
            self.current_token = response['access_token']
            self.token_expires = response['expires_in']
            return self.current_token
        else:
            return self.manager.debug_log('Fail in authentication!!!')

    def reconnect(self):
        return self.auth(self.client_id, self.client_secret, self.username, self.password)

    def get_current_token(self):
        return self.current_token

    def save_token(self):
        self.reconnect()
        with open(f'{self.manager.branch}/token', 'w') as file:
            file.write(self.current_token)
        return self.current_token

    def check_token(self, key):
        headers = {
            "Authorization": "Bearer " + key
        }
        response = self.send_request('GET', f'{BASE_URL}/v1.0/merchants', headers=headers)
        if not response:
            return False
        return True

    def get_new_token(self):
        return self.save_token()

    def get_token(self):
        if os.path.exists(f'{self.manager.branch}/token'):
            with open(f'{self.manager.branch}/token') as file:
                key = file.read()
            if self.check_token(key):
                self.current_token = key
                self.manager.debug_log('The token is valid.')
                return self.current_token
            else:
                self.manager.debug_log('Generating new token...')
                return self.get_new_token()
        else:
            self.reconnect()
            if not self.current_token:
                sys.exit(0)
            with open(f'{self.manager.branch}/token', 'w') as file:
                file.write(self.current_token)

            self.manager.debug_log('Generating and save token...')

        return self.current_token

    def polling_events(self):
        headers = {
            "Authorization": "Bearer " + self.current_token
        }
        response = self.send_request('GET', f'{BASE_URL}/v3.0/events:polling', headers=headers)
        if not response:
            response = []
        return response

    def get_merchants(self):
        headers = {
            "Authorization": "Bearer " + self.current_token
        }
        response = self.send_request('GET', f'{BASE_URL}/v1.0/merchants', headers=headers)
        if response:
            self.merchant_uuid = response[0]['id']
        return self.merchant_uuid

    def get_unavailabilities(self):
        headers = {
            "Authorization": "Bearer " + self.current_token
        }
        return self.send_request('GET', f'{BASE_URL}/v1.0/merchants/{self.merchant_uuid}/unavailabilities', headers=headers)

    def get_categories(self, merchant_id=None):
        if not merchant_id:
            merchant_id = self.merchant_id
        headers = {
            "content-type": "application/json",
            "authorization": "Bearer " + self.current_token
        }
        response = self.send_request('GET', f'{BASE_URL}/v1.0/merchants/{merchant_id}/menus/categories', headers=headers)
        if response:
            self.categories_id = response[0]['id']
        return response

    def send_recognition(self, reference):
        headers = {
            "Authorization": "Bearer " + self.current_token,
            "Content-Type": "application/json",
            "Cache-Control": "no-cache"
        }
        return self.send_request('POST', f'{BASE_URL}/v1.0/events/acknowledgment', data=reference, headers=headers)

    def send_integration(self, reference):
        headers = {
            "Authorization": "Bearer " + self.current_token,
            "Content-Type": "application/json",
            "Cache-Control": "no-cache"
        }
        return self.send_request('POST', f'{BASE_URL}/v1.0/orders/{reference}/statuses/integration', headers=headers)

    def send_confirmation(self, reference):
        headers = {
            "Authorization": "Bearer " + self.current_token,
            "Content-Type": "application/json",
            "Cache-Control": "no-cache"
        }
        return self.send_request('POST', f'{BASE_URL}/v1.0/orders/{reference}/statuses/confirmation', headers=headers)

    def save_cache_orders(self, reference):
        with open(f'{self.manager.branch}/orders', 'a') as file:
            file.write(reference + ',')

    def load_cache_orders(self, reference):
        orders_list = []
        if os.path.exists(f'{self.manager.branch}/orders'):
            with open(f'{self.manager.branch}/orders', 'r') as file:
                orders_list = file.read().split(',')
            if len(orders_list) > 100:
                with open(f'{self.manager.branch}/orders', 'w') as file:
                    file.write('')
        else:
            with open(f'{self.manager.branch}/orders', 'w') as file:
                file.write('')
        if reference not in orders_list:
            return True

    def get_order_details(self, reference):
        headers = {
            "Authorization": "Bearer " + self.current_token
        }
        return self.send_request('GET', f'{BASE_URL}/v3.0/orders/{reference}', headers=headers)

    def get_placed_orders(self, events=None):
        new_orders_list = []
        if events and len(events) > 0:
            for event in events:
                reference_id = event['correlationId']
                if self.manager.debug and int(self.manager.level) > 0:
                    if event['code'] == 'PLACED' and reference_id not in self.confirmed_list:
                        if self.load_cache_orders(reference_id):
                            os.system(f'mpg123 {resource_path("tmp")}/arrived-order.mp3 > /dev/null 2>&1')

                            order_detail = client.get_order_details(reference=reference_id)
                            self.manager.debug_log(f'\nNEW ORDER ==>> #{order_detail["shortReference"]},\n'
                                                   f' value with delivery ==>> {order_detail["totalPrice"]},\n'
                                                   f' reference id ==>> {reference_id}')

                            if int(self.manager.level) > 1:
                                confirm = input('CONFIRM AND ACCEPT ORDER? Y/N: ')

                                if confirm.upper() == 'Y':
                                    self.manager.debug_log('CONFIRMED ORDER!!!')
                                    self.send_integration(reference_id)
                                    order_confirmed = self.send_confirmation(reference_id)
                                    if order_confirmed.status_code == 202:
                                        self.save_cache_orders(reference_id)
                                    new_orders_list.append(order_detail)

                    elif event['code'] == 'CONFIRMED':
                        if self.load_cache_orders(reference_id):
                            self.confirmed_list.append(reference_id)
                            self.save_cache_orders(reference_id)
                            order_detail = client.get_order_details(reference=reference_id)
                            new_orders_list.append(order_detail)

                elif event['code'] == 'CONFIRMED':
                    if self.load_cache_orders(reference_id):
                        self.save_cache_orders(reference_id)
                        order_detail = client.get_order_details(reference=reference_id)
                        new_orders_list.append(order_detail)
        return new_orders_list


if __name__ == '__main__':
    description = 'Get orders and order information from ifood confirmed by the restaurant \n\n' \
                  'INFO: Confirmed orders can take 30 to 40 seconds to obtain.'

    usage = "USAGE: %prog [options]\n\nSimple Ifood Listener"

    parser = OptionParser(usage=usage, version='%prog 0.1', description=description)
    parser.add_option("-i", "--id", dest="id",
                      help="Cliente identification obtained from ifood (client_id).", default='', type=str)
    parser.add_option("-s", "--secret", dest="secret",
                      help="Code generated by ifood, for API authentication (client_secret).", default='', type=str)
    parser.add_option("-u", "--username", dest="username",
                      help="User generated by ifood, received in your e-mail (username).", default='', type=str)
    parser.add_option("-p", "--password", dest="password",
                      help="Pass generated by ifood, received in your e-mail (password).", default='', type=str)
    parser.add_option("-m", "--merchant", dest="merchant",
                      help="Code generated by ifood, received in your e-mail (merchand_id) for integration in yours tests.", default='', type=str)
    parser.add_option("-b", "--branch", dest="branch",
                      help="Branch identification number.", default='01', type=str)
    parser.add_option("-v", "--verbose", dest="verbose", action='store_true',
                      help="Outputs log in console.", default=False)

    (options, args) = parser.parse_args()

    client = IFood()

    client.manager.branch = options.branch

    try:
        del vars(options)['branch']
    except KeyError:
        pass

    if any(vars(options).values()):
        options = vars(options)
        verbose_status = options['verbose']

        if options['verbose']:
            client.manager.debug = True
            if len(args) > 0:
                client.manager.level = args[0]

        if os.path.exists(f'{client.manager.branch}/ifood_client.json'):
            with open(f'{client.manager.branch}/ifood_client.json') as f:
                try:
                    options = json.load(f)
                    options['verbose'] = verbose_status
                except ValueError:
                    os.remove(f'{client.manager.branch}/ifood_client.json')

        if options['verbose'] and options['id'] == '' or options['secret'] == '':
            client.manager.debug_log(
                'Extra arguments needed for authentication are missing.\n'
                'For this first run, check the options with -h or --help.')
            sys.exit(0)
    else:
        if not os.path.exists(f'{client.manager.branch}/ifood_client.json'):
            with open(f'{client.manager.branch}/ifood_client.json', 'w') as f:
                options = client.manager.save_credentials()
        else:
            with open(f'{client.manager.branch}/ifood_client.json') as f:
                try:
                    options = json.load(f)
                except ValueError:
                    os.remove(f'{client.manager.branch}/ifood_client.json')
                    options = client.manager.save_credentials()

    if type(options) == 'optparse.Values' and not vars(options)['verbose'] and vars(options)['id'] == '':
        options = client.manager.save_credentials()

    cli_id = options['id']
    cli_secret = options['secret']
    user = options['username']
    pwd = options['password']
    merchant = options['merchant']

    if merchant != '':
        client.merchant_id = merchant

    client.auth(client_id=cli_id, client_secret=cli_secret, username=user, password=pwd)

    token = client.get_token()

    merchant_uuid = client.get_merchants()

    thread_1 = Thread(target=client.manager.listen_events, args=[])
    thread_1.start()
