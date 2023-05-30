import os
import sys
import json
import shutil
import asyncio
import requests
from datetime import datetime
from optparse import OptionParser

BASE_URL = 'https://merchant-api.ifood.com.br'


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


class Manager(object):

    def __init__(self):
        self.debug = False
        self.level = 0
        self.base_dir = None
        self.branch = None

    def write_json_file(self, data, file_name, out_folder_path=None):
        folder = resource_path('tmp')
        if type(data) is list:
            new_dict = {file_name: data}
            data = new_dict
        if out_folder_path:
            folder = out_folder_path
        if not os.path.exists(folder):
            os.mkdir(folder)
        dirt = os.path.join(f"{folder}/", f"{file_name}.json")
        try:
            _data = json.dumps(data)
            with open(dirt, 'w') as file:
                file_json = file.write(str(_data))
            shutil.copy(dirt, f'{self.base_dir}/tmp')
            return file_json
        except ValueError:
            print('Error!!!')

    def debug_log(self, msg, end='\n'):
        if self.debug:
            print(msg, end=end)

    async def listen_events(self):
        turns = 0
        while True:
            if turns < 1:
                self.debug_log('Waiting orders...\n')
            if not client.check_token(client.current_token):
                client.get_token()
            events = client.polling_events()
            new_orders = client.get_placed_orders(events)
            # print(new_orders)
            if len(new_orders) > 0:
                file_name = new_orders[0]['displayId']

                # orders = self.extract_data(new_orders)
                # self.write_json_file(orders[0], f'del_{file_name}')

                self.write_json_file(new_orders, f'del_{file_name}')
            self.debug_log(f'\rRolling {turns}...', end='')
            await asyncio.sleep(30)
            turns += 1

    def extract_data(self, orders):
        order_list = []
        item_list = []
        for index, order in enumerate(orders):
            order_data = {
                'loja': f'{self.branch}',
                'palcnum': 'IFOOD',
                'pclddtped': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
                'pclnnum': orders[index]['displayId'],
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

            online = ['IFOOD_ONLINE', 'ALA', 'ALR', 'AM', 'APL_MC', 'APL_VIS', 'CARNET', 'CHF', 'DNR', 'ELO', 'ELOD',
                      'GPY_ELO',
                      'GPY_MC', 'GPY_MXMC', 'GPY_MXVIS', 'GPY_VIS', 'HIPER', 'IFE', 'LPCLUB', 'MC', 'MCMA', 'MOVPAY_AM',
                      'MOVPAY_DNR',
                      'MOVPAY_ELO', 'MOVPAY_HIPER', 'MOVPAY_MC', 'MOVPAY_VIS', 'MPAY', 'MXAM', 'MXMC', 'MXVIS', 'PAY',
                      'PSE', 'SAP',
                      'SRP', 'TAO', 'TOD', 'TRO', 'VA_ON', 'VIS', 'VISE', 'VRO']

            credit = ['BANRC', 'BANRD', 'BENVVR', 'BON', 'CHE', 'CPRCAR', 'CRE', 'DNREST', 'GER_CC', 'GER_CT', 'GER_DC',
                      'GOODC',
                      'GRNCAR', 'GRNCPL', 'MEREST', 'NUGO', 'NUTCRD', 'QRC', 'RAM', 'RDREST', 'REC', 'RED', 'RHIP',
                      'RSELE', 'RSODEX',
                      'TRE', 'TVER', 'VA_OFF', 'VALECA', 'VERDEC', 'VIREST', 'VISAVR', 'VR_SMA', 'VSREST', 'VVREST']

            if orders[index]['payments'][0]['code'] == 'DIN':
                payment_type = '1'
            elif orders[index]['payments'][0]['code'] in credit:
                payment_type = '2'
            else:
                payment_type = '3'

            order_data['cadctpcred'] = payment_type
            order_data['pclcnomcon'] = str(orders[index]['customer']['name']).replace('PEDIDO DE TESTE - ', '')
            order_data['pclchrped'] = datetime.strptime(orders[index]['createdAt'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime(
                "%d/%m/%y")
            order_data[
                'pclcobs'] = f"PRECO TOTAL: {float(orders[index]['totalPrice'])}, TAXA DE ENTREGA: {float(orders[index]['deliveryFee'])}"
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


class IFood(Manager):

    current_token = None
    refresh_token = None
    token_expires = None
    merchant_uuid = None
    categories_id = None
    catalogs_id = None
    merchant_id = None
    confirmed_list = []

    def __init__(self):
        super().__init__()
        self.client_id = None
        self.client_secret = None
        self.username = None
        self.password = None
        self.headers = self.get_headers()
        self.session = requests.Session()

    def get_headers(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) GestordePedidos/6.0.1 "
                          "Chrome/76.0.3809.146 Electron/6.0.12 Safari/537.36",
        }
        return self.headers

    def send_request(self, method, url, **kwargs):
        return self.session.request(method, url, headers=self.headers, **kwargs)

    def get_user_code(self):
        payload = {
            "clientId": self.client_id
        }
        self.headers["content-type"] = "application/x-www-form-urlencoded"
        response = self.send_request("POST",
                                     f'{BASE_URL}/authentication/v1.0/oauth/userCode',
                                     data=payload).json()
        return response

    def set_credentials(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret

    def make_payload(self, refresh_token=None):
        user_data = {}
        if not refresh_token:
            user_data = self.get_user_code()
            print(f'Abra o link no seu navegador e habilite o app {user_data["verificationUrlComplete"]}')
        payload = {
            "grantType": "authorization_code" if not refresh_token else "refresh_token",
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
            "authorizationCode": input("Insira aqui o código gerado no portal: ") if not refresh_token else "",
            "authorizationCodeVerifier": user_data["authorizationCodeVerifier"] if not refresh_token else "",
            "refreshToken": "" if not refresh_token else refresh_token,
        }
        return payload

    def authenticate(self, refresh_token=None):
        payload = self.make_payload(refresh_token)
        self.headers["content-type"] = "application/x-www-form-urlencoded"
        response = self.send_request("POST",
                                     f'{BASE_URL}/authentication/v1.0/oauth/token',
                                     data=payload)
        if response.status_code == 200:
            response = response.json()
            self.current_token = response['accessToken']
            self.token_expires = response['expiresIn']
            self.refresh_token = response['refreshToken']
            self.headers["authorization"] = f"Bearer {self.current_token}"
            return self.current_token
        else:
            return self.debug_log('Fail in authentication!!!')

    def refresh(self, refresh_token):
        return self.authenticate(refresh_token)

    def get_current_token(self):
        return self.current_token

    def save_token(self):
        self.debug_log('Generating and save token...')
        with open(f'{client.branch}/ifood_client.json') as file:
            data = json.load(file)
            data["token"] = self.current_token
            data["refresh_token"] = self.refresh_token
            with open(f'{self.branch}/ifood_client.json', 'w') as file_json:
                file_json.write(json.dumps(data))
        return self.current_token

    def check_token(self, key):
        self.headers["authorization"] = f"Bearer {key}"
        response = self.send_request("GET",
                                     f'{BASE_URL}/merchant/v1.0/merchants')
        if not response:
            return False
        return True

    def get_new_token(self):
        with open(f'{client.branch}/ifood_client.json') as file:
            data = json.load(file)
            refresh_token = data.get("refresh_token")
            if refresh_token:
                self.refresh(refresh_token)
            else:
                self.authenticate()
        return self.save_token()

    def get_token(self):
        with open(f'{self.branch}/ifood_client.json') as file:
            data = json.load(file)
            token = data.get("token")
        if token and self.check_token(token):
            self.current_token = token
            self.debug_log('The token is valid.')
            return self.current_token
        else:
            self.debug_log('Generating new token...')
            return self.get_new_token()

    def polling_events(self):
        response = self.send_request("GET",
                                     f'{BASE_URL}/order/v1.0/events:polling')
        if not response.status_code == 200:
            response = []
        return response.json()

    def get_merchants(self):
        response = self.send_request("GET",
                                     f'{BASE_URL}/merchant/v1.0/merchants').json()
        if response:
            self.merchant_uuid = response[0]['id']
        return self.merchant_uuid

    def get_unavailabilities(self):
        return self.send_request("GET",
                                 f'{BASE_URL}/v1.0/merchants/{self.merchant_uuid}/unavailabilities').json()

    def get_catalogs(self, merchant_id=None):
        if not merchant_id:
            merchant_id = self.merchant_id
        response = self.send_request("GET",
                                     f'{BASE_URL}/v1.0/merchants/{merchant_id}/catalogs').json()
        if response:
            self.catalogs_id = response[0]['id']
        return response

    def get_categories(self, merchant_id=None, catalog_id=None):
        if not merchant_id:
            merchant_id = self.merchant_id
        response = self.send_request("GET",
                                     f'{BASE_URL}/v1.0/merchants/{merchant_id}/catalogs/{catalog_id}/categories').json()
        if response:
            self.categories_id = response[0]['id']
        return response

    def send_recognition(self, reference):
        payload = [
            {"id": "cd40582b-0ef2-4d52-bc7c-507fdff12e21"},
            {"id": "193dccf8-bf1d-4860-85a0-8019f5809877"}
        ]
        self.headers["content-type"] = "application/json"
        return self.send_request("POST",
                                 f'{BASE_URL}/v1.0/events/acknowledgment',
                                 data=payload).json()

    def send_confirmation(self, reference):
        self.headers["content-type"] = "application/json"
        return self.send_request("POST",
                                 f'{BASE_URL}/order/v1.0/orders/{reference}/confirm')

    def save_cache_orders(self, reference):
        with open(f'{self.branch}/orders', 'a') as file:
            file.write(f"{reference},")

    def load_cache_orders(self, reference):
        orders_list = []
        if os.path.exists(f'{self.branch}/orders'):
            with open(f'{self.branch}/orders', 'r') as file:
                orders_list = file.read().split(',')
            if len(orders_list) > 100:
                with open(f'{self.branch}/orders', 'w') as file:
                    file.write('')
        else:
            with open(f'{self.branch}/orders', 'w') as file:
                file.write('')
        if reference not in orders_list:
            return True

    def get_order_details(self, reference):
        return self.send_request("GET",
                                 f'{BASE_URL}/order/v1.0/orders/{reference}').json()

    def get_placed_orders(self, events=None):
        new_orders_list = []
        if events and len(events) > 0:
            for event in events:
                reference_id = event['orderId']
                if self.debug and int(self.level) > 0:
                    if event['fullCode'] == 'PLACED' and reference_id not in self.confirmed_list:
                        if self.load_cache_orders(reference_id):
                            os.system(f'mpg123 {resource_path("src")}/arrived-order.mp3 > /dev/null 2>&1')
                            order_detail = client.get_order_details(reference=reference_id)
                            self.debug_log(f'\n\nNEW ORDER ==>> #{order_detail["displayId"]},\n'
                                           f' value with delivery ==>> {order_detail["total"]["orderAmount"]},\n'
                                           f' reference id ==>> {reference_id}')
                            if int(self.level) > 1:
                                confirm = input('CONFIRM AND ACCEPT ORDER? Y/N: ')
                                if confirm.upper() == 'Y':
                                    self.debug_log('CONFIRMED ORDER!!!\n')
                                    order_confirmed = self.send_confirmation(reference_id)
                                    if order_confirmed.status_code == 202:
                                        self.save_cache_orders(reference_id)
                                    new_orders_list.append(order_detail)
                    elif event['fullCode'] == 'CONFIRMED':
                        if self.load_cache_orders(reference_id):
                            self.confirmed_list.append(reference_id)
                            self.save_cache_orders(reference_id)
                            order_detail = client.get_order_details(reference=reference_id)
                            new_orders_list.append(order_detail)
                elif event['fullCode'] == 'CONFIRMED':
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
                      help="Code generated by ifood, received in your e-mail (merchand_id)"
                           " for integration in yours tests.", default='', type=str)
    parser.add_option("-d", "--directory", dest="directory",
                      help="Base directory for files management", default='./', type=str)
    parser.add_option("-b", "--branch", dest="branch",
                      help="Branch identification number.", default='01', type=str)
    parser.add_option("-v", "--verbose", dest="verbose", action='store_true',
                      help="Outputs log in console.", default=False)

    (options, args) = parser.parse_args()

    client = IFood()

    delivery_dir = os.path.join(options.branch, "delivery")
    client.base_dir = os.path.join(options.directory, options.branch)
    client.branch = os.path.join(options.directory, delivery_dir)

    try:
        del vars(options)['branch']
    except KeyError:
        pass

    if any(vars(options).values()):
        options = vars(options)
        verbose_status = options['verbose']

        if options['verbose']:
            client.debug = True
            if len(args) > 0:
                client.level = args[0]

        if os.path.exists(f'{client.branch}/ifood_client.json'):
            with open(f'{client.branch}/ifood_client.json') as f:
                try:
                    options = json.load(f)
                    options['verbose'] = verbose_status
                except ValueError:
                    os.remove(f'{client.branch}/ifood_client.json')

        if options['verbose'] and options['id'] == '' or options['secret'] == '':
            client.debug_log(
                'Extra arguments needed for authentication are missing.\n'
                'For this first run, check the options with -h or --help.')
            sys.exit(0)
    else:
        if not os.path.exists(f'{client.branch}/ifood_client.json'):
            with open(f'{client.branch}/ifood_client.json', 'w') as f:
                options = client.save_credentials()
        else:
            with open(f'{client.branch}/ifood_client.json') as f:
                try:
                    options = json.load(f)
                except ValueError:
                    os.remove(f'{client.branch}/ifood_client.json')
                    options = client.save_credentials()

    if type(options) == 'optparse.Values' \
            and not vars(options)['verbose'] \
            and vars(options)['id'] == '':
        options = client.save_credentials()

    cli_id = options['id']
    cli_secret = options['secret']
    user = options['username']
    pwd = options['password']
    merchant = options['merchant']

    client.set_credentials(cli_id, cli_secret)

    if merchant != '':
        client.merchant_id = merchant

    if not client.get_token():
        client.authenticate()

    merchant_uuid = client.get_merchants()

    try:
        asyncio.run(client.listen_events())
    except KeyboardInterrupt as e:
        print("\nFechando...")
        quit(0)
