
```
from Ifood.py_food import IFood

client = IFood() 
client.manager.branch = '01' #  Configure branch existent
client.merchant_id = '1234567' #  Optional to get categories or others configurations
client.auth('client_id', 'secret', 'username', 'password')

client.get_token() #  Return current token
merchant_uuid = client.get_merchants() #  Return uuid by merchant
events = client.polling_events() #  Return all events and orders by ifood, use with while 

for reference_id in ["4011395709683044", "1016397702932011"]:
    order_detail = [client.get_order_details(reference=reference_id)]
    file_name = order_detail[0]['shortReference']
    print('ORDER #', file_name)

    client.manager.write_json_file(order_detail, f'del_{file_name}')
```

**Instalation with pip:**

``
pip3 install git+https://github.com/cleitonleonel/Pyfood.git
``

**Generate Executable with Pyinstaller:**

``
pyinstaller --onefile --windowed py_food.py
``

**Simple Ifood Listener**

`Usage: py_food.py [options]
`

_Get orders and order information from ifood confirmed by the restaurant._

_INFO: Confirmed orders can take 30 to 40 seconds to obtain._

Options:
  ~~~~-version             show program's version number and exit
  -h, --help            show this help message and exit
  -i ID, --id=ID        Cliente identification obtained from ifood
                        (client_id).
  -s SECRET, --secret=SECRET
                        Code generated by ifood, for API authentication
                        (client_secret).
  -u USERNAME, --username=USERNAME
                        User generated by ifood, received in your e-mail
                        (username), the same used by the store to access the order manager.
  -p PASSWORD, --password=PASSWORD
                        Pass generated by ifood, received in your e-mail
                        (password), the same used by the store to access the order manager.
  -m MERCHANT, --merchant=MERCHANT
                        Code generated by ifood, received in your e-mail
                        (merchand_id) for integration in yours tests, that is, the merchant id next to ifood.
  -b BRANCH, --branch=BRANCH
                        Branch identification number.
  -v, --verbose         Outputs log in console.
