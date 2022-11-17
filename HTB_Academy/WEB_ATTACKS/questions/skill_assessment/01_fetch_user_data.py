import requests

url = "http://139.59.176.158:31683"

s = requests.Session()
for i in range(1, 101):
	r = s.get(url + f'/api.php/user/{i}')
	print(r.text)