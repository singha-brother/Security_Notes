import requests

s = requests.Session()

url = "http://139.59.176.158:31683"

xml = """<?xml version="1.0" encoding="UTF-8" ?>
<root>
  <username>s.applewhite</username>
  <password>test</password>
</root>
"""

data = {
	"username": "s.applewhite",
	"password": "test"
}

r = s.post(url + "/index.php", data=data)
print(r.text)
print(r.headers)
print(r.status_code)
print(r.cookies)
