# same as lab1 different only in poc_html

import requests

url = "https://0aed002b04f83dd2c0ce682f00d10033.web-security-academy.net/my-account/change-email"

data = {
	"email": "test@test2.com"
}

cookies = {
	"session": "Y6HpQvGT9AOTLM9TZ4xlJeX1W8qPg6Dt"
}

r = requests.post(url, data=data, cookies=cookies)

print(r.text)