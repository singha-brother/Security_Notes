import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

usernames = "../../../payloads/usernames.txt"
passwords = "../../../payloads/passwords.txt"

with open(usernames, "r") as f:
	usernames = f.readlines()

with open(passwords, "r") as f:
	passwords = f.readlines()

for username in usernames:
	print(username.strip())
url = "https://0a86009703c66522c0d2181300d2002c.web-security-academy.net"

cookies = {
	"session": "zWImcskeCQIF1bYTMqr5UUUe9KBNvtsn"
}


