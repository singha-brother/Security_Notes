from bs4 import BeautifulSoup
with open("payloads/machines.html", "r") as f:
	html_doc = f.read()

soup = BeautifulSoup(html_doc, "html.parser")
f = open("boxes.txt", "w")
elements = soup.select("a:nth-child(1) > div:nth-child(1) > div:nth-child(2) > div:nth-child(1) > span:nth-child(2)")
for el in elements:
	text = el.string + "\n"
	f.writelines(text)

f.close()
