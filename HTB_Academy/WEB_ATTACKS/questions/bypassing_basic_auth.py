import requests
import re

IP = "161.35.173.232:31420"
url = f"http://{IP}/"

session = requests.Session()

r1 = session.get(url + '/admin/reset.php')
print(f"GET method -> {r1.status_code}")

r2 = session.post(url + '/admin/reset.php')
print(f"POST method -> {r2.status_code}")

r3 = session.options(url + '/admin/reset.php')
print(f"OPTIONS method -> {r3.status_code}")

r4 = session.get(url)
answer = re.findall(r'file">(.*)<div>', r4.text)
print(answer[0])