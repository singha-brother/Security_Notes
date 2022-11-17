import requests
import json

url = "http://167.71.131.210:31081"
r = requests.get(url + "/profile/api.php/profile/5")

res = json.loads(r.text)
print(res['uuid'])
