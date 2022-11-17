import requests
import time 

s = requests.Session()

# url = "https://pokeapi.co/api/v2/ability/"

start_time = time.time()

for i in range(1, 1001):
	# r = s.get(url + str(i))
	r = s.get("http://localhost/dashboard")
	print(f'Content-Length: {len(r.text)} \
		from {url} : status code {r.status_code}')

end_time = time.time()

print("="*60)
print(f"Synchronously 100 requests done in {end_time - start_time}")
print("="*60)