## What is HTTP Host Header?

- mandatory request header as of HTTP/1.1
- specifies the domain name that the client wants to access
- eg - when a user visits `https://portswigger.net/web-security`, the browser will compose a request containing a Host header as follows:

```
GET /web-security HTTP/1.1
Host: portswigger.net
...
```

## Purpose of Host Header

- help to identify which back-end component the client wants to communicate with
- if requests didn't contain Host headers, or if the Host header was malformed in some way, this could lead to issues when routing incoming requests to the intended application
- nowadays, multiple websites and applications to be accessible at the same IP address by

### Virtual hosting

- single web server hosts multiple websites or applications
- this could be multiple websites with a single owner, or websites with different owners to be hosted on a single, shared platform
- although each of these distinct websites will have a different domain name, they all share a common IP address with the server
- websites hosted in this way on a single server are known as "virtual hosts"

### Routing traffic via an intermediary

- websites are hosted on distinct back-end servers but all traffic between teh client and servers are routed through an intermediary system
- this could be a simple load balancer or a reverse proxy server of some kind
- prevalent in cases where clients access the website via a content delivery network (CDN)
- even though the websites are hosted on separate back-end servers, all of their domain names resolve to a single IP address of the intermediary component
- problem is the reverse proxy or load balancer needs to know the appropriate back-end to which it should route each request

## How does the HTTP Host header solve the problem?

- when a browser sends the request, the target URL will resolve to the IP address of a particular server
- when the server receives the request, it refers to the Host Header to determine the intended back-end and forwards the request accordingly

## What is an HTTP Host Header attack?

- HTTP host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way
- If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior
- attacks that involve injecting a payload directly into the Host header are known as `Host header injection` attacks

- As Host header is user controllable, and can lead to a number of issues
- Example

  - Web cache poisoning
  - Business logic flaws in specific functionality
  - Routing-based SSRF
  - Classic server-side vulnerabilities such as SQLi

- Many of these vulnerabilities arise not because of insecure coding but because of insecure configuation of one or more components in the related infrastructure

## How to test

- you need to identify whether you are able to modify the Host header and still reach the target application with your request
- if so, you can use this header to probe the application and observe what effect this has on the response

### 1) Supply an arbitary Host header

- test what happens when you supply an arbitary, unreconized domain via the Host header
- any changes you made to the header would cause the request to be sent to a completely different IP address?
- still be able to access the target website even when you supply an unexpected configured with a default or fallback option ?
- if so, begin studying what the application does with the Host header and whether this behavior is exploitable
- Host header is a fundamental part of how the websites work, and you will be unable to reach the target application at all after tempering with it
- the front-end server or load balancer that received your request may simply not know where to forward it and resulting in an `Invalid Host Header` error.
- if so, you should move on to trying some of the techniques outlined below

### 2) Check for flawed validation

- Instead of receiving an `Invalid Host header` response, your request is blocked as a result of some kind of security measure
- eg - some websites will validate whether the Host header matches the SNI from the TLS handshake
- try to understand how the website parses the Host header
- eg - some parsing algorithms will omit the port from the Host header
- inject through port

```
GET /example HTTP/1.1
Host: vulnerable-website.com:bad-stuff-here
```

- other websites try to apply matching logic to allow for arbitary subdomains and able to bypass the validation entirely by registering an arbitary domain name that ends with the same sequence of characters as a whitelisted one:
- inject by adding `not` in front of valid domain

```
GET /example HTTP/1.1
Host: notvulnerable-website.com
```

OR

```
GET /example HTTP/1.1
Host: hacked-subdomain.vulnerable-website.com
```

- further examples - `circumventing common SSRF defences`, `origin header parsing errors (CORS)`

### 3) Send ambiguous requests

(i) Inject duplicate Host headers

- try adding duplicate Host headers
- often just result in the request being blocked

```
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
```

- if front-end gives precedence to the first instance of the header, but the back-end prefers the final instance

(ii) Supply an absolute URL

```
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here
```

- need to experiment with different protocols
- servers sometimes behave differently depending on whether the request line contains an HTTP or HTTPS url

(iii) Add line wrapping

```
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```

- front-end may ignore the indented header, backend may ignore the leading space

(iv) Other techniques (`HTTP request smuggling`)

### 4) Inject host override headers

- overriding its value while leaving it intact
- when an `X-Forwarded-Host` header is present, many frameworks will refer to this instead

```
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```

Other headers - `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Host`

- Burp -> Param Miner extension's Guess headers function

## How to exploit

- Password reset poisoning
- Web cache poisoning
- Exploiting classic server-side vulnerabilities
- Bypassing authentication
- Virtual host brute-forcing
- Routing-based SSRF

### Password Reset Poisoning

- technique whereby an attacker manipulates a vulnerable website into generating a password reset link pointing to a domain under their control
- can be leveraged to steal the secret tokens required to reset arbitary users' password and compromise the accounts

#### **How does a password reset work?**

There are several ways of doing this and one of most common approaches like this

1. The user enters their username or email address and submits a password reset request
2. website checks that this user exists
3. generates a temporary unique high-entropy token which it associates with the user's account on the back-end
4. website sends an email to the user that contains a link for resetting their password
5. user's unique reset token is included as a query parameter in the corresponding URL for example - `https://normal-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j`
6. when user visits this URL, the website checks whether the provided token is valid and uses it to determine which account is being reset
7. If everything is as expected, the user is given the option to enter a new password
8. Finally, the token is destroyed.

- The security relies on the principle that only the intended user has access to their email inbox
- Password reset poisoning is a method of stealing this token in order to change another user's password

#### **How to construct a password reset poisoning attack?**

If the URL that is sent to the user is dynamically generated based on controllable input, such as the Host header, it may be possible to construct a password reset poisoning attack as follow.

1. The attacker obtains the victim's email address or username as required and submits a password reset request on their behalf
2. When submitting the form, they intercept the resulting HTTP request and modify the Host header so that it points to a domain that they control, eg - `evil-user.net`
3. Victim receives a genuine password reset email directly from the website. This seems to contain an ordinary link to reset their password and contains a valid password reset token that is associated with their account. But the domain name in the URL points to the attacker's server. eg - `https://evil-user.net/reset?token=0a1q2w3e4r5t5rdd`
4. If the victim clicks this link, the password reset token will be delivered to the attacker's server
5. The attacker can now visit the real URL for the vulnerable website and supply the victim's stolen token via the corresponding parameter and will be able to reset the user's password to whatever they like and subsequently log in to their account

### Web cache poisoning via the Host header

### Exploiting classic server-side vulnerabilities

- every HTTP header is a potential vector for exploiting classic server-side vulnerabilities
- eg - try the usual SQL injection

### Accessing restricted functionality

- some websites' access control features make flawed assumptions that allow you to bypass these restrictions by making simple modifications to the Host header

### Web cache poisoning via Host header

- you may find that the Host Header is reflected in the response markup without HTML-encoding, even used directly in script imports

### Accessing internal websites with virtual host brute-forcing

- sometimes, companies have public and private websites on the same server

```
www.example.com: 12.34.56.78
intranet.example.com: 10.0.0.132
```

### Routing based SSRF

- sometimes it is possible to use the Host Header to launch routing based SSRF attacks
- can use Burp Collaborator to identify these vulnerabiliites
- supply domain of Collaborator server in the Host Header and if receive the DNS lookup from the target server or another inpath system, and indicates that it may be able to route requests to arbitary domain
- then try to identify private IP addess that are in use on the target's internal network such as 192.168.0.0/16, 10.0.0.0/8
