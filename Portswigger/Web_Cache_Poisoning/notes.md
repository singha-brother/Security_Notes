## What is web cache poisoning?

- advanced technique whereby an attacker exploits the behavior of a web server and cache so that a harmful HTTP response is served to other users
- involves two phases:
  1. attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload
  2. need to make sure that their response is cached and subsequently served to the intended victims

## How does a web cache work?

![Web cache](/Portswigger/images/caching.svg)

- if a server had to send a new response to every single HTTP request separately, this would likely overload the server, resulting in latency issues and a poor user experience
- caching is primarily a means of reducing such issues
- cache sits between the server and the user, saves (caches) the responses to particular requests, for a fixed amount of time
- if another user sends an equivalent request, the cache simply serves a copy of the cached response directly to the user, without any interaction from the back-end

## Cache keys

- when the cache receives an HTTP request, it first has to determine whether there is a cached response that it can serve directly or whether it has to forward the request for handling by the back-end server
- caches identify equivalent requests by comparing a predefined subset of the request's components (cache key)
- contain the request line and Host header
- components of the request that are not included in the cache key are said to be "unkeyed"
- if cache key of an incoming request matches the key of a previous request, the cache considers them to be equivalent
- serve a copy of the cached response that was generated for the original request
- applied to all subsequent requests with the matching cache key until the cached response expires
- other components of the request are ignored by the cache

## Impact of a web cache poisoning attack

- depends on

1. What exactly the attacker can successfully get cached?
2. Amount of traffic on the affected page

## Constructing a web cache poisoning attack

1. Identify and evaluate unkeyed inputs

- any web cache poisoning attack relies on manipulation of unkeyed inputs such as headers
- you can use unkeyed inputs to inject the payload and elicit a poisoned response which if cached will be served to all users whose requests have the matching cache key
- first step is to identify unkeyed inputs that are supported by the server
- to identify unkeyed inputs, add random inputs to requests and observing whether or not they have an effect on the response: eg - reflecting the input in the response directly or triggering an entirely different response
- use `Param Miner` extension to automate the process
  > When testing for unkeyed inputs on a live website, there is a risk of causing the cache to server your generated responses to real users  
  > important to make sure theat your requests all have a unique cache key so that they will only be served to you: add a cache buster (such as a unique parameter) to the request line each time

2. Elicit a harmful response from the back-end server

- next step is to evaluate exactly how the website processes
- if an input is reflected in the response from the server without being properly sanitized or is used to dynamically generate other data, this is a potential entry point for web cache poisoning

3. Get the response cached

- whether or not a response gets cached can depend on all kinds of factors such as file extension, content type, route, status code and response headers

## Exploiting web cache poisoning vulnerabilities

### Exploiting cache design flaws

- due to general flaws in the design of caches
- websites are vulnerable to web cache poisoning if they handle unkeyed input in an unsafe way and allow the subsequent HTTP responses to be cached

#### Using web cache poisoning to deliver an XSS attack

- simplest web cache poisoning vulnerability to exploit is when unkeyed input is reflected in a cacheable response without proper sanitization

eg -

```
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: innocent-website.co.uk
======================================
HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />
```

- `X-Forwarded-Host` header is being used to dynamically generated an Open Graph image URL, which is then reflected in the response; which is often unkeyed
- cache can potentially be poisoned with a response containing a simple XSS payload

```
# request
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"

# response
HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://a."><script>alert(1)</script>"/cms/social.png" />
```

- if this response was cached, all users who accessed `/en?region=uk` would be served this XSS payload

#### Exploit unsafe handling of resource imports

- some websites use unkeyed headers to dynamically generate URLs for importing resources, such as externally hosted JS file
- if the attacker changes the value of the appropriate header to a domain that they control, they can potentially manipulate the URL to point to their own malicious JS file instead

```
# request
GET / HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
User-Agent: Mozilla/5.0 Firefox/57.0

# response
HTTP/1.1 200 OK
<script src="https://evil-user.net/static/analytics.js"></script>
```

#### Exploit cookie-handling vulnerabilities

- eg - cookie that indicates the user's preferred lanaugage, which is used to load the corresponding version of the page

```
GET /blog/post.php?mobile=1 HTTP/1.1
Host: innocent-website.com
User-Agent: Mozilla/5.0 Firefox/57.0
Cookie: language=pl;
Connection: close
```

- Polish version of the blog post is being requested
- the information about which language version to serve is only contained in the cookie header
- suppose that the cache key contains the request line and the Host header, not in the Cookie header
- if the response to this request is cached, then all the subsequent users who tried to access this blog post would receive the Polish version

#### Using multiple headers

- sometimes need to craft a request that manipulates multiple unkeyed inputs
- suppose website requires secure communication using HTTPS
- if a request that uses another protocol is received (eg - HTTP), the website dynamically generates a redirect to itself that does use HTTPS:

```
GET /random HTTP/1.1
Host: innocent-website.com
X-Forwarded-Proto: http
---------------------
HTTP/1.1 301 moved permanently
Location: https://innocent-site.com/random
```

- by combining this with above vulnerabilities in dynamically generated URLs, it can be exploited to generate a cacheable response that redirects users to a malicious URL

#### Exploting responses that expose too much information

- Cache-control directive

  - sometimes responses explicitly reveal some of the information an attacker needs to successfully poison the cache
  - eg - when responses contain information about how often the cache is purged or how old the currently cached response is

  ```
  HTTP/1.1 200 OK
  Via: 1.1 varnish-v4
  Age: 174
  Cache-Control: public, max-age=1800
  ```

  - it gives an information when to send the payload to ensure it gets cached

- Vary header
  - specifies a list of additional headers that should be treated as part of the cache key even if they are normally unkeyed

#### Exploit DOM-based vulnerabilities

- if a script handles data from the server in an unsafe way, this can potentially lead to all kinds of DOM-based vulnerabilities
- eg - an attacker can poison the cache with a response that import JSON file containing the following payload:

```json
{ "someProperty": "<svg onload=alert(1)>" }
```

- if the website passes the value of this property into a sink that supports dynamic code execution, the payload would be executed in the context of the victim's browser session
- if you use the web cache poisoning to make a website load malicious JSON data from your server, you may need to grant the website access to the JSON using CORS:

```
HTTP/1.1 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: *
{
  "malicious json" : "malicious json"
}
```

- web cache poisoning sometimes requires the attacker to chain together several of the techniques
- by chaining together different vulnerabilities, it is often possible to expose additional layers of vulnerability that were initially unexploitable
