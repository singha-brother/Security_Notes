# Introduction

## What is XSS ?  

- when a vulnerable web application does not properly sanitize user input, a malicious user can inject extra JS code in an input field
- solely executed on the client-side and do not directly affect the back-end server
- only affect the user executing the vulnerability

## XSS Attacks

- eg -
	- target user unwittingly send their session cookie to the attacker's web server
	- target browser execute API calls that lead to a malicious action like changing the user's password to a password of the attacker's choosing
	- https://en.wikipedia.org/wiki/Samy_(computer_worm)
	- https://blog.sucuri.net/2014/06/serious-cross-site-scripting-vulnerability-in-tweetdeck-twitter.html
	- https://twitter.com/derGeruhn/status/476764918763749376
	- https://www.theguardian.com/technology/2014/jun/11/twitter-tweetdeck-xss-flaw-users-vulnerable
	- https://www.acunetix.com/blog/web-security-zone/mutation-xss-in-google-search/
	- https://blogs.apache.org/infra/entry/apache_org_04_09_2010


## Types of XSS

1. Stored (Persistent) XSS

- most critical type
- occurs when user input is stored on the back-end database and displayed upon retrival
- eg - post or comments

2. Reflected (Non-Persistent) XSS

- user input is displayed on the page after being processed by the backend server
- not being stored 
- eg - search result or error message

3. DOM-based XSS

- another non-persistent XSS
- user input is directly shown in the browser 
- completely processed on the client-side without reaching the back-end server
- eg - through client-side HTTP parameters or anchor tags


## 1. Stored (Persistent) XSS

- injected XSS payload gets stored in the back-end database 
- retrieved upon visiting the page
- may affect any user that visits the page

### XSS testing payload

```html
<script>alert(window.origin)</script>
<script>print()</script>
```
- confirm by looking at the source page

- **NOTE**
	- many modern web applications utilize cross-domain IFrames to handle user input 
	- even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web app
	- by using payload `window.origin` , if it shows the URL it is being executed on, and will confirm which form is the vulnerable one, in case an IFrame was being used

## 2. Reflected XSS

- Two types of Non-Persistent XSS
	1. Reflected XSS - gets processed by the back-end server
	2. DOM-based XSS - completely processed on the client-side and never reaches the back-end server
- temporary and not persistent through page refreshes
- can affect only the target user and not affect other users

- Reflected XSS occurs when our input reaches the back-end server and gets returned to use without being filtered or sanitized
- many cases in which our entire input might get returned to us
	- error messages
	- confirmation messages

- we may attempt using XSS payloads to see whether they execute
- they are usually temporary message, once we move from the page, they would not execute again

- **How would we target victims with it?**
- send the whole URL that will cause alert
- eg - `http://example.com/index.php?task=<script>alert(window.origin)</script>`

## 3. DOM XSS

- completely processed on the client-side through JS
- occurs when JS is used to change the page source through the DOM
- unlike Reflected XSS, no HTTP requests are made to make XSS and never reach the back-end

### Source & Sink

- Source - JS object that takes the user input, and it can be any input parameter like a URL parameter or an input field
- Sink - function that writes the user input to a DOM Object on the page; if the sink function does not properly sanitize the user input, it would be vulnerable to an XSS attack
- some of the commonly used JS functions to write to DOM 
	- `document.write()`
	- `DOM.innerHTML`
	- `DOM.outerHTML`
	- `add()`
	- `after()`
	- `append()`

- if the Sink function writes the exact input without any sanitization and no other means of sanitization were used, we know that the page should be vulnerable to XSS
- eg JS code

```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
...
document.getElementById("todo").innerHTML = "<b>Next Task:</b>" + decodeURICompnent(task);
```

### DOM attacks

- in `innerHTML`, to execute XSS - `<img src="" onerror=alert(window.origin)>`


## XSS Discovery

### Automated Discovery

- Nessus, Burp Pro, ZAP have various capabilities for detecting XSS
- Passive scan - reviews client side code for potential DOM-based vulnerabilities
- Active scan - sends various types of payloads to attempt to trigger an XSS through payload injection in the page source
- OPEN SOURCE TOOLS
	- https://github.com/s0md3v/XSStrike
	- https://github.com/rajeshmajumdar/BruteXSS
	- https://github.com/epsylon/xsser

### Manual Discovery

#### XSS Payloads

- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md
- https://github.com/payloadbox/xss-payload-list

- XSS can be injected into any input in the HTML page which is not exclusive to HTML input fields, but may also be in HTTP headers like the Cookies or User-Agent 

- it may be more efficient to write own Script to automate sending the payloads and comparing the page source to see how the payloads where rendered

#### Code Review

- most reliable method of detecting XSS vulnerabilities is manual code review
- review should cover both back-end and front-end code
- if we understand precisely how our input is being handled all the way until it reaches the web browser, we can write a custom payload that should work with high confidence