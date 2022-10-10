# Excessive trust in client-side controls

## Lab - 1: Excessive trust in client-side controls (A)

- This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket". You can log in to your own account using the following credentials: wiener:peter

- login with `wiener` account which has 100$.
- try to buy the item which is 1337$
- found the POST request to order the item as below

```
POST /cart HTTP/1.1
...

productId=1&redir=PRODUCT&quantity=1&price=133700
```

- change the price to 1 and send the request
- it is accepted.

---

## Lab - 2: 2FA broken logic (P)

- This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page. Your credentials:
- wiener:peter
- Victim's username: carlos

You also have access to the email server to receive your 2FA verification code.

- authentication takes at two places: `/login`, `/login2`

```
POST /login2 HTTP/1.1
Host: 0acc0063042c53c7c0ef2d7d00ba00fd.web-security-academy.net
Cookie: session=DYilJfJf1DWJlo29QH67IiR8jRb5eOB3; verify=carlos
...
mfa-code=0000
```

- change the cookie to carlos and brute force the mfa-code from `0000` to `9999` in Burp Intruder
- in Burp Intruder Payloads
  - Payload type: Numbers
  - From: 0000
  - To : 9999
  - Step: 1
  - Min integer digits: 4
  - Max integer digits: 4
  - Max fraction digits: 0

---

# Failing to handle unconventional input

## Lab - 3: High-Level Logic Vulnerability (A)

- This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket". You can log in to your own account using the following credentials: wiener:peter

- enter `wiener` account which has $100
- see the flow of buying process
- try with negative quantity and it accept
- it is not accepted the negative balance
- buy 1 Lightweight l33t which is 1337$ and adjust with other items filling negative numbers for quantity

---

## Lab - 4: Low-level logic flaw (P)

- This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket". You can log in to your own account using the following credentials: wiener:peter
