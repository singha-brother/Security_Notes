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
