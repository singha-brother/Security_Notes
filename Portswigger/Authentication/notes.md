## What is authentication?

- process of verifying the identity of a given user or client
- making sure that they really are who they claim to be
- Three authentication factors
  1. **Knowledge factors** - something you `know` such as password or the answer to a security question
  2. **Possession factors** - something you `have`, a physical object such as mobile phone, or security token
  3. **Inherence factors** - something you `are` or do, such as biometrics or patterns of behavior

## Authentication Vs Authorization

- **authentication** - process of verifying that a user really is `who they claim to be`
- **authorization** - verifying whether a user is `allowed to do something`

## How do authentication vulnerabilities arise?

- authentication mechanisms are weak as they fail to adequately protect against brute-force attacks
- logic flaws or poor coding allow the authentication mechanisms to be bypassed (broken authentication)

## Vulnerabilities in password-based login

### Brute-force attacks

- brute-force usernames
- brute-force passwords
- username enumeration
  - attempting to brute-force a login page, pay particular attention to any differences in
    1. Status Code
    2. Error Messages
    3. Response times
- flawed brute-force protection
  - locking the account if they make too many failed login attempts
  - blocking remote user's IP if they make too many login attempts in quick succession

## Vulnerabilities in multi-factor authentication

- bypassing two-factor authentication
  - if the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a logged in state before they have entered the verification code
  - test whether you can directly skip to 'logged-in only' pages after completing the first authentication step
- flawed two-factore verification logic

  - sometimes, after a user has completed the initial login step, the website doesn't adequately verify that the same user is completing the second step
  - eg - user logins with normal credentials in first step

  ```
  POST /login-steps/first HTTP/1.1
  Host: vulnerable-website.com
  ...
  username=carlos&password=qwerty
  ```

  - assigned a cookie that relates to their account, before being taken to the second step of the login process

  ```
  HTTP/1.1 200 OK
  Set-Cookie: account=carlos

  GET /login-steps/second HTTP/1.1
  Cookie: account=carlos
  ```

  - when submitting the verification code, the request uses this cookie to determine which account the user is trying to access

  ```
  POST /login-steps/second HTTP/1.1
  Host: vulnerable-website.com
  Cookie: account=carlos
  ...
  verification-code=123456
  ```

  - attacker could log in using their own credentials but then change the value of the account cookie to any arbitary username when submitting the verification code

  ```
  POST /login-steps/second HTTP/1.1
  Host: vulnerable-website.com
  Cookie: account=victim-user
  ...
  verification-code=123456
  ```

## Vulnerabilities in other authentication mechanism

### Keeping users logged in

- this functionality is often implemented by genrating a 'remember me' token of some kind, which is then stroed in a persistent cookie
- processing this cookie may allows you to bypass the entire login process
- so, it is best practice for this cookie to be impractical to guess

### Resetting user passwords

- Sending passwords by email
- Resetting passwords using a URL
- Changing user passwords
  - sometimes, if the username is provided in a hidden field, an attacker might be able to edit this value in the request to target arbitary users and can be exploited to enumerate usernames, and brute-force passwords
