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
