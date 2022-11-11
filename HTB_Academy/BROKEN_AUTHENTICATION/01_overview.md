# Authentication and Authorization

## Authentication

- the act of proving an assertion
- the process of determining if an entity (a user or an automated application) is who it claims to be
- login forms

## Authorization

- the process of approving or disapproving a request from a given (authenticated) entity

---

# Authentication Methods

- During the authentication phase, the entity who wants to authenticate sends an identification string that could be an ID, a username, email along with additional data

## Multi-factor Authentication (MFA, 2FA)

- Factors are separated into 3 different domains:
	1. something the user knows (eg - username, password)
	2. something the user has, (eg - hardware token)
	3. something the user is, (eg - biometric fingerprint)

- When an authentication process requires the entity to send data that belongs to more than one of these domains, it should be considered an MFA process

## Form-Based Authentication

- the application presents an HTML form where the user inputs their username and password and the access is granted after comparing the received data against a backend
- after successful login attempt, the application server creates a session tied to a unique key (usually stored in a cookie)
- this unique key is passed between the client and the web application on every subsequent communication for the session to be maintained
- some web apps require the user to pass through multiple steps of authentication; eg - first step requires to enter the username and password and second a One-Time Password (OTP) token which originate from a hardware device or mobile application that generates passwords and last for a limited amount of time
- muli-step login procedures could suffer from business logic vulnerabilities

## HTTP Based Authentication

- the application server can specify different authentication schemes such as Basic Digest and NTLM
- All HTTP authentication schemes resolve around the 401 status code and the WWW-Authenticate response header and are used by application servers to challenge a client request and provide authentication details (Challenge-Response process)
- `Authorization header` holds the authentication data and should be present in every request for the user to be authenticated
- to perform HTTP basic auth login, the browser encodes the username and password using Base64 and the Authorization header will contain the base64-encoded credentials in every request
- an attacker that can capture the network traffic in plaintext can capture credentials
- example of HTTP Authentication Header
```
GET /basic_auth.php HTTP/1.1
Host: brokenauth.hackthebox.eu
Cache-Control: max-age=0
Authorization: Basic YWRtaW46czNjdXIzcDQ1NQ==
```

## Other Forms of Authentication

- it is possible that authentication is performed by checking the source IP address
- modern applications could use third parties to authenticate users, such as SAML (Secure Assertion Markup Language)
- APIs usually require a specific authentication form often based on a multi-step approach

# Attacks Against Authentication

- again authentication attacks can take place against a total of three domains
	1. The `HAS` domain
	2. The `IS` domain
	3. The `KNOWS` domain

## 1. Attacking the HAS domain

- A badge could be cloned without taking it over?
- A cryptographic algorithm used to generate One-Time Password could be broken?
- Any physical device could be stolen?

## 2. Attacking the IS domain

- if a person relies on "something" to prove their identity and this "something" is compromised, they lose the unique way of proving their identity since there is no way one can change the way they are
- retina scan, fingerprint readers, facial recognition have been all proved to be breakable


## 3. Attacking the KNOWS domain

- things a user knows, like a username or a password

