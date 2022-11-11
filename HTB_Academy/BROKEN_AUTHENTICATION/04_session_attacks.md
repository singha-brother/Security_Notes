# Brute Forcing Cookies

- without cookies, the other ways to track users are `HTTP Authentication` and `ViewState` in .NET framewroks before a user even reach the login form
- ViewState - included as a hidden field in HTML forms
- built as a serialized object containing userful information about the current user/session (where the user came from, where the user can go and what the user can see or modify, etc)
- ViewState token can be easily decoded if it is not encrypted
- even if it is encrypted, it could suffer even RCE
- session cookies can suffer from the same vulnerabilities that may affect password reset tokens
- they could be predictable, broken, or forged

## Cookie Token Tampering

- like password reset tokens, sesison tokens could also be based on guessable information
- often, homebrewed web applications feature custom session handling and custom cookie-building mechanisms to have user-related details handy
- most common piece of data we can find in cookies is user grants; whether a user is an admin, operator, or basic user
- it is not rare to see tokens genereated from important values, such as userid, grants, time, etc
- eg - sessionID as 757365723A6874623B726F6C653A75736572 which is hex version of ascii text
```sh
echo 757365723A6874623B726F6C653A75736572 | xxd -p -r 
```
- get `user:htb;role:user`
- we could try escalating our privileges within the application by modifying this session cookie to `role:admin` 

## Remember me Token

- can consider a rememberme token as a session cookie that lasts for a long time than usual which usually last for at least seven days or even for entire month
- given their long lifespan, rememberme tokens can be easier to brute force

## Encrypted or encoded token

- cookies can also contain the result of the encryption of a sequence of data
- weak crypto algorithm could lead to privilege escalation or auth bypass
- https://en.wikipedia.org/wiki/Padding_oracle_attack
- some encoding algorithms - hex, base64
- before encoding, may contain - XOR or compression function
```
always check for magic bytes when you have a sequence of bytes that looks
like junk to you 
https://en.wikipedia.org/wiki/List_of_file_signatures
```
- eg
```sh
echo H4sIAC4kKGAA/wXAMQ0AAADCMLUooPaPxS4Mfn/YBAAAAA== | base64 -d | xxd -p
> 1f8b08002e24286000ff05c0310d000000c230b528a0f68fc52e0c7e7fd804000000
```
- find 1f8b in wiki -> found that gzip signature and
```sh
echo H4sIAC4kKGAA/wXAMQ0AAADCMLUooPaPxS4Mfn/YBAAAAA== | base64 -d | gunzip
> test
```

```sh
❯ echo 425a683931415926535909a1ac440000030b80162010901d124000200022864f483daa100002a539da608f0cf8bb9229c284804d0d6220 | xxd -p -r | bzip2 -dk | base64 -d

❯ encoding_rox
```

- sometimes cookies are set with random or pseudo-random values, and easy decode doesn't lead to a successful attack

- check `automate_cookie_tampering.py` 

## Weak session token

- even when cookies are generated using strong randomization, resulting in a difficult-to-guess string, it could be possible that the token is not long enough
- problem if the tested web application has many concurrent users due to space is not enough, [Birthday Paradox](https://en.wikipedia.org/wiki/Birthday_problem)
- in this case, two users might receive the same token, the web app should check if a newly generated one already exists and regenerate it
- this behavior makes it easier for an attacker to brute force the token and obtain a valid one

- if we try to brute force a session cookie, the time needed would depend on the length and the charset used to create the token itself

```sh
john --incremental=LowerNum --min-length=6 --max-length=6 --stdout| wfuzz -z stdin -b HTBSESS=FUZZ --ss "Welcome" -u https://brokenauthentication.hackthebox.eu/profile.php 
```

# Insecure Token Handling

- One difference between cookies and tokens is that 
	- cookies are used to send and store arbitary data 
	- tokens are explicitly used to send authorization data

- when perform token-based authentication such as OpenID or OpenID Connect, we receive an id token from a trusted authority and often referred to JWT and token-based authentication
- typical use case for JWT is continuous authentication for Single Sign-On (SSO)

## Token Lifetime

- token should expire after the user has been inactivate for a given amount of time
- if a token never expires, the Session Fixation attack is even worse and the attacker could try to brute force a valid session token created in the past
- the chances of succeeding in a brute force attack are proportionate to the shortness of the cookie value itself

## Session Fixation

- most important rule about a cookie token is that its value should change as soon as the access level changes
	- a guest user should receive a cookie and as soon as they authenticate and the token should change
	- the same should happen if the user gets more grants during a sudo-like session
	- if this does not occur, the web app or better any authenticated user, could be vulnerable to Session Fixation
- this attack is carried out by phishing a user with a link that has a fixed, and unknown by the web application, session value
- the web app should bounce the user to the login page as the SESSIONID is not associated with any valid one
- When the user logs in, the SESSIONID remains the smae, and an attacker can reuse it
- eg 
	- suppose a web app that sets SESSIONID from a URL parameter like `https://vuln-website.com/view.php?SESSIONID=anyrandomvalue`
	- when a user that does not have a valid session clicks on that link, the web app could set SESSIONID as any random value as a cookie and as it is not a valid SESSIONID and the user is redirected to the login page
	- if the web applicaiton does not change that token after a successful login, the attacker could reuse it anytime until it expires

## Token in URL 

- until recent days, it was possible to catch a valid session token by making the user browse away from a website where they had been authenticated, moving to a website controlled by the attacker
- the Referer header carried the full URL of the previous website, including both the domain and parameters and the webserver would log it
- nowadays, this attack is not always feasible as by default modern browsers strip the Referer header but it could still be an issue if the web app suffers from a **Local File Inclusion** vulnerability or the **Referer-Policy header** is set in an unsafe manner
- if we can read application or web server logs, we may also obtain a high number of valid tokens remotely
- it is also possible to obtain valid tokens remotely if we manage to compromise an external analytics or log collection tool used by a web server or application

## Session Security

- secure session handling starts from giving the counterpart, the user, as little information as possible
- if a cookie contains only a random sequence, an attacker will have a tough time
- on the other side, the web application should hold every detail safely and use a cookie value just as an id to fetch the correct session
- some security libraries offer the feature of transparently encrypting cookie IDs also at the server level
- encryption is performed using some hardcoded values, concatenated to some value taken from the request, such as User-Agent, IP address or a part of it or another environment variable
- this technique has been implemented inside in Snuffleupagus PHP module
- like any other security measure, cookie encryption is not a silver bullet and could cause unexpected issues
- session security should also cover multiple logins for the same user and concurrent usage of the same session token from different endpoints
- user should be allowed to have access to an account from one device at a time
- an exception can be set for mobile access, which should use a parallel session check

## Cookie Security 

- most tokens are sent and received using cookies
- cookie should be created with the correct path value, be set as httponly and secure and have the proper domain scope
- an unsecured cookie could be stolen and reused quite easily through XSS or Man in the middle (MitM) attacks