# CSRF

- web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform.
- allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other

## Impact

- the attacker causes the victim user to carry out an action unintentionally
- eg - change email address, change password, make a funds transfer

## How does it work?

1. **Relevant action** - eg - privileged action (such as modifying permissions for other users) or any action on user-specific data (such as changing the user's own password)

2. **Cookie-based session handling**(session cookies) - performing the action involves issuing one or more HTTP requests and the application relies solely on session cookies to identify the user who has made the requests.

3. **No unpredictable request parameters** - requests that perform the action do not contain any parameters whose values the attacker cannot determine or guess.

eg - an application contains a function that lets the user change the email address. When the user performs this action, they make an HTTP request like:

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=wiener@normal-user.com
```

This meets the conditions required for CSRF

- action of changing email address
- session cookie to identify which user issued the request
- values of request parameters can be easily determined

Then the attacker can construct a web page containing the following HTML

```html
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="post">
      <input type="hidden" name="email" value="attacker@email.com" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

- when the victim user visits the attacker's web page,
- the attacker's page will trigger an HTTP request to the vulnerable web site
- if the user is logged in to the vulnerable web site, their browser will automatically include their session cookie in the request (assuming SameSite cookies are not being used)
- the vulnerable web site will process the request in the normal way, treat it as having been made by the victim user and change their email address to attacker's email

## How to construct CSRF attack

- select a request anywhere in Burp that you want to test or exploit
- Right-click > Select Engagement tools > Generate CSRF PoC
- will generate some HTML that will trigger the selected request (without cookies, that will be added automatically by the victim's browser)
- copy the generated HTML into a web page, view it in the browser that is logged in to the vulnerable web site and test whether the intended request is issued successfully and the desired action occurs

## How to deliver CSRF exploit

- delivery mechanisms is same as that of reflected XSS
- attacher will place the malicious HTML onto a web site that they control and induce victims to visit that web-site by feedin the user a link to the web site via the email or social media message
- some simple CSRF exploits employ the GET method and can be fully self-contained with a single URL on the vulnerable web site and can directly feed victims a malicious URL on the vulnerable domain
  eg - `<img src="https://vuln-website.com/email/change?email=attacker@email.com">`

## XSS Vs CSRF

- XSS - allows an attacker to execute arbitary JS within the browser of the victim user
- CSRF - allows an attacker to induce a victim user to perform actions that they do not intend to

- CSRF - only applies to a subset of actions that the user is able to perform, and those that are overlooked CSRF defenses
- XSS can normally induce a user to perform any action that the user is able to perform

## Defend

### CSRF Token

- most robust way to defend against CSRF attacks is to include a CSRF token within relevant requests and the token should be
  - unpredictable with high entropy as for the session tokens in general
  - tied to the user's session
  - strictly validated in every case before the relevant action is executed

### SameSite cookies

- `SameSite` attribute can be used to control whether and how cookies are submitted in cross-site requests
- two values : `Strict` or `Lax`
- eg `Set-Cookie: SessionId=some-random-string; SameSite=Strict`
- if strict, the browser will not include the cookie in any requests that originate from another site
- if lax, the browser will include the cookie in requests that originate from another site but only if two conditions are met
  - the reqest uses the GET method (with other methods like POST will not include the cookie)
  - the request resulted from a top-level navigation by the user, such as clicking a link

## Common CSRF vulnerabilities

1. CSRF validation only occurs at certain method eg - CSRF token validation takes place only in POST method and not in GET method

2. Validation of CSRF token depends on token being present - some applications correctly validate the token only when it is present but skip the validation if the token is omitted. (try to remove the token)

3. CSRF token is not tied to the user session - some applications do not validate that the token belongs to the same session as the user who is making the request. (application maintains a global pool of tokens that it has issued and accepts any token that appears in this pool)

4. CSRF token tied to a non-session cookie
   eg -

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv

csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
```

- harder to exploit
- if web site contains any behavior that allows an attacker to set a cookie in a victim's browser, then an attack is possible

5. CSRF token - simply duplicated in a cookie

- some applications do not maintain any server-side record of tokens that have been issued, but instead duplicate each token within a cookie and a request parameter

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
```

6. Referer-based defences

- some applications make use of the HTTP Referer header to attempt to defend against CSRF attacks
- when it is present in requests, validate the token and if the header is omitted, skip the validation
- easiest way to do is adding META tag with no referer

```
<meta name="referrer" content="never">
```

## Testing CSRF Tokens

1. Remove the CSRF token and see if the application accepts the request
2. Change request method - eg - from POST to GET method
3. Swap the CSRF token with other account and test it

## Testing CSRF Tokens and CSRF cookies

1. Check if the CSRF token is tied to the CSRF cookie
   - Submit an invalid CSRF token
   - Submit a valid CSRF token from another user
2. Submit valid CSRF token and cookie from another user
