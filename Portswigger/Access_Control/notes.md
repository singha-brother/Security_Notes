## Examples of broken access controls

### Vertical Priviledge Escalation

#### Unprotected funcationality

- admin page is accessible by any user at `https://insecure-website.com/admin`

- admin URL might be disclosed in other locations such as `robots.txt`.

- though admin route's name is given a less predictable URL, but it is exposed in JS files.

#### Parameter-based access control methods

- some applications determine the user's access rights or role at login, and store information in a user-controllable location such as a hidden field, cookie or preset query string parameter. eg- `https://insecure-website.com/login/home.jsp?admin=true` or `https://insecure-website.com/login/home.jsp?role=1`

#### Broken access control resulting from platform misconfiguration

eg - application that was configured rules like the following:

```
DENY: GET, /admin/deleteUser, managers
```

- This rule denies access to the GET method on the URL /admin/deleteUser, for users in managers group.

`/admin` route is made to access denied. Try whether `X-Original-URL` and `X-Rewrite-URL` work. Get a get response to home page and add `X-Original-URL: /invalid` and if `not found` return, X-Original-URL works. Then to delete the user carlos, add this line in GET response.

```
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```

### Horizontal Privilege Escalation

- **User ID controlled by request parameter** - change the
  id value for other users in `GET /my-account?id=wiener HTTP/1.1`

- If the id parameters are random, find them in website. They will link to somewhere.

### IDOR (Insecure direct object references)

- subcategory of access control vulnerabilities
- arises when an application uses user-supplied input to access objects directly and an attacker can modify the input to obtain unauthorized access

- Direct reference to database object
- Direct reference to static files

### Access control vulnerablities in multi-step processes

eg - administrative function to update user details might involve the following steps

- load form containing details for a specific user
- submit changes
- review the changes and confirm
- in these steps, suppose access controls are correctly applied to the first and second steps but not to the third step
- The attacker can gain unauthorized access to the function by skipping the first two steps and directly submitting the request for the third step with the required parameters

### Referer-based access control

- Some websites base access controls on the Referer header submitted in HTTP request
- eg - an application robustly enforces access control over the main admin page at `/admin` but for sub-pages such as `/admin/deleteUser` only inspects the Referer header. Then, the Referer header contains the main `/admin` URL, the request is allowed.

### Location based access control

- some web sies enforce access controls over resources based on the user's geographical location
- can be circumvented by the use of web proxies, VPNs, or manipulation of client-side geolocation mechanisms
