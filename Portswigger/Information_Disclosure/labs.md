## Lab - 1: Information disclosure in error messages

- This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework.

- try SQLi at `/product?productId=1'` and found an error message

---

## Lab - 2: Information disclosure on debug page

- This lab contains a debug page that discloses sensitive information about the application. To solve the lab, obtain and submit the SECRET_KEY environment variable.

- found an end point that show phpinfo at `/cgi-bin/phpinfo.php`

- search SECRET_KEY from that page

---

## Lab - 3: Source code disclosure via backup files

- This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code.

- found backup directory at `/backup/ProductTemplate.java.bak`

---

## Lab - 4: Authentication bypass via information disclosure

- This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.

- To solve the lab, obtain the header name then use it to bypass the lab's authentication. Access the admin interface and delete Carlos's account.

- You can log in to your own account using the following credentials: wiener:peter

- `/admin` route is not allowed
- send the request with `TRACE /admin` and the response contains `X-Custom-IP-Authorization` header containing your IP address
  > Proxy > Options > Match and Replace > Add > Type: "Request header", Replace: "X-Custom-IP-Authorization: 127.0.0.1"
- Then send request to `/admin` route from the browser

---

## Lab - 5: Information disclosure in version control history

- This lab discloses sensitive information via its version control history. To solve the lab, obtain the password for the administrator user then log in and delete Carlos's account.

- at `/.git` path, there is a git folder

```sh
wget -r https://your-lab-id.com/.git
cd to_download_folder
git log
```

```
commit c2c692df9b49a02ad4e1d56e008f8330caf713e6 (HEAD -> master)
Author: Carlos Montoya <carlos@evil-user.net>
Date:   Tue Jun 23 14:05:07 2020 +0000

    Remove admin password from config
```

```sh
git show c2c692df9b49a02ad4e1d56e008f8330caf713e6
```

```
commit c2c692df9b49a02ad4e1d56e008f8330caf713e6 (HEAD -> master)
Author: Carlos Montoya <carlos@evil-user.net>
Date:   Tue Jun 23 14:05:07 2020 +0000

    Remove admin password from config

diff --git a/admin.conf b/admin.conf
index 7ce2a19..21d23f1 100644
--- a/admin.conf
+++ b/admin.conf
@@ -1 +1 @@
-ADMIN_PASSWORD=td6begsw5ot0iidpt3on
+ADMIN_PASSWORD=env('ADMIN_PASSWORD')
```
