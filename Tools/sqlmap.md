- simple run 
```sh
sqlmap --url <URL>
```

- using a request file saved from BURP or somewhere else
```sh
sqlmap -r file.req
```

- More parameters
```
-p "Parameter to test"
--risk 3
--level 5
--dbms "DBMS systems"
-hh # (for more)
```

- database data 
```
--all # retrieve everything
--dbs # names of the dbs
--tables -D DB
--columns -T table -D DB
-D DB -T table -C column # dumbp column
```

- Internal information
```
--current-user
-is-dba # is db admin
--hostname
--users
--passwords
--privileges
```
