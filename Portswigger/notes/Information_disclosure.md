- Information disclosure is known as information leakage.
- website unintentionally reveals sensitive information to its users.
- data about other users, such as usernames, financial information
- sensitive commercial or business data
- technical details about the website and its infrastructure

- basic examples of information disclosure

1. Revealing the names of hidden directories, their structure, and their contents via a robots.txt file or directory listing
2. Providing access to source code files via temporary backups
3. Explicitly mentioning database table or column names in error messages
4. Unnecessarily exposing highly sensitive information, such as credit card detail
5. Hard-coding API keys, IP addresses, database credentials
6. Hinting at the existence or absence of resources, usernames, and so on via subtle differences in appliation behaviour

---

## How do information disclosure vulnerabilities arise?

- Failure to remove internal content from public content
- Insecure configuration of the website and related technologies
- Flawed design and behavior of the application

## How to find and exploit

- Fuzzing
- using Burp Scanner
- using Burp's engagement tools
- Engineering informative responses

## common sources of information disclosure

- files for web crawlers
- directory listings
- developer comments
- error messages
- debugging data (eg-phpinfo files)
- user account pages
- backup files
- insecure configuration
- version control histroy

- Many websites provides files at `/robots.txt` and `/sitemap.xml`.
- make an error to show error messages
  eg - `GET /product?productId=1000000000000000 `
