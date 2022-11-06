# Ffuf

| **Command**                                                                                                                                                     | **Description**          |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `ffuf -h`                                                                                                                                                       | ffuf help                |
| `ffuf <snip> -ic`                                                                                                                                               | to remove copyright text |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ`                                                                                                       | Directory Fuzzing        |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ`                                                                                                  | Extension Fuzzing        |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php`                                                                                              | Page Fuzzing             |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v`                                                              | Recursive Fuzzing        |
| `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/`                                                                                                      | Sub-domain Fuzzing       |
| `ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx`                                                                     | VHost Fuzzing            |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx`                                                                   | Parameter Fuzzing - GET  |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Parameter Fuzzing - POST |
| `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`       | Value Fuzzing            |

# Wordlists

| **Command**                                                   | **Description**         |
| ------------------------------------------------------------- | ----------------------- |
| `SecLists/Discovery/Web-Content/directory-list-2.3-small.txt` | Directory/Page Wordlist |
| `SecLists/Discovery/Web-Content/web-extensions.txt`           | Extensions Wordlist     |
| `SecLists/Discovery/DNS/subdomains-top1million-5000.txt`      | Domain Wordlist         |
| `SecLists/Discovery/Web-Content/burp-parameter-names.txt`     | Parameters Wordlist     |

# Misc

| **Command**                                                                                                                   | **Description**          |
| ----------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'`                                                                     | Add DNS entry            |
| `for i in $(seq 1 1000); do echo $i >> ids.txt; done`                                                                         | Create Sequence Wordlist |
| `curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'` | curl w/ POST             |

# Page Fuzzing

- first Extension fuzzing

```bash
ffuf -w /opt/tools/SecLists-master/Discovery/Web-Content/web-extensions.txt -u http://167.99.195.127:32560/blog/indexFUZZ -ic

```

- suppose will result `php`
- then Page Fuzzing

```bash
ffuf -u http://167.99.195.127:32560/blog/FUZZ.php -w /opt/tools/SecLists-master/Discovery/Web-Content/directory-list-2.3-small.txt -ic -t 64
```

# Recursive fuzzing

- `-recursion`
- `-recursion-depth 1` - only one sub-directory
- `-e .php` - extension

```
thnwht@htb[/htb]$ ffuf -w /opt/tools/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```

# Add DNS record

```sh
thnwht@htb[/htb]$ sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

# Sub-Domain Fuzzing

- wordlist - `/SecLists/Discovery/DNS/...`

```
ffuf -w /opt/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.hackthebox.eu/
```

# Vhost Fuzzing

- VHost - sub-domain served on the same server and has the same IP such that a single IP could be serving two or more different websites
- **VHosts may or may not have public DNS records**

```
thnwht@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```

# Filtering results

```
thnwht@htb[/htb]$ ffuf -h
...SNIP...
MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl              Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr              Filter regexp
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
  -fw              Filter by amount of words in response. Comma separated list of word counts and ranges
<...SNIP...>
```

# Parameter Fuzzing -GET

```
thnwht@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```

# Parameter Fuzzing - POST

```
thnwht@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

# Value Fuzzing

```
thnwht@htb[/htb]$ ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
