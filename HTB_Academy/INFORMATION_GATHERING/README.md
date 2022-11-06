# Information Gathering

1. Domains and Subdomains
2. IP ranges
3. Infrastructure
4. Virtual Hosts

- Two main categories

1. Passive information gathering
2. Active information gathering

# Passive Information Gathering

## WHOIS

- **white pages** for domain names
- TCP-based transaction-oriented query/response protocol on TCP port 43 
- can get domain names, IP addresses or autonomous systems and provide information services to Internet users
- RFC 3912
- searchable list of all domains currently registered worldwide

```sh
whois example.com
```

## DNS

- converts domain names to IP addresses allowing browsers to access resources on the internet
- hierarchy of names in the DNS structure
- [ISO-3166-1](https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)

1. Resource Record
- domain name is the first part of a Resource Record
- if you don't use a fully qualified domain name, the zone's name where the record is located will be appended to the end of the name

2. TTL 
- Time-To-Live - defaults to the minimum value specified in the SOA record

3. Record Class - Internet, Hesiod, or Chaos

4. Start of Authority (SOA)
- first in a zone file because it indicates the start of a zone
- each zone can only have on SOA record and contains the zone's values such as a serial number and multiple expiration timeouts

5. Name Servers (NS)
- database is bound together by NS records
- in charge of a zone's authoritative name server and the authority for a child zone to a name server

6. IPV4 Address (A)
- A record is only a mapping between a hostname and an IP address
- Forward zones are those with A records

7. Pointer(PTR)
- mapping between an IP address and a hostname 
- Reverse zones are those that have PTR records

8. Canonical Name (CNAME)
- alias hostname is mapped to an A record hostname using the CNAME record

9. Mail Exchange (MX)
- identifies a host that will accept emails for a specific host
- multiple MX records can exist on the same host
- priority value has been assigned to the specified host
- prioritized list is made consisting of the records for a specific host

## Nslookup & DIG

- eg 

```sh
nslookup domain.com
dig domain.com @1.1.1.1
nslookup -query=ANY google.com
dig any google.com @8.8.8.8
```

- dig can specify a nameserver if needed by adding `@<nameserver/IP>`

| Querying | nslookup | dig |
| -------- | -------- | --- |
| A Records | nslookup $TARGET | dig $TARGET |
| A Records for subdomain | nslookup -query=A $TARGET | dig a $TARGET |
| PTR Records for an IP | nslookup -query=PTR $IP | dig -x $IP |
| ANY Existing Records | nslookup -query=ANY $TARGET | dig any $TARGET |
| TXT Records | nslookup -query=TXT $TARGET | dig txt $TARGET |
| MX Records | nslookup -query=MX | dig mx $TARGET |

- organizations are given IP address on the internet, but they aren't always their owners and rely on ISPs and hosting provides that lease smaller netblocks 
- combine some of the results gathered via nslookup with the whois database to determine if our target organization uses hosting providers


## Passive subdomain enumeration

### [VirusTotal](https://www.virustotal.com/gui/home/url)

### Certificates

- SSL/TLS certificates
- Certificate Transparency (CT), project that requires every SSL/TLS certificate issued by a Certificate Authority (CA) to be published in a publicly accessible log 
	- https://censys.io
	- https://crt.sh

```sh
export TARGET="facebook.com"
curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"
```
- can perform against a target using OpenSSL
```sh
export TARGET="facebook.com"
export PORT="443"
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
```

### Automating 

1. TheHarvester
- this tool collects emails, names, subdomains, IP addresses, URLs from various public data sources for passive information gathering

- eg - in sources.txt
```txt
baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

```sh
export TARGET="facebook.com"
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
```
- can extract all the subdomains found and sort them via
```sh
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```

-merge all the passive recon files by
```sh
cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
cat facebook.com_subdomains_passive.txt | wc -l
```

## Passive Infrasturcture Identification

1. Netcraft - https://sitereport.netcraft.com 

2. Wayback Machine - http://web.archive.org/
- to find old versions that may have interesting comments in the source code or files that should not be there
- eg - suppose a website running on WordPress 
	- current version is not vulnerable after testing
	- search in the past files and find that a vulnerable plugin
	- heading back to the current version of the site and find that the plugin was not removed properly and can still be access via the wp-content directory
	- can utilize it to get RCE on host 

- GO tool - `waybackurls`
```sh
waybackurls -dates https://facebook.com > waybackurls.txt
cat waybackurls.txt
```

# Active Information Gathering

## Active Infrastructure Identification

- can guess the webserver behind the target application and what operating system is running on the back-end server
- eg 
	- IIS 6.0: Windows Server 2003
	- IIS 7.0-8.5: Windows Server 2008 / Windows Server 2008R2
	- IIS 10.0 (v1607-v1709): Windows Server 2016
	- IIS 10.0 (v1809): Windows Server 2019

### 1. Web Servers

- look at the response headers, eg
- X-Powered-By - what the web app is using
- Cookies 
	- .NET: ASPSESSIONID<random>=<cookie_value>
	- PHP: PHPSESSID=<cookie_value>
	- JAVA: JSESSION=<cookie_value>

```sh
curl -I "http://${TARGET}"
```

- WhatWeb cli tool
```sh
whatweb https://www.tesla.com -v
```

- Wappalyzer extension
- WafW00f tool
```sh
wafw00f -v https://www.testla.com
```

- Aquatone
```sh
cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000
```

## Active Subdomain Enumeration

### ZoneTransfers

- how a secondary DNS server receives information from the primary DNS server and updates it 
- master-slave approach is used to organize DNS servers within a domain, with the slaves receiving updated DNS information from the master DNS
- the master DNS server should be configured to enable zone transfers from the secondary(slave) DNS servers, and this might be misconfigured

- https://hackertarget.com/zone-transfer/

**Manual approach**
1. Identifying Nameservers
```sh
nslookup -type=NS zonetransfer.me  
``` 

2. Testing for ANY and AXFR Zone Transfer
```sh
nslookup -type=any -query=AXFR zonetransfer.me result_from_above_lookup
```

### Gobuster

- common flags
	- dns - launch the DNS module
	- -q  - not print the banner and other noise
	- -r  - use custom DNS server
	- -d  - target domain name
	- -p  - path to the pattern file
	- -w  - path to the wordlist
	- -o  - output file
```sh
export TARGET="facebook.com"
export NS="d.ns.facebook.com"
export WORDLIST="numbers.txt"
gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
```

## Virtual Hosts

- feature that allows several websites to be hosted on a single server
- two ways to configure virtual hosts
	- IP-based virtual hosting
	- Name-based virtual hosting

- IP-based virtual hosting
	- a host can have multiple network interface
	- multiple IP addresses or interface aliases can be configured on each network interface of a host
	- servers or virtual servers running on the host can bind to one or more IP addresses; different servers can be addressed under different IP addresses on the host

- Name-based virtual hosting
	- several domain names can refer to the same IP
	- internally on the server, these are separated and distinguished using different folders; in Linux server, for example
		- admin.inlanefreight.htb in /var/www/admin
		- backup.inlanefreight.htb in /var/www/backup

	- suppose the web server is identified at `192.168.10.10` 
	- `curl -s http://192.168.10.10 -H "Host: randomtarget.com"`
	- check the namelist at `/SecList/Discovery/DNS/namelist.txt`
	- suppose in vhosts 
	```
	app
	blog
	dev-admin
	forum
	help
	m
	my
	shop
	some
	store
	support
	www
	```
	```sh
	cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done
	```

#### Automating Virtual Hosts Discovery with ffuf

```
MATCHER OPTIONS:
  -mc                 Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403,405)
  -ml                 Match amount of lines in response
  -mr                 Match regexp
  -ms                 Match HTTP response size
  -mw                 Match amount of words in response

FILTER OPTIONS:
  -fc                 Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl                 Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr                 Filter regexp
  -fs                 Filter HTTP response size. Comma separated list of sizes and ranges
  -fw                 Filter by amount of words in response. Comma separated list of word counts and ranges
```

```sh
ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612
```

## Crawling

### ZAP

- https://www.zaproxy.org/docs/desktop/start/
- Sites > domain (right-click) > Attack > Spider

### FFUF

```sh
ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
```

## Sensitive Information Disclosure

### Resources

- common extensions
	- `/SecList/Discovery/Web-Content/raft-[small|medium|large]-extensions.txt`
- https://github.com/digininja/CeWL

### Steps

1. create a file with the following folder names and save into `folders.txt`

```
wp-admin
wp-content
wp-includes
```

2. Extract some keywords 

- can extract some keywords from the website using CeWL

```sh
cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10
```
- -m5 - minimum length of 5 characters
- --lowercase - convert into lowercase
- wordlist.txt -> save results into this file

3. Combine everything in ffuf 

```sh
ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS
```