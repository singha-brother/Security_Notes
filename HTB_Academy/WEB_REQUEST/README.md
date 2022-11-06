# HTTP

- Hypertext (text containing links to other resources and text that the readers can easily interpret) transfer protocol
- application-level protocol
- client and server
- default port 80 and can change any other port depending on the server configuration

# URL

```
			user					   port 			query string
	   --------------                   --				 ----------
http://admin:password@inlanefreight.com:80/dashboard.php?login=true#status
----				  -----------------    -------------            ------
scheme						host				path				fragment
```

# HTTP Flow

![HTTP flow](images/HTTP_Flow.png)

# HTTPS

- hypertext transfer protocol secure
- in HTTP, all data is transferred in clear-text and can perform a Man-in-the-middle (MiTM) attack to view the transferred data
- in HTTPS, all communications are transferred in an encrypted format

- HTTP in wireshark

![HTTP](images/https_clear.png)

- HTTPS in wireshark

![HTTPS](images/https_google_enc.png)

<pre style="color: red">
<strong>NOTE</strong>
Although the data, transferred through the HTTPS protocol may be encrypted, the request may still reveal the visited URL if it contacted a clear-text DNS server.
It is recommended to utilize encrypted DNS servers (eg- 8.8.8.8 or 1.2.3.4) or utilize a VPN service to ensure all traffic is properly encrypted
</pre>

# HTTPS Flow

![HTTPS Flow](images/HTTPS_Flow.png)

<pre style="color: red">
<strong>NOTE</strong>
Depending on circumstances, an attacker may be able to perform an HTTP downgrade attack, which downgrades HTTPS to HTTP, making the data transferred in clear-text.
This is done by setting up a Man-In-The-Middle proxy to transfer all traffic through the attacker's host without the user's knowledge.
</pre>

# HTTP Requests and Responses

## Requests

![raw request](images/raw_request.png)

- HTTP version 1.X sends requests as clear-text, and uses a new-line character to separate different fields and different requests
- HTTP version 2.X, sends requests as binary data in a dictionary form

## Responses

![raw response](images/raw_response.png)

- response body which is separated by a new line after the headers, and usually defined as **HTML** code
- sometimes, JSON, website resources such as images, style sheets, or scripts, or a document

# HTTP Headers

1. General Headers
2. Entity Headers
3. Request Headers
4. Response Headers
5. Security Headers

## 1. General Headers

- used in both requests and responses
- used to describe the message rather than contents

| Header     | Example                              | Description                                                                                                                                                                                                                                                                                                                     |
| ---------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Date       | Date: Wed, 16, Feb 2022 10:33:34 GMT | Holds the date and time at which the message originated; preferred to convert the time to the standard UTC time zone                                                                                                                                                                                                            |
| Connection | Connection: close                    | Dictates if the current network connection should stay alive after the request finishes; **close**, and **keep-alive**; **close** value from either the client or server means that they would like to terminate the connection, **keep-alive** indicates that the connection should remain open to receive more data and input |

## 2. Entity Headers

- common to both the request and response
- usually found in responses and POST or PUT requests
- used to describe the content (entity) transferred by a message

| Header           | Example                            | Description                                                                                                                                                                                                                                    |
| ---------------- | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Content-Type     | Content-Type: text/html            | <ul><li>used to describe the type of resource being transfrred </li><li>automatically added by the browsers on the client-side and returned in the server response</li><li>charset field denotes the encoding standard such as UTF-8</li></ul> |
| Media-Type       | Media-Type: application/pdf        | <ul><li>similar to Content-Type</li><li>describes the data being transferred</li><li>play a crucial role in making the server interpret the input</li><li>charset field may also be used with this header</li></ul>                            |
| Boundary         | boundary="boundary="b4e4fbd93540"" | <ul><li>acts as a marker to separate content when there is more than one in the same message</li><li>eg: within a form data, this boundary gets used as <strong>--b4e4fbd93540</strong> to separate different parts of the form</li></ul>      |
| Content-Length   | Content-Length: 385                | <ul><li>Holds the size of the entity being passed</li><li>necessary as the server uses it to read data from the message body</li><li>automatically generated by the browser or tools like cURL</li></ul>                                       |
| Content-Encoding | Content-Encoding: gzip             | <ul><li>data can undergo multiple transformations before being passed</li><li>eg: large amounts of data can be compressed to reduce the message size</li></ul>                                                                                 |

## 3. Request Headers

- client sends request headers in an HTTP transaction
- used in an HTTP request and do not relate to the content of the message

| Header        | Example                                | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Host          | Host: www.inlanefreight.com            | <ul><li>used to specify the host being queried for the resource</li><li>can be a domain name or IP</li><li>HTTP servers can be configured to host different websites based on the hostname</li></ul>                                                                                                                                                                                                          |
| User-Agent    | User-Agent: curl/7.77.0                | <ul><li>used to describe the client requesting resources</li><li>reveal about the client such as browser, version and OS</li></ul>                                                                                                                                                                                                                                                                            |
| Referer       | Referer: http://www.inlanefreight.com/ | <ul><li>denote where the current request is coming from</li></ul>                                                                                                                                                                                                                                                                                                                                             |
| Accept        | Accept: \*/\*                          | <ul><li>describes which media types the client can understand</li><li>can contain multiple media types separated by commas</li><li>\*/\* value signifies that all media types are accepted</li></ul>                                                                                                                                                                                                          |
| Cookie        | Cookie: PHPSESSID=b4e4fb93540          | <ul><li>cookie-value pairs in **name=value** format</li><li>cookie - piece of data stored on the client-side and on the server which acts as an identifier</li><li>passed to the server per request, and maintaining the client's access</li><li>can serve other purposes such as saving user preferences or session tracking</li><li>multiple cookies in a single header separated by a semi-colon</li></ul> |
| Authorization | Authorization: BASIC cGFzc3dvcmQK      | <ul><li>to identify clients</li><li>after successful authentication, the server returns a token unique to the client</li><li>unlike cookies, tokens are stored only on the client-size and retrieved by the server per request</li></ul>                                                                                                                                                                      |

- [request headers RFC 7231](https://www.rfc-editor.org/rfc/rfc7231#section-5)

## 4. Response Headers

- used in an HTTP response and do not relate to the content
- **Age, Location, Server** - used to provide more context about the response

| Header           | Example                                   | Description                                                                                                                                                                                                |
| ---------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Server           | Server: Apache/2.2.14 (Win32)             | <ul><li>contains information about the HTTP server, which processed the request</li><li>used to gain information about the server such as version</li></ul>                                                |
| Set-Cookie       | Set-Cookie: PHPSESSID=b4e3fbd93540        | <ul><li>contains the cookies needed for client identification</li><li>browsers parse the cookies and store them for future requests</li><li>follows the same format as the Cookie request header</li></ul> |
| WWW-Authenticate | WWW-Authenticate: BASIC realm="localhost" | <li>notifies the client about the type of authenticaiton required to access the requested resources</li>                                                                                                   |

## 5. Security Headers

- class of response headers used to specify certain rules and policies to be followed by the browser while accessing the website

| Header                    | Example                                    | Description                                                                                                                                                                                                                                                                                                     |
| ------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Content-Security-Policy   | Content-Security-Policy: script-src 'self' | <ul><li>dictates the website's policy towards externally injected resources</li><li>JS code as well as script resources</li><li>insturcts the browser to accept resources only from certain trusted domains to prevent attacks such as XSS</li></ul>                                                            |
| Script-Transport-Security | Script-Transport-Security: max-age=3156000 | <ul><li>prevents the browser from accessing the website over the plaintext HTTP protocol and forces all communication to be carried over the secure HTTPS protocol</li><li>prevents attackers from sniffing web traffic and accessing protected information such as passwords or other sensitive data</li></ul> |
| Referrer-Policy           | Referrer-Policy: origin                    | <ul><li>dictates whether the browser should include the value specified via the Referer header or not</li><li>help in avoiding disclosing sensitive URLs and information while browsing the website</li></ul>                                                                                                   |

- [Mozilla HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

# HTTP Methods and Codes

## HTTP Methods

| Method  | Description                                                                                                                                                                                                                      |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET     | <ul><li>requests a specific resource</li><li>additional data can be passed to the server via query strings in the URL</li></ul>                                                                                                  |
| POST    | <ul><li>sends data to the server</li><li>handle multiple types of input such as text, documents, other forms of binary data</li><li>commonly used to send information (forms/login etc) or uploading data to a website</li></ul> |
| HEAD    | <ul><li>requests the headers that would be returned if a GET request was made to the server</li><li>doesn't return the request body</li><li>is made to check the response length before downloading resources</li></ul>          |
| PUT     | <ul><li>creates new resources on the server</li><li>allowing without proper controls can lead to upload vulnerabilities</li></ul>                                                                                                |
| DELETE  | <ul><li>delete an existing resource on the server</li><li>if not properly secured, can lead to DoS by deleting critical files on the server</li></ul>                                                                            |
| OPTIONS | <ul><li>returns information about the server, such as the methods accepted by it </li></ul>                                                                                                                                      |
| PATCH   | <ul><li>applies partial modifications to the resource at the specified location </li></ul>                                                                                                                                       |

- Most web applications mainly rely on GET and POST methods
- in REST APIs also rely on PUT and DELETE method

## Response Codes

| Type | Description                                                            |
| ---- | ---------------------------------------------------------------------- |
| 1xx  | Provides information and does not affect the processing of the request |
| 2xx  | returned when a request succeeds                                       |
| 3xx  | returned when the server redirects the client                          |
| 4xx  | signifies improper requests from the client                            |
| 5xx  | returned when there is some problem with the HTTP server itself        |

| Code                      | Description                                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 200 OK                    | returned on a successful request, and response body usually contains the requested resource                                                      |
| 302 Found                 | redirects the client to another URL                                                                                                              |
| 400 Bad Request           | returned on encountering malformed requests such as requests with missing line terminators                                                       |
| 403 Forbidden             | signifies that the client doens't have appropriate access to the resource; can be returned when the server detects malicious input from the user |
| 404 Not Found             | returned when the client requests a resource that doesn't exist on the server                                                                    |
| 500 Internal Server Error | returned when the server cannot process the request                                                                                              |

- various servers and providers implement their own codes
- [Amazon](https://docs.aws.amazon.com/AmazonSimpleDB/latest/DeveloperGuide/APIError.html)
- [Cloudflare](https://support.cloudflare.com/hc/en-us/articles/115003014432-HTTP-Status-Codes#h_rx7Qh33zM85NHkEeGBPXj)

# GET

## HTTP Basic Auth

![HTTP auth login](images/http_auth_login.jpg)

- unlike the usual login forms which utilize HTTP parameters to validate the user credentials (eg - POST request), this type of authentication utilizes a basic HTTP authentication which handled directly by the webserver to protect a specific page/directory, without directly interacting with the web application

- once we enter the credentials, we can get access to the page

![HTTP auth in](images/http_auth_index.jpg)

- with cURL

```
thnwht@htb[/htb]$ curl -i http://<SERVER_IP>:<PORT>/
HTTP/1.1 401 Authorization Required
Date: Mon, 21 Feb 2022 13:11:46 GMT
Server: Apache/2.4.41 (Ubuntu)
Cache-Control: no-cache, must-revalidate, max-age=0
WWW-Authenticate: Basic realm="Access denied"
Content-Length: 13
Content-Type: text/html; charset=UTF-8

Access denied
```

```
thnwht@htb[/htb]$ curl -u admin:admin http://<SERVER_IP>:<PORT>/

<!DOCTYPE html>
<html lang="en">

<head>
...SNIP...
```

OR

```
thnwht@htb[/htb]$ curl -v http://admin:admin@<SERVER_IP>:<PORT>/

<!DOCTYPE html>
<html lang="en">

<head>
...SNIP...
```

OR

- encode the `admin:admin` will result `YWRtaW46YWRtaW4=`

```
thnwht@htb[/htb]$ curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/

<!DOCTYPE html
<html lang="en">

<head>
...SNIP...
```

# POST

- unlike HTTP GET, HTTP POST places user parameters within the HTTP Request body and benefits are

1. Lack of logging - as POST requests may transfer large files (eg - file upload) and there is no server log
2. Less Encoding Requirements - POST request places data in the body which can accept binary data; only characters that need to be encoded are those that are used to separate parameters
3. More data can be sent - a URL's lengths should be kept to below 2000 characters and so they cannot handle a lot of data

```
thnwht@htb[/htb]$ curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/

...SNIP...
        <em>Type a city name and hit <strong>Enter</strong></em>
...SNIP...
```

- we can use '-L' flag to follow redirection

```
thnwht@htb[/htb]$ curl -X POST -d '{"search":"london"}' -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php


["London (UK)"]
```

# CURD APIs

- suppose `api.php` endpoint and want to update the city table with city name london

```
curl -X PUT http://<server-ip>:<port>/api.php/city/london
```

| Operation | HTTP Method | Description                                        |
| --------- | ----------- | -------------------------------------------------- |
| Create    | POST        | Adds the specified data to the database table      |
| Read      | GET         | Reads the specified entity from the database table |
| Updated   | PUT         | Updates the data of the specified database table   |
| Delete    | DELETE      | Removes the specified row from the database table  |

## Read

```
thnwht@htb[/htb]$ curl http://<SERVER_IP>:<PORT>/api.php/city/london

[{"city_name":"London","country_name":"(UK)"}]
```

```
thnwht@htb[/htb]$ curl -s http://<SERVER_IP>:<PORT>/api.php/city/london | jq

[
  {
    "city_name": "London",
    "country_name": "(UK)"
  }
]
```

- can provide a search term and get all matching results

```
thnwht@htb[/htb]$ curl -s http://<SERVER_IP>:<PORT>/api.php/city/le | jq

[
  {
    "city_name": "Leeds",
    "country_name": "(UK)"
  },
  {
    "city_name": "Dudley",
    "country_name": "(UK)"
  },
  {
    "city_name": "Leicester",
    "country_name": "(UK)"
  },
  ...SNIP...
]
```

- can pass an empty string to retrieve all entries in the table

```
thnwht@htb[/htb]$ curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq

[
  {
    "city_name": "London",
    "country_name": "(UK)"
  },
  {
    "city_name": "Birmingham",
    "country_name": "(UK)"
  },
  {
    "city_name": "Leeds",
    "country_name": "(UK)"
  },
  ...SNIP...
]
```

## Create

```
thnwht@htb[/htb]$ curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```

## Update

- PATCH - used to update API entries instead of PUT, partially update an entry
- PUT - used to update the entire entry
- use HTTP OPTIONS method to see which of the two is accepted by the server

```
thnwht@htb[/htb]$ curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```

## Delete

```
thnwht@htb[/htb]$ curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City
```
