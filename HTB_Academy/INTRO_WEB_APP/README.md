# Web application layout

## Web application infrastructure

- client-server
- one server
- many servers - one database
- many servers - many databases

### Client-Server

![Client-server](images/client-server-model.jpg)

- in this model, web apps have two types of components,
  - those in the front end which are usually interpreted and executed on the client-side(browser)
  - components in the back end, usually compiled, interpreted and executed by the hosting server

### One server

![One-server](images/one-server-arch.jpg)

- the entire web app or even several web apps and their components, including the database are hosted on a single server
- easy to implement but the riskiest design
- **all eggs in one basket**

### Many servers - one database

![many server one db](images/many-server-one-db-arch.jpg)

- separates the database onto its own database server and allows the web app's hosting server to access the database server to store and retrieve data
- allow several web app to access a single database to have access to the same data without syncing the data between them
- main advantage - **segmentation** where each of the main components of a web app is located and hosted separately

### Many servers - many databases

![many servers many dbs](images/many-server-many-db-arch.jpg)

- used for redundancy purpose to reduce downtime
- difficult to implement and may require load balancers

## Web application components

1. Client
2. Server
   - webserver
   - web application logic
   - database
3. Services (Microservice)
   - 3rd party integrations
   - web application integrations
4. Functions (Serverless)

## Web application architecture

1. Presentation layer

- consists of UI process components that enable communication with the application and the system
- accessed by the client via the web browser and are returned in the form of HTML, JS, CSS

2. Application layer

- all client requests (web requests) are correctly processed
- various criteria are checked such as authorization, priveileges, data passed on to the client

3. Data layer

- worked closely with the application layer to determine exactly where the required data is stored and can be accessed

- eg - ASP.NET core web app architecture

![aspnet core arch](images/image5-12.png)

## Microservices

- independent components of the web application
- eg - for an online store, we can decompose core tasks into
  - registration
  - search
  - payments
  - ratings
  - reviews
- these components communicate with the client and with each other
- communication between these microservices is stateless, request and response are independent because the stored data is stored separately from the respective microservice
- **Service-orignted architecture (SOA)** - built as a collection of different automated functions focused on a single business goal
- can use different programming languages and still interact

## Serverless

- cloud providers such as AWS, GCP, Azure, and others offer serverless architectures
- provide application frameworks to build web apps without having to worry about the servers themselves
- run in stateless computing containers (eg - Docker)
- all server management is done by the cloud provider

## Back End

- Back end servers
  - hardware and OS that hosts all other components
  - run on OS like Linux, Windows, or Containers
- Web Servers
  - handle HTTP requests and connections
  - eg - Apache, NGINX, IIS
- Databases
  - store and retrieve the web application data
  - eg - MySQL, MSSQL, Oracle, PostgreSQL, MongoDB
- Development Frameworks
  - used to develop the core Web application
  - eg - PHP, C#, Java, Python, NodeJS

![back end](images/backend-server.jpg)

- possible to host each component of the back end on its own isolated server or in isolated containers by utilizing services such as Docker
- components can be installed in separate containers

## URL Encoding

- percent-encoding
- in URLs , browsers can only use ASCII encoding which allows alphanumerical characters and certain special characters and other characters outside of the ASCII character-set have to be encoded within a URL

| Character | Encoding |
| --------- | -------- |
| Null      | %00      |
| LF        | %0a      |
| CR        | %0d      |
| space     | %20      |
| !         | %21      |
| "         | %22      |
| #         | %23      |
| $         | %24      |
| %         | %25      |
| &         | %26      |
| '         | %27      |
| (         | %28      |
| )         | %29      |

## Usages

- DOM - platform and language-neutral interface that allows programs and scripts to dynamically access and update the content, structure, and style of the components

1. Core DOM - standard model for all document types
2. XML DOM - standard model for XML documents
3. HTML DOM - standard model for HTML documents

# Some Front end vulnerabilities

## Sensitive data exposure

- availability of sensitive data in clear-text to the end-user
- usually found in the source code of the web page or page source on front end application
- sometimes we may find login credentials, hashes, or other sensitive data hidden in the comments of a web page's source code or within external JS code being imported

## HTML Injection

- occurs when unfiltered user input is displayed on the page
- through
  -retrieving previously submitted code like retrieving a user comment from the back end database or
  - directly displaying unfiltered user input through JS on the front end
- when a user has complete control of how their input will be displayed, they can submit HTML code, and the browser may display it as part of the page which may include a malicious HTML code, like an external login form to collect login credentials of others
- another example is **web page defacing**

  - injecting new HTML code to change the web page's appearence inserting malicious ads, or even completely changing the page

- injection example

```html
<style>
  body {
    background-image: url("https://academy.hackthebox.com/images/logo.svg");
  }
</style>
```

## XSS

1. Reflected XSS - occurs when user input is displayed on the page after processing
2. Stored XSS - occurs when user input is stored in the back end database and displayed upon retrieval
3. DOM XSS - occurs when user input is directly shouwn in the browser and is written to an HTML DOM object

## CSRF

- CSRF may utilize XSS vulns to perform certain queries and API calls on a web app that the victim is currently authenticated to

## Web servers

- application that runs on the back end server which handles all of the HTTP traffic from the client-side browser, routes it to the requested pages and finally responds to the client-side browser
- also accept various types of user input within HTTP requests including text, JSON, binary data
- once web server receives a web request, it is responsible for routing it to its destination and run any processes needed for that request and return response to the user on the client-side
- the pages and files that the webserver processes and routes traffic to are the web app core files
- can even develop our own basic web server using languages like Python, JS, PHP
- but for each language, there's a popular web app that is optimized for handling large amounts of web traffic which saves time in creating web server

- Apache

  - Apache or httpd
  - usually used with PHP
  - also supports .Net, Python, Perl or even Bash through CGI

- NGINX

- IIS (Internet Information Services)

## SOAP

- simple objects access - shares data through XML

```xml
<?xml version="1.0"?>

<soap:Envelope
xmlns:soap="http://www.example.com/soap/soap/"
soap:encodingStyle="http://www.w3.org/soap/soap-encoding">

<soap:Header>
</soap:Header>

<soap:Body>
  <soap:Fault>
  </soap:Fault>
</soap:Body>

</soap:Envelope>
```

## REST

- Representational State Transfer - shares data through the URL path and return JSON format

```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```
