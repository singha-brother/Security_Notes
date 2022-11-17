# Introduction to Server-Side Attacks

- target the actual application
- objective - leak sensitive data or inject unwarranted input into the application and achieve RCE

## Types of Server-Side Attacks

1. Abusing Intermediary Application 
	- accessing internal applications not accessible from our network by leveraging specific exposed binary protocols

2. Server-Side Request Forgery (SSRF) 
	- making the host application server issue requests to arbitary external domains or internal resources in an attempt to identify sensitive data

3. Server-Side Includes Injection (SSI) 
	- injecting a payload so that ill-intended Server-Side Include directives are parsed to achieve RCE or leak sensitive data. 
	- occurs when poorly validated user input manages to become part of a response that is parsed for Server-Side Include directives

4. Edige-Side Includes Injection (ESI)
	- XML-based markup language used to tackle performance issues by termporarily storing dynamic web content that the regular web caching protocols do not save
	- occurs when an attacker manages to reflect ill-intended ESI tags in the HTTP response
	- root cause - HTTP surrogates cannot validate the ESI tag origin
	- parse and evaluate legitimate ESI tags by the upstream server and malicious ESI tags supplied by an attacker

5. Server-Side Template Injection (SSTI)
	- template engines facilitate dynamic data presentation through web pages or emails
	- injecting ill-intended template directives (payload) inside a template, leveraging Template Engines that insecurely mix user input with a given template

6. Extensible Stylesheet Language Transformations Server-Side Injection (XSLT)
	- an XML-based language usually used when transforming XML documents into XML, another XML document or PDF
	- occur when arbitary XSLT file upload is possible or when an application generates the XSL Transformation's XML document dynamically using unvalidated input from the user

	