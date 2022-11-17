# Intro to HTTP Verb Tampering

- depending on the web server configuration, web applications may be scripted to accept certain HTTP methods for their various functionalities and perform a particular action based on the type of the request
- suppose both the web application and back-end web server are configured only to accept GET and POST requests
	- sending a different request will cause a web server error page to be displayed
	- it is not a severe vulnerability in itself
	- providing a bad user experience and potentially leading to information disclosure
- on the other hand, if the web server configurations are not restricted to only accept the HTTP methods required by the web server and the web applicaiton is not developed to handle other types of HTTP requests (eg - HEAD, PUT)
	- we may be able to exploit this insecure configuration to gain access to functionalities we do not have access to or even bypass certain security controls

## HTTP Verb Tempering

| Verb    | Description |
| ------- | ----------- |
| HEAD    | identical to a GET request, but its response only contains the headers without the response body |
| PUT     | Writes the request payload to the specified location |
| DELETE  | Deletes the resource at the specified location |
| OPTIONS | Shows different options accepted by a web server, like accepted HTTP verbs |
| PATCH   | Apply partial modifications to the resource at the specified location |

- some of the above methods can perform very sensitive functionalities like writing (PUT) and deleting (DELETE) files to the web-root directory on the back-end server
- if a web server is not securely configured to manage these methods, we can use them to gain control over the back-end server
- what makes HTTP verb tampering attacks more common (more critical) is that they are caused by a misconfiguration in either the back-end web server or the web application, either of which can cause the vulnerability

## Insecure Configurations

- first type of the HTTP Verb Tampering vulns
- web server's authentication configuration may be limited to specific HTTP methods, which would leave some HTTP methods accessible without authentication 
- eg - a system admin may use the following configuration to require authentication on a particular web page

```xml
<Limit GET POST>
	Require valid-user
</Limit>
```

- though the configuration specifies both GET and POST requests for the authentication method, the attacker may still use a different HTTP method (like HEAD) to bypass this authentication mechanism altogether 
- this leads to authentication bypass

## Insecure Coding

- occurs when a web developer applies specific filters to mitigate particular vulnerabilities while not covering all HTTP methods with that filter
- eg - web page was found to be vulnerable to SQL injection and the developer mitigate the SQL injection vulns by the following input sanitization filters

```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```
- the filter is only being testing only on the `GET` parameter leading to an inconsistency in the use of HTTP verbs
- in this case, the attacker may use a `POST` request to perform SQL injection and may still vulnerable to SQL injection

---

# Bypassing Basic Authentication

- Exploiting HTTP Verb Tampering vuln - relatively straightforward process
- just to try alternative HTTP methods to see how they are handled by the web server and the web application
- many automated vulnerability scanners can identify vulns caused by `insecure server configurations`, they usually miss to identify those due to `insecure coding`

1. Identify

- first identify which pages (endpoints) are restristed for authenticated users only eg - admin pages
- will get 401 Unauthorized page

2. Exploit

- try with alternative method (**GET, POST**) 
- if not successful, **OPTIONS** request to see what HTTP methods are accepted

```sh
curl -i -X OPTIONS https://example.com
```

---

# Bypassing Security Filters

- caused by Insecure Coding errors made during the development of the web application, which lead to web application not covering all HTTP methods in certain functionalities
- found in security filters that detect malicious requests
- eg - if a security filter was being used to detect injection vulnerabilities and only checked for injections in POST -> test with GET

---

# Verb Tampering Prevention

- Insecure configurations and insecure coding are common reasons to cause that vulnerabilities

## Insecure Configurations

- can occur in most modern web servers, including Apache, Tomcat, ASP.NET 
- usually happens when we limit a page's authorization to a particular set of HTTP verbs/methods, which leaves the other remaining methods unprotected
- an example of a vulnerable configuration for an Apache web server which is located in the site configuration file (eg - `000-default.conf`) or in `.htaccess` web page configuration file

```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

- configuration setting for admin web directory
- but limit only for GET requests
- can accessible through the POST requests
- even if GET and POST are limited, HEAD and OPTIONS are remained accessible

- example of same vulnerability for a Tomcat server which can be found in `web.xml` file for Java web application

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

- for ASP.NET configuration found in the `web.config` file of a web application

```xml
<system.web>
	<authorization>
		<allow verbs="GET" roles="admin">
			<deny verbs="GET" users="*">
			</deny>
		</allow>
	</authorization>
</system.web>
```

## Insecure Coding

- consider the following PHP code 
```php
if (isset($_REQUEST['filename'])) {
	if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
		system("touch " . $_REQUEST['filename']);
	} else {
		echo "Malicious Request Denied!";
	}
}
```

- fatal error made in this case is not due to Command Injections but due to the inconsistent use of HTTP methods

- to avoid HTTP Verb Tampering vulnerabilities in the code, we must be consistent with our use of HTTP methods and ensure the same method is always used for any specific functionality across the web application

---