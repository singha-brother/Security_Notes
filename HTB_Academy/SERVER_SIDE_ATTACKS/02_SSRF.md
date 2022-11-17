# SSRF

- Server Side Request Forgery - abuse server functionality to perform internal or external resource requests on behalf of the server
- need to modify or supply URLs used by the target application to read or submit data
- exploiting SSRF can lead to 
	- Interacting with known internal systems
	- Discovering internal services via port scans
	- Disclosing local/sensitive data
	- Including files in the target application
	- Leaking NetNTLM hashes using UNC Paths (Windows)
	- Achieving RCE

- usually find SSRF vulns in applications that fetch remote resources
- when hunting for SSRF vulns, we should look for
	- **Parts of HTTP requests, including URLs**
	- **File imports such as HTML, PDFs, images, etc**
	- **Remote server connections to fetch data**
	- **API specification imports**
	- **Dashboards including ping and similar functionalities to check server statuses**

- web application fuzzing should be any part of any penetration testing or bug bounty hunting activity
- fuzzing should not be limited to user input fields only 
- extend fuzzing to parts of the HTTP request as well such as User-Agent

---

# SSRF Exploitation Example

- attack flow will be as follow
```

```	