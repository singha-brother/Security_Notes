## What are JWTs?

- JSON web tokens (JWTs) - standarized format for sending cryptographically signed JSON data between systems
- contain any kind of data but are most commonly used to send information ("claims") about users as part of authentication, session handling and access control mechanisms

### JWT format

- 3 parts: `header`, `payload` and `signature` separated by dot
- header and payload parts of a JWT are just base64url-encoded JSON objects
- header contains metadata about the token itself, while the payload contains actual claims about the user

  eg -

```
eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5HkT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA
```

- header part is decoded as follow

```json
{ "kid": "9136ddb3-cb0a-4a19-a07e-eadf5a44c8b5", "alg": "RS256" }
```

- payload part

```json
{
  "iss": "portswigger",
  "exp": 1648037164,
  "name": "Carlos Montoya",
  "sub": "carlos",
  "role": "blog_author",
  "email": "carlos@carlos-montoya.net",
  "iat": 1516239022
}
```

- security of any JWT-based mechanism is heavily reliant on the cryptographic signature

## JWT attacks

- user sending modified JWTs to the server in order to achieve a malicious goal
- goal is to bypass authentication and access controls by impersonating another user who has been authenticated
- impact - severe

### Exploiting flawed JWT signature verification

- by design, servers don't store any information about the JWTs that they issue and instead each token is an entirely self-contained entity
- one problem is that server doesn't know anything about the original contents of the token or even what the original signature was
- if the server doesn't verify the signature properly, the attacker can chage the rest of the token

1. Accepting arbitary signatures

- the application doesn't verify the signature part at all
- just change the payload parameters and it works

2. Accepting tokens with no signature

- in header part, it looks like :

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

- "alg" parameter is set to `none` -> `unsecured JWT`
- servers usually reject tokens with no signature
- but this kind of filtering relies on string parsing, and can bypass by using classic obfuscation techniques such as mixed capitalization and unexpected encodings

3. Brute-forcing secret keys

- some signing algorithms such as HS256 (HMAC + SHA-256) use an arbitary standalone string as the secret key like password and this secret can't be easily guessed or brute-forced by an attacker
- otherwise, they may be able to create JWTs with any header and payload values and use that key to resign the token with a valid signature
- sometimes, develpers make mistakes like forgetting to change default or placeholder secrets, or copy and paste code snippets they find online
- an attacker can brute-force a server's secret using [wordlist of well-known secrets](https://github.com/wallarm/jwt-secrets)
- use `hashcat` to burte-force

```sh
hashcat -a 0 -m 16500 <jwt> <wordlist>
```

### JWT header parameter injections

- only `alg` header is mandatory
- but JWT header (JOSE header) often contain several other parameters
- eg - `jwk` (JSON Web Key) - provides an embedded JSON object representing the key
  - `jku` (JSON Web Key Set URL) - provides URL from which servers can fetch a set of keys containing the correct key
  - `kid` (Key ID) - provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from

#### Injecting self-signed JWTs via jwk

- JWK - standarized format for representing keys as a JSON object
  eg -

```json
{
  "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
  "typ": "JWT",
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
  }
}
```

- ideally, servers should only use a limited whitelist of public keys to verify JWT signature
- but, misconfigured servers sometimes use any key that's embedded in the `jwk` parameter
- exploit by signing a modified JWT using your own RSA pirvate key, then embedding the matching public key in the jwk header

#### Injecting self-signed JWTs via jku parameter

- instead of using the jwk header parameter, some servers let you use the jku (JWK Set URL) header parameter to reference a JWK Set containing the key
- JWK Set - JSON object containing an array of JWKs representing different keys

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
      "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
    },
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
      "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
    }
  ]
}
```

- JWK Sets are sometimes exposed publicly via a standard endpoint `/.well-known/jwks.json`
- more secure websites will only fetch keys from trusted domains, and can bypass like SSRF bypass

#### Injecting self-signed JWTs via the kid parameter

- header of JWT may contain a `kid` (Key ID) parameter, which helps the server to identify which key to use when verifying the signature
- Verification keys are often stored as a JWK Set
- the server may simply look for the JWK with the same `kid` as the token
- `kid` was not defined a concrete structure
- developers might use the `kid` parameter to point to a particular entry in a database, or even the name of a file
- if this parameter is also vulnerable to directory traversal, an attacker can potentially force the server to use an arbitary file from its filesystem

```json
{
  "kid": "../../path/to/file",
  "typ": "JWT",
  "alg": "HS256",
  "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```

- if the server supports JWTs signed using symmetric algorithm, it is dangerous
- one simplest methods is in Linux server use `/dev/null` path, which is an empty file and fetching it return null and signing the token with a Base64-encoded null byte will result a valid signature

### Other JWT header parameters

- `cty` (Content Type) - to declare a media type for the content in the JWT payload; if you found a way to bypass signature verification, you can try injecting a `cty` header to change the content type to `text/xml` or `application/x-java-serialized-object` which can enable new vectors for XXE and deserialization attacks

- `x5c` (X.509 Certificate Chain) - can be used to inject self-signed certificates similar to the jwk header injection (CVE-2017-2800, CVE-2018-2633)

## JWT algorithm confusion

- known as key confusion attacks 
- occur when an attacker is able to force the server to verify the signature of a JSON web token using a different algorithm than is intended by the developers

### Symmetric Vs Asymmetric

- JWT can be signed using different algorithms
- eg - HS256 (HMAC + SHA256) use a symmetric key means the server uses a single key to both sign and verify the token 

![[Pasted image 20221101205841.jpg]]

- other algorithms such as RS256 (RSA + SHA256) uses asymmetric key pairs which contains a private key which the server uses to sign the token and a mathematically related public key that can be used to verify the signature

![[Pasted image 20221101210036.jpg]]

### Performing algorithm confusion attack

1. Obtain the server's public key
2. Convert the public key to a suitable format
3. Create a malicious JWT with a modified payload and the alg header set to `HS256`
4. Sign the token with HS256, using the public key as the secret

Step 1. Obtain the server's public key
- servers sometimes expose their public keys as JSON Web Key (JWK) objects via endpoint such as `/jwks.json` or `/.well-known/jwks.json` and they may be stored in an array of JWKs called `keys` and known as `JWK Set`
```json
{
	"keys": [
		{
			"kty": "RSA",
			"e": "AQAB",
			"kid": "...",
			"n": "..."
		},
		{
			"kty": "RSA",
			"e": "AQAB",
			"kid": "...",
			"n": "..."
		}
	]
}
```

Step 2 - Convert the public key to a suitable format
- version of the key that you use to sign the JWT must be identical to the server's local copy and every signle byte must match including any non-printing characters
- In Burp
	1. In JWT Editor Keys tab, `New RSA` > paste the JWK that was obtained earlier
	2. Select the `PEM` radio button and copy the resulting PEM key
	3. in Decoder Tab, `Base64-encode` the PEM
	4. in JWT Editor Keys, `New Symmetric Key` > `Generate`
	5. replace the generated value for the `k` parameter with a Base64-encoded PEM key that was copied and save the key

Step 3 - Modify your JWT
- modify the JWT as you like and make sure the `alg` header to `HS256`

Step 4 - Sign the JWT using the public key
- Sign the token using the HS256 algorithm with the RSA public key as secret